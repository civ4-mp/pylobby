import socket
import select
import logging
import errno
import traceback
import collections
import time


class NetworkClient(object):
    def __init__(self, server, sock):
        self.server = server
        self.socket = sock
        (self.host, self.port) = sock.getpeername()
        self._read_buffer = bytearray()
        self._write_buffer = bytearray()

    def __str__(self):
        return '{}@{}:{}'.format(self.__class__.__name__, self.host, self.port)

    def info(self, msg, *args, **kwargs):
        logging.info(str(self) + msg, *args, **kwargs)

    def write_queue_size(self):
        return len(self._write_buffer)

    def socket_readable_notification(self):
        try:
            data = self.socket.recv(2 ** 10)
            if not data:
                self.disconnect('EOT')
            self._read_buffer += data
            try:
                self._read_buffer = self._parse_read_buffer(self._read_buffer)
            except Exception as err:
                logging.error('[%s] Exception during parse_read_buffer: %s', self, err)
                logging.error('%s', traceback.format_exc())
                # Reset buffer to avoid another exception
                # Maybe we should disconnect here?
                self._read_buffer = bytearray()
        except socket.error as err:
            if err.args[0] == errno.EAGAIN or err.args[0] == errno.EWOULDBLOCK:
                logging.warning('[%s] Nonblocking read failed, will retry: %s', self, err)
            else:
                logging.warning('[%s] Nonblocking read failed hard, disconnect: %s', self, err)
                self.disconnect(err)

    def socket_writable_notification(self):
        logging.debug('flusing write buffer (%d bytes) of client %s', len(self._write_buffer), self)
        if not self._write_buffer:
            return
        try:
            sent = self.socket.send(self._write_buffer[:1024])
            self._write_buffer = self._write_buffer[sent:]
        except socket.error as err:
            if err.args[0] == errno.EAGAIN or err.args[0] == errno.EWOULDBLOCK:
                logging.warning('[%s] Nonblocking send failed, will retry: %s', self, err)
            else:
                logging.warning('[%s] Nonblocking send failed hard, disconnect: %s', self, err)
                self.disconnect(err)

    def disconnect(self, quitmsg):
        logging.info('[%s] client disconnected: %s', self, quitmsg)
        self.server.unregister_client(self.socket, self)
        self.socket.close()

    def write(self, msg):
        logging.debug('[%s] adding message with length %d to write buffer.', self, len(msg))
        self._write_buffer += msg


class NetworkServer(object):
    def __init__(self):
        self._clients_by_socket = {}
        self._server_socket_handlers = {}
        self._info_interval = 3 * 60

    def register_client(self, sock, client):
        self._clients_by_socket[sock] = client

    def unregister_client(self, sock, client):
        del self._clients_by_socket[sock]

    def register_server(self, server_socket, client_class):
        def handler():
            (client_sock, addr) = server_socket.accept()
            client_sock.setblocking(0)
            client = client_class(self, client_sock)
            self.register_client(client_sock, client)
            logging.info('Accepted connection from %s:%d, spawning new %s',
                         addr[0], addr[1], client_class.__name__)
        self._server_socket_handlers[server_socket] = handler

    def select(self, timeout=10):
        (rlst, wlst, xlst) = select.select(
            list(self._server_socket_handlers.keys()) + list(self._clients_by_socket.keys()),
            [sock for (sock, client) in self._clients_by_socket.items() if client.write_queue_size() > 0],
            [],
            timeout)
        for rsock in rlst:
            if rsock in self._clients_by_socket:
                self._clients_by_socket[rsock].socket_readable_notification()
            elif rsock in self._server_socket_handlers:
                try:
                    self._server_socket_handlers[rsock]()
                except Exception as err:
                    logging.error('Exception occured during client creation: %s', err)
            else:
                logging.error('Invalid rlist socket from select')

        for wsock in wlst:
            try:
                self._clients_by_socket[wsock].socket_writable_notification()
            except Exception as err:
                logging.error('Exception occured during writable_notification: %s', err)

    def run(self):
        logging.info('Server ready, waiting for connections')
        print('Server ready, waiting for connections.')
        last_info = time.time()
        while True:
            self.select()
            now = time.time()
            if now >= last_info + self._info_interval:
                self.info()
                last_info = now

    def info(self):
        logging.info('[%s] server alive with %d clients total:',
                     self.__class__.__name__, len(self._clients_by_socket))
        cs = collections.Counter([c.__class__.__name__ for c in self._clients_by_socket.values()])
        for classname, count in cs.items():
            logging.info('%s: %d', classname, count)
