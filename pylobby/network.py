import collections
import errno
import logging
import select
import socket
import time
import traceback
from abc import abstractmethod
from typing import Callable, Dict, Generic, Optional, Type, TypeVar

from prometheus_client import Counter, Gauge

logger = logging.getLogger(__name__)

ServerType = TypeVar("ServerType", bound="NetworkServer")


class NetworkClient(Generic[ServerType]):
    server: ServerType
    _socket: socket.socket
    _read_buffer: bytes
    _write_buffer: bytes

    def __init__(self, server: ServerType, sock: socket.socket):
        self.server = server
        self._socket = sock
        (self.host, self.port) = sock.getpeername()
        self._read_buffer = b""
        self._write_buffer = b""

    def __str__(self) -> str:
        return "{}@{}:{}".format(self.__class__.__name__, self.host, self.port)

    def write_queue_size(self) -> int:
        return len(self._write_buffer)

    @abstractmethod
    def _parse_read_buffer(self, buffer: bytes) -> bytes:
        pass

    def socket_readable_notification(self) -> None:
        try:
            data = self._socket.recv(2 ** 10)
            if not data:
                self.disconnect("EOT")
            self._read_buffer += data
            try:
                self._read_buffer = self._parse_read_buffer(self._read_buffer)
            except Exception as err:
                logger.error("[%s] Exception during parse_read_buffer: %s", self, err)
                logger.error("%s", traceback.format_exc())
                # Reset buffer to avoid another exception
                # Maybe we should disconnect here?
                self._read_buffer = b""
        except socket.error as err:
            if err.args[0] == errno.EAGAIN or err.args[0] == errno.EWOULDBLOCK:
                logger.warning(
                    "[%s] Nonblocking read failed, will retry: %s", self, err
                )
            else:
                logger.warning(
                    "[%s] Nonblocking read failed hard, disconnect: %s", self, err
                )
                self.disconnect(err)

    def socket_writable_notification(self) -> None:
        logger.debug(
            "flushing write buffer (%d bytes) of client %s",
            len(self._write_buffer),
            self,
        )
        if not self._write_buffer:
            return
        try:
            sent = self._socket.send(self._write_buffer[:1024])
            self._write_buffer = self._write_buffer[sent:]
        except socket.error as err:
            if err.args[0] == errno.EAGAIN or err.args[0] == errno.EWOULDBLOCK:
                logger.warning(
                    "[%s] Nonblocking send failed, will retry: %s", self, err
                )
            else:
                logger.warning(
                    "[%s] Nonblocking send failed hard, disconnect: %s", self, err
                )
                self.disconnect(err)

    def disconnect(self, quitmsg) -> None:
        logger.info("[%s] client disconnected: %s", self, quitmsg)
        self.server.unregister_client(self._socket, self)
        self._socket.close()

    def write(self, msg: bytes) -> None:
        logger.debug(
            "[%s] adding message with length %d to write buffer.", self, len(msg)
        )
        self._write_buffer += msg


Handler = Callable[[], None]
ClientType = TypeVar("ClientType", bound=NetworkClient)


class NetworkServer(Generic[ClientType]):
    _clients_by_socket: Dict[socket.socket, ClientType]
    _server_socket_handlers: Dict[socket.socket, Handler]
    _info_interval: int

    _metric_clients: Gauge
    _metric_clients_by_type: Dict[Type[ClientType], Gauge] = {}
    _metric_connections_total: Counter
    _metric_connections_total_by_type: Dict[Type[ClientType], Counter] = {}

    def __init__(self, prometheus_prefix: str, prometheus_description: str):
        self._clients_by_socket = {}
        self._server_socket_handlers = {}
        self._info_interval: int = 10 * 60

        self._metric_clients = Gauge(
            f"{prometheus_prefix}clients",
            f"Number of active clients of {prometheus_description}",
            labelnames=("client_type", "server_type"),
        )
        self._metric_connections_total = Counter(
            f"{prometheus_prefix}connections_total",
            f"Number of connections to {prometheus_description}",
            labelnames=("client_type", "server_type"),
        )

    def register_client(self, sock: socket.socket, client: ClientType) -> None:
        assert sock not in self._clients_by_socket
        self._clients_by_socket[sock] = client
        self._metric_connections_total_by_type[type(client)].inc()

    def unregister_client(self, sock: socket.socket, client: ClientType) -> None:
        assert sock in self._clients_by_socket
        del self._clients_by_socket[sock]

    def register_server(
        self, server_socket: socket.socket, client_class: Type[ClientType]
    ) -> None:
        def handler():
            (client_sock, addr) = server_socket.accept()
            client_sock.setblocking(0)
            client = client_class(self, client_sock)
            self.register_client(client_sock, client)
            logger.info(
                "Accepted connection from %s:%d, spawning new %s",
                addr[0],
                addr[1],
                client_class.__name__,
            )

        self._server_socket_handlers[server_socket] = handler

        assert client_class not in self._metric_clients_by_type
        assert client_class not in self._metric_connections_total_by_type
        self._metric_clients_by_type[client_class] = self._metric_clients.labels(
            client_type=client_class.__name__, server_type=type(self).__name__
        )

        # Capture trick...
        def c(cc: Optional[Type[ClientType]] = client_class):
            return sum(
                1 if cc == type(client) else 0
                for client in self._clients_by_socket.values()
            )

        self._metric_clients_by_type[client_class].set_function(c)
        self._metric_connections_total_by_type[
            client_class
        ] = self._metric_connections_total.labels(
            client_type=client_class.__name__, server_type=type(self).__name__
        )

    def select(self, timeout: int = 10) -> None:
        (rlst, wlst, xlst) = select.select(
            list(self._server_socket_handlers.keys())
            + list(self._clients_by_socket.keys()),
            [
                sock
                for (sock, client) in self._clients_by_socket.items()
                if client.write_queue_size() > 0
            ],
            [],
            timeout,
        )
        for rsock in rlst:
            if rsock in self._clients_by_socket:
                self._clients_by_socket[rsock].socket_readable_notification()
            elif rsock in self._server_socket_handlers:
                try:
                    self._server_socket_handlers[rsock]()
                except Exception as err:
                    logger.error("Exception occured during client creation: %s", err)
            else:
                logger.error("Invalid rlist socket from select")

        for wsock in wlst:
            try:
                self._clients_by_socket[wsock].socket_writable_notification()
            except Exception as err:
                logger.error("Exception occured during writable_notification: %s", err)

    def run(self) -> None:
        logger.info("Server ready, waiting for connections")
        last_info = time.time()
        while True:
            self.select()
            now = time.time()
            if now >= last_info + self._info_interval:
                self.info()
                last_info = now

    def info(self) -> None:
        logger.info(
            "[%s] server alive with %d clients total:",
            self.__class__.__name__,
            len(self._clients_by_socket),
        )
        cs = collections.Counter(
            [c.__class__.__name__ for c in self._clients_by_socket.values()]
        )
        for classname, count in cs.items():
            logger.info("%s: %d", classname, count)
