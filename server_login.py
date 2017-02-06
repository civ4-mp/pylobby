#!/usr/bin/env python3

#gs presence server (29900)
#based on works: prmasterserver, miniircd, gsopensdk, aluigi's works
#
#
#RECHECK input info for wrong characters and lengths    CHECK
#2 TCP SERVER SOCKETs                                   CHECK
#Session number bundled with socket instance            CHECK
#1 DATABASE FOR USER INFORMATION                        CHECK
#PASSWORD GSBASE64DEC, GSENC, MD5-HASHING PROCEDURES    CHECK
#PASSWORD LOGINCHECK_TRANSFORMATION                     CHECK
#PASSWORD -> PROOF TRANSFORMATION                       CHECK
##<|lc\1 <- (login or newuser)                          CHECK
##>|login -> lc\2                                       CHECK
##>|newuser -> nur                                      CHECK
##<|bdy,blk,bm                                          Not needed
##>|getprofile -> pi                                    Not needed
##>|status ->bdy,blk,bm                                 Not needed
##?|lt                                                  Not needed
##?|ka                                                  Not needed

import socket
import time
import re
import sqlite3
import logging
import traceback

import config_login
from gs_network import NetworkClient, NetworkServer
import gs_enc2


class GPBaseClient(NetworkClient):
    def __init__(self, server, sock):
        super().__init__(server, sock)

    def _parse_read_buffer(self, read_buffer):
        # We assume all packets and with \final\ - but never have that inbetween
        read_buffer = read_buffer.decode('windows-1253', 'ignore')
        packets = read_buffer.split('\\final\\')
        # Put last word (maybe empty) back into the readbuffer as we don't know if it is complete yet.
        remainder = packets[-1]
        packets = packets[:-1]
        # Now the packets array should contain complete packets and the readbuffer any remaining incomplete ones
        for packet in packets:
            self._parse_packet(packet)
        return bytearray(remainder, 'windows-1253', 'ignore')

    def _parse_packet(self, packet):
        words = packet.split('\\')
        if len(words) < 3 or words[0] != '':
            logging.warning('Parsing strange packet: {}', packet)
        command = words[1]
        words = words[1:]
        cooked = [(words[i], words[i + 1]) for i in range(0, len(words) - 1, 2)]
        data = dict(cooked)
        logging.debug('Receiving command %s, data: %s', command, data)
        data['command'] = command # for debug purposes
        if command in self.handlers:
            try:
                self.handlers[command](data)
            except Exception as ex:
                logging.error('Error handling command: %s, data: %s, error: %s', command, data, ex)
                logging.error('%s', traceback.format_exc())
        else:
            logging.warning('No handler for command: %s', command)

    def respond(self, words):
        logging.debug('sending response: %s', words)
        msg = bytearray(b'\\')
        for word in words:
            msg += bytes(str(word), 'windows-1253')
            msg += b'\\'
        msg += b'final\\'
        self.write(msg)


_valid_nickname_regexp = re.compile(r"^[][\-`_^{|}A-Za-z][][\-`_^{|}A-Za-z0-9]{0,50}$")


def is_valid_nickname(uname):
    # FIXME: Check if these restrictions are consistent with the already existing users
    if not (5 < len(uname) < 24):
        return False
    if not _valid_nickname_regexp.match(uname):
        return False
    return True


class GPSClient(GPBaseClient):
    def __init__(self, server, sock):
        super().__init__(server, sock)
        self.handlers = {'search': self.handle_search,
                         'logout': self.handle_logout}

    def handle_search(self, data):
        try:
            uname = data.get('uniquenick', '')
            if not is_valid_nickname(uname):
                raise KeyError()
            user = self.server.user_db[uname]
            self.respond(['bsr', 30000 + int(user.id), 'uniquenick', uname, 'bsrdone', ''])
        except:
            # No user, roughly relevant answer to the client that seem to work
            self.respond(['bsr', '', 'bsrdone', ''])

    def handle_logout(self, data):
        self.disconnect('logout')


class GPClient(GPBaseClient):
    def __init__(self, server, sock):
        super().__init__(server, sock)
        self.id = -1
        self.handlers = {'login': self.handle_login,
                         'logout': self.handle_logout,
                         'newuser': self.handle_newuser,
                         'getprofile': self.handle_getprofile,
                         'status': self.handle_status,
                         'addbuddy': self.handle_addbuddy,
                         'bm': self.handle_buddymsg}

        # Initial greeting
        self.respond(['lc', 1, 'challenge', config_login.challenge, 'id', 1])

    def handle_login(self, data):
        uname = data.get('uniquenick', '')
        logging.info("Player %s attempting to login.", uname)

        if not is_valid_nickname(uname):
            self.error(260, 'fatal', 'Username invalid!')
            return

        try:
            user = self.server.user_db[uname]
        except KeyError:
            self.error(260, 'fatal', 'Username does not exist!')
            return

        if data['response'] != gs_enc2.PW_Hash_to_Resp(user.password, uname, config_login.challenge, data['challenge']):
            self.error(260, 'fatal', 'Incorrect password!')
            return

        # Adding 30000 so that the value has 5+ digits. Thats untested, maybe it will work with 1+ digit okay
        self.id = 30000 + int(user.id)

        user.lastip   = self.host
        user.lasttime = time.time()
        user.session += 1

        self.server.register_gpclient(self)

        self.respond(['lc', 2,
                      'sesskey', self.id,
                      'proof', gs_enc2.PW_Hash_to_Proof(user.password, uname,
                                                        config_login.challenge, data['challenge']),
                      'userid', 2000000 + int(user.id),
                      'profileid', 1000000 + int(user.id),
                      'uniquenick', uname,
                      'lt', '1112223334445556667778__',
                      'id', 1])

        # example login data:
        # \login\\challenge\4jv99yxEnyNWrq6EUiBmsbUfrkgmYF4f\uniquenick\EvilLurksInternet-tk\partnerid\0\response\45f06fe0f350ae4e3cc1af9ffe258c93\firewall\1\port\0\productid\11081\gamename\civ4bts\namespaceid\17\sdkrevision\3\id\1\final\
        
    def handle_newuser(self, data):
        print("NEWUSER ", data)
        if not (5 < len(data.get('nick', '')) < 24 and
                50 > len(data.get('email', '')) > 2 and
                24 > len(data.get('passwordenc', '')) > 7):
            self.error(0, 'fatal', 'Error creating account, check length!')
            return

        if not is_valid_nickname(data['nick']):
            self.error(0, 'fatal', 'Error creating account, invalid name!')
            return

        if data['nick'] in self.server.user_db:
            self.error(516, 'fatal', 'Account name already in use!')
            return

        pwhash = gs_enc2.gsPWDecHash(data['passwordenc'])
        user = self.server.user_db.create(data['nick'], pwhash, data['email'], '', self.host)
        self.respond(['nur', '', 'userid', 2000000 + user.id, 'profileid', 1000000 + user.id, 'id', 1])

        # example newuser data
        # \newuser\\email\qqq@qq\nick\borf-tk\passwordenc\J8DHxh7t\productid\11081\gamename\civ4bts\namespaceid\17\uniquenick\borf-tk\partnerid\0\id\1\final\
        
    def handle_getprofile(self, data):
        profileid = int(data['profileid'])
        user = self.server.user_db[profileid  - 30000]
        self.respond(['pi', '', 'profileid', profileid, 'sig', 'xxxxxx', 'uniquenick', user.name, 'id', data['id']])

    def handle_addbuddy(self, data):
        newprofileid = int(data['newprofileid'])
        if newprofileid == self.id:
            # doesn't let you adding yourself
            self.error(0, 'warning', 'Refusing to add yourself as buddy')
            return
        self.respond(['bm', 100, 'f', newprofileid, 'msg', "|s|1|ss|chilling"])

    def handle_buddymsg(self, data):
        if data['bm'] != '1':
            self.debug('Ignoring unknown bm %s', data['bm'])
            return
        msg = data['msg']
        if not (256 >= len(msg) > 0):
            self.error(0, 'warning', 'Invalid buddy message size {}. Needs to be >0, <= 256.'.format(len(msg)))
            # possibly more type checks needed
        msg.replace('\\', '?')
        buddy_id = int(data['t'])
        try:
            self.server.gpclient_by_id(buddy_id).respond(['bm', 1, 'f', self.id, 'msg', msg])
        except KeyError:
            self.error(0, 'warning', 'Buddy is not online.')


    def handle_status(self, data):
        if 'logout' in data:
            self.disconnect('status logout')

    def handle_logout(self, data):
        self.disconnect('logout')

    def error(self, err, severity, errmsg):
        self.respond(['error', '', 'err', err, severity, 'errmsg', errmsg, 'id', 1])


# Yes this looks inefficient - but it's clever and never out of date.
# If the DB caching is too bad we can optimize later...
class UserObj:
    # Note: id not considered a field.
    fields = ['name', 'password', 'email', 'country', 'lastip', 'lasttime', 'session']

    def __init__(self, db, uid):
        self.__dict__['db'] = db
        self.__dict__['id'] = int(uid)

    def __getattr__(self, key):
        if key not in UserObj.fields:
            raise AttributeError()
        self.db.dbcur.execute('SELECT {} FROM users WHERE id = ?'.format(key), (self.id, ))
        return self.db.dbcur.fetchone()[0]

    def __setattr__(self, key, value):
        self.db.dbcur.execute('UPDATE users SET {} = ? WHERE id = ?'.format(key), (value, self.id))


class UserDB:
    def __init__(self, path):
        self.dbcon = sqlite3.connect(path, isolation_level=None)
        self.dbcur = self.dbcon.cursor()
        self.dbcur.execute("create table if not exists users ( id INTEGER PRIMARY KEY, name TEXT NOT NULL, "
                           "password TEXT NOT NULL, email TEXT NOT NULL, country TEXT NOT NULL, lastip TEXT NOT NULL, "
                           "lasttime INTEGER NULL DEFAULT '0', session INTEGER NULL DEFAULT '0' );")

    def __contains__(self, uname):
        self.dbcur.execute("SELECT EXISTS(SELECT name FROM users WHERE name=? LIMIT 1);", (uname, ))
        return self.dbcur.fetchone()[0]

    def __getitem__(self, id_or_name):
        if isinstance(id_or_name, int):
            return UserObj(self, id_or_name)
        try:
            self.dbcur.execute("SELECT id FROM users WHERE name=? LIMIT 1;", (id_or_name, ))
            uid = self.dbcur.fetchone()[0]
            return UserObj(self, uid)
        except:
            raise KeyError()

    def create(self, name, password, email, country, lastip):
        self.dbcur.execute("INSERT INTO users (name, password, email, country, lastip) VALUES (?, ?, ?, ?, ?);",
                           (name, password, email, country, lastip))
        return UserObj(self, self.dbcur.lastrowid)
    

class LoginServer(NetworkServer):
    def __init__(self):
        super().__init__()

        self.user_db = UserDB(config_login.dbpath)
        self._gpclients_by_id = {}

        gp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        gp_socket.setblocking(0)
        try:
            gp_socket.bind(("", 29900))
        except socket.error as err:
            print('Bind failed for gp (29900 TCP): {}'.format(err))
            raise err
        gp_socket.listen(5)
        gp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        gp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 120)
        gp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 60)
        gp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        self.register_server(gp_socket, GPClient)

        gps_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        gps_socket.setblocking(0)
        try:
            gps_socket.bind(("", 29901))
        except socket.error as err:
            print('Bind failed for gps (29901 TCP): {}'.format(err))
            raise err
        gps_socket.listen(5)
        gps_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        gps_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 120)
        gps_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 60)
        gps_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        self.register_server(gps_socket, GPSClient)

    # Called after login by the client iself
    def register_gpclient(self, client):
        self._gpclients_by_id[client.id] = client

    # Called by base class
    def unregister_client(self, sock, client):
        try:
            if isinstance(client, GPClient): 
                del self._gpclients_by_id[client.id]
        except KeyError:
            pass
        super().unregister_client(sock, client)

    def gpclient_by_id(self, id):
        return self._gpclients_by_id[id]



#logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.DEBUG)
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)
server = LoginServer()
try:
    server.run()
except KeyboardInterrupt:
    print("LoginServer interrupted.")
