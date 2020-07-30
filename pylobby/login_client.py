import logging
import re
import secrets
import socket
import string
import time
import traceback
from typing import Callable, Dict, Iterable, Optional, Union

from .gs import enc2 as gs_enc2
from .network import NetworkClient

logger = logging.getLogger(__name__)

_valid_nickname_regexp = re.compile(r"^[][\-`_^{|}A-Za-z][][\-`_^{|}A-Za-z0-9]{0,50}$")


def is_valid_nickname(uname: str) -> bool:
    # FIXME: Check if these restrictions are consistent with the already existing users
    if not (5 < len(uname) < 24):
        return False
    if not _valid_nickname_regexp.match(uname):
        return False
    return True


class LoginBaseClient(NetworkClient["LoginServer"]):
    handlers: Dict[str, Callable[..., None]]

    def __init__(self, server: "LoginServer", sock: socket.socket):
        super().__init__(server, sock)

    def _parse_read_buffer(self, read_buffer: bytes) -> bytes:
        # We assume all packets and with \final\ - but never have that inbetween
        packets = read_buffer.decode("windows-1253", "ignore").split("\\final\\")
        # Put last word (maybe empty) back into the readbuffer as we don't know if it is complete yet.
        remainder = packets[-1]
        packets = packets[:-1]
        # Now the packets array should contain complete packets and the readbuffer any remaining incomplete ones
        for packet in packets:
            self._parse_packet(packet)
        return bytes(remainder, "windows-1253", "ignore")

    def _parse_packet(self, packet: str) -> None:
        words = packet.split("\\")
        if len(words) < 3 or words[0] != "":
            logger.warning("Parsing strange packet: {}", packet)
        command = words[1]
        words = words[1:]
        cooked = [(words[i], words[i + 1]) for i in range(0, len(words) - 1, 2)]
        data: Dict[str, str] = dict(cooked)
        logger.debug("Receiving command %s, data: %s", command, data)
        data["command"] = command  # for debug purposes
        if command in self.handlers:
            try:
                self.handlers[command](data)
            except Exception as ex:
                logger.error(
                    "Error handling command: %s, data: %s, error: %s", command, data, ex
                )
                logger.error("%s", traceback.format_exc())
        else:
            logger.warning("No handler for command: %s", command)

    def respond(self, words: Iterable[Union[str, int]]) -> None:
        logger.debug("sending response: %s", words)
        msg = bytearray(b"\\")
        for word in words:
            msg += bytes(str(word), "windows-1253")
            msg += b"\\"
        msg += b"final\\"
        self.write(msg)


class LoginClient(LoginBaseClient):
    id: int = -1
    challenge: str

    def __init__(self, server: "LoginServer", sock: socket.socket):
        super().__init__(server, sock)
        self.handlers = {
            "login": self.handle_login,
            "logout": self.handle_logout,
            "newuser": self.handle_newuser,
            "getprofile": self.handle_getprofile,
            "status": self.handle_status,
            "addbuddy": self.handle_addbuddy,
            "bm": self.handle_buddymsg,
        }

        self.challenge = "".join(
            [secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8)]
        )

        # Initial greeting
        self.respond(["lc", 1, "challenge", self.challenge, "id", 1])

    # example login data:
    # \login\\challenge\4jv99yxEnyNWrq6EUiBmsbUfrkgmYF4f\uniquenick\EvilLurksInternet-tk\partnerid\0\response\45f06fe0f350ae4e3cc1af9ffe258c93\firewall\1\port\0\productid\11081\gamename\civ4bts\namespaceid\17\sdkrevision\3\id\1\final\
    def handle_login(
        self, uniquenick: str, challenge: str, response: str, **kwargs
    ) -> None:
        uname = uniquenick
        logger.info("Player %s attempting to login.", uname)

        if not is_valid_nickname(uname):
            self.error(260, "fatal", "Username invalid!")
            return

        try:
            user = self.server.user_db[uname]
        except KeyError:
            self.error(260, "fatal", "Username does not exist!")
            return

        if response != gs_enc2.pw_hash_to_response(
            user.password, uname, self.challenge, challenge
        ):
            self.error(260, "fatal", "Incorrect password!")
            return

        # Adding 30000 so that the value has 5+ digits. Thats untested, maybe it will work with 1+ digit okay
        self.id = 30000 + int(user.id)

        user.lastip = self.host
        user.lasttime = time.time()
        user.session += 1

        self.server.register_gpclient(self)

        self.respond(
            [
                "lc",
                2,
                "sesskey",
                self.id,
                "proof",
                gs_enc2.pw_hash_to_proof(
                    user.password, uname, self.challenge, challenge
                ),
                "userid",
                2000000 + int(user.id),
                "profileid",
                1000000 + int(user.id),
                "uniquenick",
                uname,
                "lt",
                "1112223334445556667778__",
                "id",
                1,
            ]
        )

    # example newuser data
    # \newuser\\email\qqq@qq\nick\borf-tk\passwordenc\J8DHxh7t\productid\11081\gamename\civ4bts\namespaceid\17\uniquenick\borf-tk\partnerid\0\id\1\final\
    def handle_newuser(
        self, nick: str, email: str, passwordenc: str, **kwargs: str
    ) -> None:
        if not (
            5 < len(nick) < 24 and 50 > len(email) > 2 and 24 > len(passwordenc) > 7
        ):
            self.error(0, "fatal", "Error creating account, check length!")
            return

        if not is_valid_nickname(nick):
            self.error(0, "fatal", "Error creating account, invalid name!")
            return

        if nick in self.server.user_db:
            self.error(516, "fatal", "Account name already in use!")
            return

        pwhash = gs_enc2.pw_decode_hash(passwordenc)
        user = self.server.user_db.create(nick, pwhash, email, "", self.host)
        self.respond(
            [
                "nur",
                "",
                "userid",
                2000000 + user.id,
                "profileid",
                1000000 + user.id,
                "id",
                1,
            ]
        )

    def handle_getprofile(self, profileid: str, id: str, **kwargs: str) -> None:
        # WARNING `id` shadowed
        pid = int(profileid)
        user = self.server.user_db[pid - 30000]
        self.respond(
            [
                "pi",
                "",
                "profileid",
                pid,
                "sig",
                "xxxxxx",
                "uniquenick",
                user.name,
                "id",
                id,
            ]
        )

    def handle_addbuddy(self, newprofileid: str, **kwargs: str) -> None:
        npid = int(newprofileid)
        if npid == self.id:
            # doesn't let you adding yourself
            self.error(0, "warning", "Refusing to add yourself as buddy")
            return
        self.respond(["bm", 100, "f", npid, "msg", "|s|1|ss|chilling"])

    def handle_buddymsg(self, bm: str, msg: str, t: str, **kwargs: str) -> None:
        if bm != "1":
            logger.debug("Ignoring unknown bm %s", bm)
            return
        if not (256 >= len(msg) > 0):
            self.error(
                0,
                "warning",
                "Invalid buddy message size {}. Needs to be >0, <= 256.".format(
                    len(msg)
                ),
            )
            # possibly more type checks needed
        msg.replace("\\", "?")
        buddy_id = int(t)
        try:
            self.server.gpclient_by_id(buddy_id).respond(
                ["bm", 1, "f", self.id, "msg", msg]
            )
        except KeyError:
            self.error(0, "warning", "Buddy is not online.")

    def handle_status(self, logout: Optional[str] = None, **kwargs: str) -> None:
        if logout is not None:
            self.disconnect("status logout")

    def handle_logout(self, **kwargs: str) -> None:
        self.disconnect("logout")

    def error(self, err: int, severity: str, errmsg: str) -> None:
        logger.info("Client {} #{}: '{}'".format(severity, err, errmsg))
        self.respond(["error", "", "err", err, severity, "errmsg", errmsg, "id", 1])


class SearchClient(LoginBaseClient):
    def __init__(self, server: "LoginServer", sock: socket.socket):
        super().__init__(server, sock)
        self.handlers = {"search": self.handle_search, "logout": self.handle_logout}

    def handle_search(self, uniquenick: str, **kwargs: str) -> None:
        try:
            if not is_valid_nickname(uniquenick):
                raise KeyError()
            user = self.server.user_db[uniquenick]
            self.respond(
                ["bsr", 30000 + int(user.id), "uniquenick", uniquenick, "bsrdone", ""]
            )
        except:  # TODO which exception?
            # No user, roughly relevant answer to the client that seem to work
            self.respond(["bsr", "", "bsrdone", ""])

    def handle_logout(self, *kwargs: str) -> None:
        self.disconnect("logout")
