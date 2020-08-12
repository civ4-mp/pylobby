#! /usr/bin/env python3
# Based on code copied or translated from works: miniircd,dwc_network_server_emulator, GsOpenSDK, ALuigi's projects, possibly other sources
#
import logging
import random
import socket
import sys
import time
from typing import Dict, List, Optional, Sequence, Tuple

import click
import pkg_resources

import click_log
from prometheus_client import Counter, Gauge, Info, start_http_server

from . import byteencode
from .gs import consts as gs_consts
from .gs import enc as gs_enc
from .network import NetworkClient, NetworkServer

# Use root logger here, so other loggers inherit the configuration
logger = logging.getLogger()
click_log.basic_config(logger)

info = Info("civgs_gamebrowser", "Civilization 4 lobby/gamebrowser version information")
info.info(
    {
        # https://stackoverflow.com/a/2073599/620382
        "version": pkg_resources.require("civ4-mp.pylobby")[0].version,
    }
)


def get_string(data: bytes, idx: int) -> bytes:
    data = data[idx:]
    end = data.index(b"\x00")
    return data[:end]


# for AF_INET hostname, port
Address = Tuple[str, int]


class GameHost:
    ip: str
    port: int
    sessionid: bytes
    lasthread: int
    # TODO is that right?
    data: Dict[str, str]

    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.sessionid = b"\x00\x00\x00\x00"
        self.last_activity = time.time()
        self.data = {}

    def refresh(self) -> None:
        self.last_activity = time.time()

    def __str__(self) -> str:
        return "{}:{}".format(self.ip, self.port)


class SBClient(NetworkClient["SBQRServer"]):
    out_crypt: Optional[gs_enc.GOACryptState]
    _timestamp: float
    _sent_ping: bool

    def __init__(self, server: "SBQRServer", sock: socket.socket):
        super().__init__(server, sock)
        self.out_crypt = None
        self._timestamp = time.time()
        self._sent_ping = False

    def sb_00respgen(self, fields: Sequence[bytes]) -> bytes:
        # keysheader
        r = bytearray()
        r += byteencode.ipaddr(self.host)
        r += byteencode.uint16(self.port)
        r += byteencode.uint8(len(fields))
        for field in fields:
            r += b"\x00" + field + b"\x00"
        r += b"\x00"
        # list of hosts
        for key, host in self.server.hosts.items():
            if (
                host.last_activity + 360 < time.time()
            ):  # deleting old servers here so we dont need a timer for that
                del self.server.hosts[key]
            else:
                flags = 0
                flags_buffer = b""
                # setting flags - this part has potential to be improved
                if len(host.data) != 0:
                    flags |= gs_consts.UNSOLICITED_UDP_FLAG
                    flags |= gs_consts.HAS_KEYS_FLAG
                    if "natneg" in host.data:
                        flags |= gs_consts.CONNECT_NEGOTIATE_FLAG
                    flags |= gs_consts.NONSTANDARD_PORT_FLAG
                    flags |= gs_consts.PRIVATE_IP_FLAG  # ?
                    flags |= gs_consts.NONSTANDARD_PRIVATE_PORT_FLAG  # ?
                flags_buffer += byteencode.ipaddr(host.ip)
                flags_buffer += byteencode.uint16(host.port)
                # adding 1 of local ip's :localport
                # for now server sends a random localip from all supplied
                lips = []
                for key1, value1 in host.data.items():
                    if key1.startswith("localip"):
                        lips.append(value1)
                if not lips:
                    lips.append("127.0.0.1")
                flags_buffer += byteencode.ipaddr(lips[random.randrange(0, len(lips))])
                flags_buffer += byteencode.uint16(int(host.data.get("localport", 6500)))
                r += byteencode.uint8(flags)
                r += flags_buffer
                # adding fields
                if len(host.data) != 0:
                    for field in fields:
                        r += (
                            b"\xff"
                            + host.data.get(field.decode(errors="ignore"), "0").encode()
                            + b"\x00"
                        )
        # ending symbols
        r += b"\x00"
        r += b"\xff" * 4
        return r

    def _parse_packet(self, packet: bytes) -> None:
        if packet[2] == 0x00:  # List request
            if len(packet) > 25:
                idx = 9
                query_game = get_string(packet, idx)
                idx += len(query_game) + 1
                game_name = get_string(packet, idx)
                idx += len(query_game) + 1
                cchallenge = packet[idx : idx + 8]
                idx += 8
                f = get_string(packet, idx)
                idx += len(f) + 1
                fields_str = get_string(packet, idx)
                fields = [x for x in fields_str.split(b"\\") if x and not x.isspace()]
                self.write(gs_enc.SBpreCryptHeader())
                self.out_crypt = gs_enc.GOACryptState()
                qfromkey = gs_consts.gngk.get(
                    query_game.decode(errors="ignore"), "Cs2iIq"
                ).encode()
                self.out_crypt.SBCryptStart(
                    bytes(qfromkey), cchallenge, gs_enc.SCHALLCONST,
                )
                self.write(self.sb_00respgen(fields))
        elif packet[2] == 0x02:  # forward req
            self.info("forward request")
            self.server.qr_forw_to(packet)
        elif packet[2] == 0x03:  # ping response
            self.info("ping ack")
        else:
            self.info("SB recieved unknown command: {}".format(packet[2]))

    def _parse_read_buffer(self, read_buffer: bytes) -> bytes:
        self._timestamp = time.time()
        self._sent_ping = False
        # We need at least two bytes to identify the packet length
        while len(read_buffer) >= 2:
            cplen = read_buffer[0] * 256 + read_buffer[1]
            if len(read_buffer) >= cplen:
                packet = read_buffer[:cplen]
                read_buffer = read_buffer[cplen:]
                self._parse_packet(packet)
            else:
                break  # not a full packet
        return read_buffer

    def check_aliveness(self) -> None:
        now = time.time()
        if self._timestamp + 180 < now:
            self.disconnect("ping timeout")
            return
        if not self._sent_ping and self._timestamp + 80 < now:
            pingstr = b"\x00\x07\x03\x77\x77\x77\x77"
            self.write(pingstr)
            self._sent_ping = True

    def write(self, msg: bytes):
        if self.out_crypt is not None:
            msg = self.out_crypt.GOAEncrypt(msg)
        super().write(msg)


class SBQRServer(NetworkServer[SBClient]):
    hosts: Dict[Address, GameHost]
    qr_socket: socket.socket
    sb_socket: socket.socket
    last_aliveness_check: float

    def __init__(self):
        super().__init__("civgs_", "Civilization 4 GameSpy Lobby server")
        self.hosts = {}  # key = ip:port; value = other stuff
        self.qr_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.qr_socket.bind(("", 27900))
        except socket.error as err:
            logging.error("Bind failed for qr socket (UDP 27900): %s", err)
        self.qr_socket.setblocking(0)
        # We dont use register_server here, this is a special UDP handler that doesn't accept / create clients etc.
        self._server_socket_handlers[self.qr_socket] = self.handle_qr

        self.sb_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sb_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sb_socket.bind(("", 28910))
            self.sb_socket.listen(5)
            self.sb_socket.setblocking(0)
        except socket.error as err:
            logging.error("Bind/listen failed for sb socket (TCP 28910): %s", err)
        self.register_server(self.sb_socket, SBClient)

        self.last_aliveness_check = time.time()

        self._metric_games_concurrent = Gauge(
            "civgs_games_concurrent", "Number of open games in the Civ4 gamebrowser"
        )
        self._metric_games_concurrent.set_function(lambda: len(self.hosts))
        self._metric_games_total = Counter(
            "civgs_games_total", "Number of games created in the Civ4 gamebrowser"
        )

    def log_hostlist(self) -> None:
        logging.debug("hostlist of server...")
        for index, (_, host) in enumerate(self.hosts.items()):
            logging.debug(
                "[{}] {}:{} ({!r}) {}".format(
                    index, host.ip, host.port, host.sessionid, host.last_activity
                )
            )
            logging.debug(host.data)
            logging.debug("... end of hostlist")

    def qr_forw_to(self, rawdata: bytes) -> None:
        if rawdata[9:15] == b"\xfd\xfc\x1e\x66\x6a\xb2":
            ip = (
                str(rawdata[3])
                + "."
                + str(rawdata[4])
                + "."
                + str(rawdata[5])
                + "."
                + str(rawdata[6])
            )
            port = rawdata[7] * 256 + rawdata[8]
            if (ip, port) in self.hosts:
                logging.info("forwarding to existing host")
            else:
                logging.info("forwarding to unknown address")
            resp = b"\xfe\xfd\x06"
            if (ip, port) in self.hosts:
                resp += self.hosts[(ip, port)].sessionid
            else:
                resp += b"\x00" * 4
            # random cookie here
            resp += bytes((random.randrange(0, 256)) for _ in range(4))
            resp += rawdata[9:]
            self.qr_send_to(resp, (ip, port), "qrforwto")
        else:
            logging.warning("wrong data to forward")

    @staticmethod
    def qr_parse03(raw: bytes) -> Dict[str, str]:
        prepared = raw[5:].split(b"\x00\x00\x00")[0].split(b"\x00")
        if len(prepared) % 2 == 1:
            logging.warning("Could not correctly parse03: %s", prepared)
        cooked = [
            (
                prepared[i].decode(errors="ignore"),
                prepared[i + 1].decode(errors="ignore"),
            )
            for i in range(0, len(prepared) - 1, 2)
        ]
        return dict(cooked)

    def qr_send_to(self, resp: bytes, address: Address, location: str) -> None:
        try:
            self.qr_socket.sendto(resp, address)
        except socket.error as err:
            logging.error("Socket error on location %s: %s", location, err)

    def handle_qr(self) -> None:
        recv_data, addr = self.qr_socket.recvfrom(1024)
        if len(recv_data) > 0:
            self.process_qr(recv_data, addr)

    def process_qr(self, recv_data: bytes, address: Address) -> None:
        logging.debug("process_qr address: %s", address)
        if (
            recv_data[0] == 0x09 and len(recv_data) >= 5
        ):  # 09,4xUid,'civ4bts','0'  - game checks if qr is up
            resp = b"\xfe\xfd\x09" + recv_data[1:5] + b"\x00"
            self.qr_send_to(resp, address, "09")
        elif recv_data[0] == 0x08 and len(recv_data) >= 5:  # 08 4xuid - ping
            resp = b"\xfe\xfd\x08" + recv_data[1:5]
            self.qr_send_to(resp, address, "08")
        elif recv_data[0] == 0x07 and len(recv_data) >= 5:  # 06 ACK - no response
            # TODO debug output this thing
            # hexprint(recv_data)
            pass
        elif recv_data[0] == 0x01 and len(recv_data) >= 5:  # resp to our challenge
            resp = b"\xfe\xfd\x0a" + recv_data[1:5]
            self.qr_send_to(resp, address, "01")
        elif recv_data[0] == 0x03 and len(recv_data) >= 5:
            parsed = SBQRServer.qr_parse03(recv_data)
            statechanged = int(parsed.get("statechanged", "0"))
            if statechanged == 3:
                if address in self.hosts:
                    del self.hosts[address]
                self._metric_games_total.inc()
                self.hosts[address] = GameHost(*address)
                self.hosts[address].sessionid = recv_data[1:5]
                self.hosts[address].data = parsed
                resp = b"\xfe\xfd\x01" + recv_data[1:5] + gs_consts.ghchal
                self.qr_send_to(resp, address, "03-3")
                self.sb_sendpush02(self.hosts[address])
            elif statechanged == 2:
                if address in self.hosts:
                    self.sb_senddel04(address)
                    del self.hosts[address]
            elif statechanged == 1:
                if address in self.hosts:
                    self.hosts[address].data = parsed
                    self.hosts[address].refresh()
                    self.sb_sendpush02(self.hosts[address])
            elif statechanged == 0:
                if address in self.hosts:
                    self.hosts[address].refresh()

        self.log_hostlist()

    def sb_sendpush02(self, host: GameHost) -> None:
        msg = b"\x02"
        flags = 0
        flags_buffer = b""
        if len(host.data) != 0:
            flags |= gs_consts.UNSOLICITED_UDP_FLAG
            flags |= gs_consts.HAS_KEYS_FLAG
            if "natneg" in host.data:
                flags |= gs_consts.CONNECT_NEGOTIATE_FLAG
                flags |= gs_consts.NONSTANDARD_PORT_FLAG
                flags |= gs_consts.PRIVATE_IP_FLAG  # ?
                flags |= gs_consts.NONSTANDARD_PRIVATE_PORT_FLAG  # ?
        msg += byteencode.uint8(flags)
        flags_buffer += byteencode.ipaddr(host.ip)
        flags_buffer += byteencode.uint16(host.port)
        localips: List[str] = []
        for key1, value1 in host.data.items():
            if key1.startswith("localip"):
                localips.append(value1)
        if len(localips) == 1:
            localip = localips[0]
            logging.info("sb_sendpush02, single localip: %s", localip)
        elif not localips:
            logging.warning("sb_sendpush02: Missing localips, using fake")
            localip = "127.0.0.1"
        else:
            localip = random.choice(localips)
            logging.info(
                "sb_sendpush02: Multiple localips: %s, using random one: %s",
                localips,
                localip,
            )
        flags_buffer += byteencode.ipaddr(localip)
        flags_buffer += byteencode.uint16(int(host.data.get("localport", 6500)))
        msg += flags_buffer
        for field in gs_consts.defaultfields:
            msg += host.data[field].encode(errors="ignore") + b"\x00"
        msg += b"\x01"
        l = byteencode.uint16(len(msg) + 2)
        msg = l + msg
        # iterate through SBClients and make a message for each
        logging.info(
            "Sending info about host %s to %d clients",
            host,
            len(self._clients_by_socket),
        )
        for client in self._clients_by_socket.values():
            client.write(msg)

    def sb_senddel04(self, address: Address) -> None:
        msg = b"\x00\x09\x04"
        msg += byteencode.ipaddr(address[0])
        msg += byteencode.uint16(address[1])
        for client in self._clients_by_socket.values():
            client.write(msg)

    def run(self) -> None:
        logging.info("Server ready, waiting for connections.")
        while True:
            self.select()
            now = time.time()
            if self.last_aliveness_check + 10 < now:
                for client in self._clients_by_socket.values():
                    client.check_aliveness()
                self.last_aliveness_check = now


@click.command()
@click.option(
    "--prometheus",
    default="",
    help="enable prometheus metrics at given address:port, set to empty to disable",
)
@click_log.simple_verbosity_option(logger)
def main(prometheus: str):
    if prometheus:
        try:
            addr, port_str = prometheus.split(":")
            port = int(port_str)
        except ValueError:
            addr = prometheus
            port = 9148
        logger.info(f"Starting prometheus server on {addr}:{port}")
        start_http_server(port=port, addr=addr)

    server = SBQRServer()
    try:
        server.run()
    except KeyboardInterrupt:
        logger.info("gamebrowser server stopped")
