import socket
from typing import Dict

from .login_client import LoginBaseClient, LoginClient, SearchClient
from .network import NetworkServer
from .user_db import UserDB


class LoginServer(NetworkServer[LoginBaseClient]):
    user_db: UserDB
    _login_clients_by_id: Dict[int, LoginClient]

    def __init__(self, user_db_path: str):
        super().__init__()

        self.user_db = UserDB(user_db_path)
        self._login_clients_by_id = {}

        gp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        gp_socket.setblocking(False)
        try:
            gp_socket.bind(("", 29900))
        except socket.error as err:
            print("Bind failed for gp (29900 TCP): {}".format(err))
            raise err
        gp_socket.listen(5)
        gp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        gp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 120)
        gp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 60)
        gp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        self.register_server(gp_socket, LoginClient)

        gps_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        gps_socket.setblocking(False)
        try:
            gps_socket.bind(("", 29901))
        except socket.error as err:
            print("Bind failed for gps (29901 TCP): {}".format(err))
            raise err
        gps_socket.listen(5)
        gps_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        gps_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 120)
        gps_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 60)
        gps_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        self.register_server(gps_socket, SearchClient)

    # Called after login by the client iself
    def register_gpclient(self, client: LoginClient) -> None:
        self._login_clients_by_id[client.id] = client

    # Called by base class
    def unregister_client(self, sock: socket.socket, client: LoginBaseClient) -> None:
        try:
            if isinstance(client, LoginClient):
                del self._login_clients_by_id[client.id]
        except KeyError:
            pass
        super().unregister_client(sock, client)

    def gpclient_by_id(self, id: int) -> LoginClient:
        return self._login_clients_by_id[id]
