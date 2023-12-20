import logging

from mitmproxy import connection, tls
from mitmproxy.utils import human


class TLSIntercept:
    def __init__(self, host) -> None:
        self.host = host

    @staticmethod
    def get_addr(server: connection.Server):
        return server.peername or server.address

    def tls_clienthello(self, data: tls.ClientHelloData):
        if data.context.client.sni == self.host:
            logging.info("MITM host: %s", self.host)
            return
        else:
            server_address = self.get_addr(data.context.server)
            logging.info(
                "Skip TLS intercept for %s.", human.format_address(server_address)
            )
            data.ignore_connection = True


addons = [TLSIntercept(host="buy.kakao.com")]
