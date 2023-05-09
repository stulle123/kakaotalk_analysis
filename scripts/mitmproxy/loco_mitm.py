import logging

from mitmproxy import connection
from mitmproxy import tcp
from mitmproxy import tls
from mitmproxy.utils import human
from mitmproxy.utils import strutils

from lib.loco_parser import LocoParser


class LocoMitm:
    @staticmethod
    def get_addr(server: connection.Server):
        return server.peername or server.address

    def tls_clienthello(self, data: tls.ClientHelloData):
        server_address = self.get_addr(data.context.server)
        logging.info(f"Skip TLS intercept for {human.format_address(server_address)}.")
        data.ignore_connection = True

    def tcp_message(self, flow: tcp.TCPFlow):
        message = flow.messages[-1]
        parser = LocoParser()
        parser.parse(message.content)
        tampered_packet = parser.inject_message("foo", "bar")

        if tampered_packet:
            message.content = tampered_packet

        if parser.loco_packet:
            logging.info(
                f"from_client={message.from_client}, content={parser.loco_packet.get_packet_as_dict()}"
            )
        else:
            logging.info(
                f"from_client={message.from_client}), content={strutils.bytes_to_escaped_str(message.content)}]"
            )


addons = [LocoMitm()]
