import base64
from pathlib import Path
from typing import Final

import pytest
import ruamel.yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from lib.crypto_utils import get_rsa_public_key_pem, rsa_decrypt, rsa_encrypt
from lib.loco_parser import LocoEncryptedPacket, LocoPacket, LocoParser

yaml = ruamel.yaml.YAML(typ="safe", pure=True)

_LOCO_ENYCRYPTED_PACKETS_RAW: Final = [
    "blsync_packet_client.raw",
    "chatonroom_packet_client.raw",
    "chatonroom_packet_server.raw",
    "checkin_packet_client.raw",
    "empty_loco_packet.raw",
    "getlpk_packet_client.raw",
    "getlpk_packet_server.raw",
    "getmem_packet_client.raw",
    "getmem_packet_server.raw",
    "getpk_packet_client.raw",
    "getpk_packet_server.raw",
    "gettoken_packet_client.raw",
    "gettoken_packet_server.raw",
    "loginlist_packet_client.raw",
    "loginlist_packet_client_0.raw",
    "screate_packet_client.raw",
    "screate_packet_server.raw",
    "setpk_packet_client.raw",
    "setpk_packet_server.raw",
    "setsk_packet_client_0.raw",
    "setsk_packet_server.raw",
    "swrite_packet_client.raw",
    "syncmsg_packet_client.raw",
    "syncmsg_packet_server.raw",
]
_LOCO_PACKETS_YAML: Final = [
    "blsync_packet_client.yaml",
    "chatonroom_packet_client.yaml",
    "chatonroom_packet_server.yaml",
    "checkin_packet_client.yaml",
    "empty_loco_packet.yaml",
    "getlpk_packet_client.yaml",
    "getlpk_packet_server.yaml",
    "getmem_packet_client.yaml",
    "getmem_packet_server.yaml",
    "getpk_packet_client.yaml",
    "getpk_packet_server.yaml",
    "gettoken_packet_client.yaml",
    "gettoken_packet_server.yaml",
    "loginlist_packet_client.yaml",
    "loginlist_packet_client_0.yaml",
    "screate_packet_client.yaml",
    "screate_packet_server.yaml",
    "setpk_packet_client.yaml",
    "setpk_packet_server.yaml",
    "setsk_packet_client_0.yaml",
    "setsk_packet_server.yaml",
    "swrite_packet_client.yaml",
    "syncmsg_packet_client.yaml",
    "syncmsg_packet_server.yaml",
]
_IV: Final = 16 * b"\x00"
_KAKAOTALK_RSA_PUBLIC_KEY: Final = b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9itiCdmMHYWJXq4GE0Xm\ncYy2/ifVv7lYZgPkqw2hjhhhPRYBGchuWUrWynqK0lQODvRIOyM3Q9khv8CPKss2\nipkBbQ4HHRSmpR346TbMQrTUjUCDSSfyY8Awy+DjGzWfn46uY0sHutP6wbGNhlmq\nc8mLP1mjAePYXE3QL1o1oWxhMqyRNY/RSrYMnqowt4u1/Fb3TVQ99uq6q7GkSWJC\nW+ALzx8eTHqnDUl7VqIS0EfNrHsExaR8m5HubWjfg8ZGX4+NNd9kNEINXTVfAcGH\nZ6XuMT1bdeW/F3IbAslbfH7Uj3LRTQhZ8iDzG19DIQy73s/IajPmQllFJaDdIr/w\nFQIDAQAB"
_SHARED_SECRET: Final = b"SHARED_SECRET"


def get_rsa_2048_key_pair():
    key_pair_pem = b"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD2K2IJ2YwdhYle\nrgYTReZxjLb+J9W/uVhmA+SrDaGOGGE9FgEZyG5ZStbKeorSVA4O9Eg7IzdD2SG/\nwI8qyzaKmQFtDgcdFKalHfjpNsxCtNSNQINJJ/JjwDDL4OMbNZ+fjq5jSwe60/rB\nsY2GWapzyYs/WaMB49hcTdAvWjWhbGEyrJE1j9FKtgyeqjC3i7X8VvdNVD326rqr\nsaRJYkJb4AvPHx5MeqcNSXtWohLQR82sewTFpHybke5taN+DxkZfj40132Q0Qg1d\nNV8BwYdnpe4xPVt15b8XchsCyVt8ftSPctFNCFnyIPMbX0MhDLvez8hqM+ZCWUUl\noN0iv/AVAgMBAAECggEAMUOqWZVHZKsSPDfwcE/3V7cU8hUPwlA54CScUR0nvTOk\n1iA+tSW267i99oSCnqgCrjx17hvUlgfwqJrFLAfCEQeg0O3TP58f4IB4jVeRljHx\nLZmBDJVpfUv7l/mYCZx4JurbfHSKBfohPz0kuQPdyFFHxDRQmnK6HHLYHHndrMGK\nzmuH+DigjPy2WIJvuWnMQE6kMnIdncHu6PpuZb8syryYQSWEgXUeUL96CHdhNwNk\nayXWRli6uqVM9yBYPUHU11V7LrZYoFp3T1P81Gd+SVSUfMumS37l18q7fZXbrRr8\nsRWes75cwulp5KZsmsQVBaMbl4Dm3iClDJ5nSqpPIQKBgQD/FnftIGnKuiSX382J\nJdGHzR2XkYHiiL/zZEkLAT+5NjJRS6UNeK5o/M1L6boPycvytzJmH0jV0sC3X4SY\n7XOGXnmJmnzG2zxDrdge+j+KGJ3i0eTdQBE8+kC1NUCZHSEYRN4MZEzHfAHop5NF\nIaHBbDnqHOudomrb4DrIow6/5QKBgQD3DL/1jK4qIrryWuPzN7cpWft6vwHG7t+q\nnf9a9tjZ5gec/I6TvbM0Qj4ok005NjwUI1BhR2OGoSd/Axd59Xx4P+Q4mNPiysRi\n+ItmQlnV3U6l1m2A2iznF1/2127pQT7NUfaDoX9MNSOzLCCGBWqSktP+FhLD8csU\nHWLNelyMcQKBgA1LxoR9pAYFHdMsvzHe3sUNU/WKiBKeviKZn5ULQ58LzCOgpcHG\nAJFIXAsQ67nW8uJ72gyopMtAaPsl52txNQxT8FHT050p4EJG1XUH5jf0gIZKGnvN\n0xgykxze4bcZZZg2Pry2nanoNNFDqtF3p07FrV8ekslspdVAItBCb4phAoGAO9Ta\nqJ1pkMrYe9mHW2Ai++DPBus7gvJXOPsK3Pzrh9ot/dcssJtAy2c/ppQGH9UCt93V\nmbmwYOqmphwZk2/gtT7EBvD8X/C7nzyShjGLkEAIzCEiZBJyzYTbuOxz8AndK9yt\n1zNFoS89dic5uTuWk+j7bo3p/YqRpE15oEoCIAECgYEA6Sj9AJKKdtdhY1xRTJvh\n6r85iW24EVN1K4eZqNLKiu6l7N1zofxfwXlZPOwE5YYN965xVKGHocwL0dk3Js5C\nw5+hHfxWLomnz+c2tv7kkTJTZzKfSR/6gzsdR4kX9hS2bntQdH137RpobvdGcJGe\nh5FwC5Myfu2oxAqtvX6ii9g=\n-----END PRIVATE KEY-----\n"
    return serialization.load_pem_private_key(key_pair_pem, password=None)


@pytest.fixture
def parser():
    return LocoParser()


@pytest.fixture(params=_LOCO_PACKETS_YAML)
def loco_packet_packet(request):
    with open(Path(request.param), encoding="utf-8") as packet_yaml:
        loco_packet_dict = yaml.load(packet_yaml)

    return LocoPacket(
        loco_packet_dict.get("id"),
        loco_packet_dict.get("status_code"),
        loco_packet_dict.get("loco_command"),
        loco_packet_dict.get("body_type"),
        loco_packet_dict.get("body_length"),
        loco_packet_dict.get("body_payload"),
    )


@pytest.fixture
def loco_encrypted_packet():
    return LocoEncryptedPacket(length=0, iv=_IV, payload=b"")


@pytest.fixture(params=zip(_LOCO_ENYCRYPTED_PACKETS_RAW, _LOCO_PACKETS_YAML))
def loco_zip(request):
    return request.param


def test_parse(parser, loco_zip):
    encrypted_loco_packet_path, loco_packet_yaml_path = loco_zip

    with open(encrypted_loco_packet_path, "rb") as packet_raw, open(
        loco_packet_yaml_path, encoding="utf-8"
    ) as packet_yaml:
        encrypted_loco_packet = packet_raw.read()
        loco_packet_dict = yaml.load(packet_yaml)

    parser.parse(encrypted_loco_packet)

    packet = LocoPacket(
        loco_packet_dict.get("id"),
        loco_packet_dict.get("status_code"),
        loco_packet_dict.get("loco_command"),
        loco_packet_dict.get("body_type"),
        loco_packet_dict.get("body_length"),
        loco_packet_dict.get("body_payload"),
    )

    assert parser.loco_packet.get_packet_as_dict() == packet.get_packet_as_dict()


def test_inject_public_key(parser, loco_encrypted_packet):
    rsa_key_pair = get_rsa_2048_key_pair()

    with open(Path("encrypted_screate_packet_with_mitm_key.raw"), "rb") as packet_raw:
        encrypted_screate_packet_with_mitm_key = packet_raw.read()

    with open(Path("screate_loco_packet.yaml"), encoding="utf-8") as packet_yaml:
        screate_dict = yaml.load(packet_yaml)

    original_public_key = screate_dict.get("body_payload").get("pi")[0].get("ek")
    assert original_public_key

    screate_packet = LocoPacket(
        screate_dict.get("id"),
        screate_dict.get("status_code"),
        screate_dict.get("loco_command"),
        screate_dict.get("body_type"),
        screate_dict.get("body_length"),
        screate_dict.get("body_payload"),
    )

    parser.loco_packet = screate_packet
    assert parser.loco_packet

    parser.loco_encrypted_packet = loco_encrypted_packet
    assert parser.loco_encrypted_packet

    assert parser.inject_public_key(rsa_key_pair) == (
        original_public_key.encode(),
        encrypted_screate_packet_with_mitm_key,
    )


def test_get_shared_secret(parser):
    rsa_key_pair = get_rsa_2048_key_pair()

    with open(
        Path("setsk_loco_packet_sk_enc_with_mitm_key.yaml"), encoding="utf-8"
    ) as packet_yaml:
        setsk_dict = yaml.load(packet_yaml)

    encrypted_shared_secret = setsk_dict.get("body_payload").get("sk")[0]
    decrypted_shared_secret = rsa_decrypt(
        base64.b64decode(encrypted_shared_secret), rsa_key_pair
    )

    assert decrypted_shared_secret == _SHARED_SECRET

    setsk_packet = LocoPacket(
        setsk_dict.get("id"),
        setsk_dict.get("status_code"),
        setsk_dict.get("loco_command"),
        setsk_dict.get("body_type"),
        setsk_dict.get("body_length"),
        setsk_dict.get("body_payload"),
    )

    parser.loco_packet = setsk_packet
    assert parser.loco_packet

    assert parser.get_shared_secret(rsa_key_pair) == decrypted_shared_secret


def test_encrypt_shared_secret(parser, loco_encrypted_packet):
    with open(Path("encrypted_setsk_packet.raw"), "rb") as packet_raw:
        encrypted_setsk_packet = packet_raw.read()

    with open(
        Path("setsk_loco_packet_sk_enc_with_mitm_key.yaml"), encoding="utf-8"
    ) as packet_yaml:
        setsk_dict = yaml.load(packet_yaml)

    setsk_packet = LocoPacket(
        setsk_dict.get("id"),
        setsk_dict.get("status_code"),
        setsk_dict.get("loco_command"),
        setsk_dict.get("body_type"),
        setsk_dict.get("body_length"),
        setsk_dict.get("body_payload"),
    )

    parser.loco_packet = setsk_packet
    assert parser.loco_packet

    parser.loco_encrypted_packet = loco_encrypted_packet
    assert parser.loco_encrypted_packet

    assert (
        parser.encrypt_shared_secret(_SHARED_SECRET, _KAKAOTALK_RSA_PUBLIC_KEY)
        == encrypted_setsk_packet
    )
