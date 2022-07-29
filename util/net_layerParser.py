from binascii import hexlify
from util.Parser import hex2Mac


def parseEth(header):
    dst = hexlify(header[0]).decode()
    src = hexlify(header[1]).decode()
    type = hexlify(header[2]).decode()
    return (hex2Mac(dst), hex2Mac(src), type)