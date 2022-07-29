from binascii import hexlify
import re

"""

CREATED BY ZAKARIA HARIRA @2022

"""

def hex2Mac(hex):
    s = re.findall("..", hex)
    return ':'.join(s)

def b2x(bdata:str):
    return hex(int(bdata, base=16))

def parseProto(proto):
    if proto == 6:
        return "TCP"
    elif proto == 17:
        return "UDP"
