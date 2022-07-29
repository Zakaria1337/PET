from binascii import hexlify
from util.Parser import b2x, hex2Mac
import socket



def parseIpv4(header):
    version = hexlify(header[0]).decode()
    service = b2x(hexlify(header[1]))
    len = str(header[2])
    identification = str(header[3])
    flag = b2x(hexlify(header[4]))
    ttl = str(header[5])
    protocol = int(header[6])
    sum = b2x(hexlify(header[7]))
    src = socket.inet_ntoa(header[8])
    dst = socket.inet_ntoa(header[9])
    return (version, service, len, identification, flag, ttl, protocol, sum, src, dst)

def parseIpv6(header):
    first = hexlify(header[0])
    (vrs, tra, flow) = [first[0], first[1:2], first[3:]]
    lenp = int(header[1])
    next = int(header[2])
    hop = str(header[3])
    src = socket.inet_ntop(socket.AF_INET6,header[4])
    dst = socket.inet_ntop(socket.AF_INET6,header[5])
    return (vrs, b2x(tra), b2x(flow), lenp, next, hop, src, dst)

def parseARP(head):
    hw_type = hexlify(head[0]).decode().lstrip("0")
    prototype = b2x(hexlify(head[1]))
    hwlen = hexlify(head[2]).decode().lstrip("0")
    protolen = hexlify(head[3]).decode().lstrip("0")
    op = hexlify(head[4]).decode().lstrip("0")
    macsrc = hex2Mac(hexlify(head[5]).decode())
    srcaddr = socket.inet_ntoa(head[6])
    mactar = hex2Mac(hexlify(head[7]).decode())
    taraddr = socket.inet_ntoa(head[8])
    return(hw_type, prototype, hwlen, protolen, op, macsrc, srcaddr, mactar, taraddr)
