from binascii import hexlify

from util.Parser import b2x


def parseTCP(header):
    dport = str(header[0])
    sport = str(header[1])
    seq = str(header[2])
    ack = str(header[3])
    hlen = int(hexlify(header[4]), 16)
    win = str(header[5])
    sum = b2x(hexlify(header[6]))
    urgentp = str(header[7])
    return (dport, sport, seq, ack, hlen, win, sum, urgentp)

def parseUDP(header):
    udp_sport = int(hexlify(header[0]).decode(), 16)
    udp_dport = int(hexlify(header[1]).decode(), 16)
    udp_len = int(hexlify(header[2]), 16)
    udp_sum = b2x(hexlify(header[3]))
    return (udp_sport, udp_dport, udp_len, udp_sum)