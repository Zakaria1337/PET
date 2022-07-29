import struct
from threading import Thread
import socket
from util import parseEth, parseIpv4, parseTCP, hex2Mac, parseUDP, parseARP, parseIpv6, parseProto
from termcolor import colored

"""

CREATED BY ZAKARIA HARIRA @2022

"""

class PET(Thread):
    def __init__(self, host, port):
        Thread.__init__(self)
        self.host = host
        self.port = port
        sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        self.sock = sock

    def run(self):
       while True:
            try:
                packet = self.sock.recvfrom(2048)
                ether = packet[0][0:14]
                ethhead = struct.unpack("!6s6s2s", ether)
                (dst, src, type) = parseEth(ethhead)
                sign = colored("[+]", "yellow", attrs=['bold'])
                ethflag = colored("----ETH----", "yellow", attrs=['bold', 'reverse'])
                arpsign = colored("[+]", "red", attrs=['bold'])
                arpflag = colored("----ARP----", "red", attrs=['bold', 'reverse'])
                ipv6sign = colored("[+]", "blue", attrs=['bold'])
                ipv6flag = colored("----IPv6----", "blue", attrs=['bold', 'reverse'])
                ipv4sign = colored("[+]", "cyan", attrs=['bold'])
                ipv4flag = colored("----IPv4----", "cyan", attrs=['bold', 'reverse'])
                udpsign = colored("[+]", "magenta", attrs=['bold'])
                udpflag = colored("----UDP----", "magenta", attrs=['bold', 'reverse'])
                tcpsign = colored("[+]", "white", attrs=['bold'])
                tcpflag = colored("----TCP----", "white", attrs=['bold', 'reverse'])
                print(f"{ethflag}\n{sign} Mac Source : {src}\n{sign} Mac Destination : {dst}\n{sign} Type : {type}\n")
                if type == "0806":
                    arp = packet[0][14:42]
                    arphead = struct.unpack("!2s2s1s1s2s6s4s6s4s", arp)
                    (hw_type, prototype, hwlen, protolen, op, macsrc, srcaddr, mactar, taraddr) = parseARP(arphead)
                    print(f"{arpflag}\n{arpsign} Hardware type : {hw_type}\n{arpsign} Protocol type : {prototype}\n{arpsign} Hardware size : {hwlen}\n{arpsign} Protocol size : {protolen}\n{arpsign} Opcode : {op}\n{arpsign} Sender Mac Address : {macsrc}\n{arpsign} Sender Ip Address : {srcaddr}\n{arpsign} Target Mac Address : {mactar}\n{arpsign} Target Ip Address : {taraddr}\n")
                elif type == "86dd":
                    ipv6 = packet[0][14:54]
                    ipheader = struct.unpack("!4sHBB16s16s", ipv6)
                    (vrs, tra, flow, lenp, next, hop, src_, dst_) = parseIpv6(ipheader)
                    print(f"{ipv6flag}\n{ipv6sign} Version : {vrs}\n{ipv6sign} Traffic class : {tra}\n{ipv6sign} Flow label : {flow}\n{ipv6sign} Payload length : {lenp}\n{ipv6sign} Next header : {next}\n{ipv6sign} Hop limit : {hop}\n{ipv6sign} Source address : {src_}\n{ipv6sign} Destination Address : {dst_}\n")
                    if next == 17:
                        udp = packet[0][54:62]
                        data = packet[0][62:]
                        udphead = struct.unpack("!2s2s2s2s", udp)
                        (udpsport, udpdport, udplen, udpsum) = parseUDP(udphead)
                        print(f"{udpflag}:\n{udpsign} Source Port : {udpsport}\n{udpsign} Destination Port : {udpdport}\n{udpsign} Length : {udplen}\n{udpsign} Checksum : {udpsum}")
                        print("----DATA----: {}".format(data))
                    if next == 6:
                        tcp = packet[0][54:74]
                        tcphead = struct.unpack("!HHII2sH2sH", tcp)
                        data = packet[0][74:]
                        (dport, sport, seq, ack, hlen, win, tcp_sum, urgentp) = parseTCP(tcphead)
                        print(f"{tcpflag}\n{tcpsign} Source port : {sport}\n{tcpsign} Destination port : {dport}\n{tcpsign} Sequence number : {seq}\n{tcpsign} Acknowlegement number : {ack} Header length : {hlen}\n{tcpsign} Window size : {win}\n{tcpsign} Checksum : {tcp_sum}\n{tcpsign} Urgent Pointer : {urgentp}\n")
                        print("----DATA----: {}".format(data))

                elif type == "0800":
                    ip = packet[0][14:34]
                    iphead = struct.unpack("!1s1s1H1H2s1B1B2s4s4s", ip)
                    (version, service, len, identification, flag, ttl, protocol, ip_sum, ip_src, ip_dst) = parseIpv4(iphead)
                    print(f"{ipv4flag}\n{ipv4sign} Version : {version}\n{ipv4sign} Service : {service}\n{ipv4sign} Length : {len}\n{ipv4sign} Identification : {identification}\n{ipv4sign} Flag : {flag}\n{ipv4sign} ttl : {ttl}\n{ipv4sign} Protocol : {parseProto(protocol)}\n{ipv4sign} Checksum : {ip_sum}\n{ipv4sign} Ip Source : {ip_src}\n{ipv4sign} Ip Destination : {ip_dst}\n\n")
                    if parseProto(protocol) == "TCP":
                        tcp = packet[0][34:54]
                        tcphead = struct.unpack("!HHII2sH2sH", tcp)
                        data = packet[0][54:]
                        (dport, sport, seq, ack, hlen, win, tcp_sum, urgentp) = parseTCP(tcphead)
                        print(f"{tcpflag}\n{tcpsign} Source port : {sport}\n{tcpsign} Destination port : {dport}\n{tcpsign} Sequence number : {seq}\n{tcpsign} Acknowlegement number : {ack} Header length : {hlen}\n{tcpsign} Window size : {win}\n{tcpsign} Checksum : {tcp_sum}\n{tcpsign} Urgent Pointer : {urgentp}\n")
                        print("----DATA----: {}".format(data))
                    if parseProto(protocol) == "UDP":
                        udp = packet[0][34:42]
                        data = packet[0][42:]
                        udphead = struct.unpack("!2s2s2s2s", udp)
                        (udpsport, udpdport, udplen, udpsum) = parseUDP(udphead)
                        print(f"{udpflag}\n{udpsign} Source port : {udpsport}\n{udpsign} Destination port : {udpdport}\n{udpsign} Length : {udplen}\n{udpsign} Checksum : {udpsum}\n")
            except KeyboardInterrupt:
                print("[!] EXIT...")
