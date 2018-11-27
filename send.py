# -*-coding=utf-8 -*-
# by:hijack89
# date:2018-11-2

import scapy.all as scapy
import random


class FakePkt():
    def __init__(self, src, dst, iface, message='hello'):
        self.src = src
        self.dst = dst
        self.iface = iface
        if len(message) <= 256:
            self.message = message
        else:
            raise Exception
        self.data = self.__create_data()

    def __create_data(self):
        hex_m = ''.join(hex(ord(i)).replace("0x", "") for i in self.message)
        data = hex_m
        return data

    def __create_ips(self):
        head = self.src.split(".")
        head.pop()
        src_head = ".".join(i for i in head)
        dst_tail = int(self.dst.split(".")[-1])
        ips = [src_head + "." + str(int(self.src.split(".")[-1]) ^ dst_tail)]
        data = self.__create_data()
        for i in range(0, len(data), 2):
            one_byte = int(data[i] + data[i + 1], 16)
            encode_iptail = one_byte ^ dst_tail
            ips.append(src_head + "." + str(encode_iptail))
        ips.append(src_head + "." + str(int(self.src.split(".")[-1]) ^ dst_tail))
        return ips

    def __create_mac(self, n, ip):
        ip = ip.split(".")
        mac = scapy.RandMAC()
        mac = mac.split(":")
        mac[-1] = hex(n ^ int(ip[-1])).replace("0x", "")
        if len(mac[-1]) == 1:
            mac[-1] = "0" + mac[-1]
        return ':'.join(i for i in mac)

    def create_udp(self):
        self.pkts = []
        ips = self.__create_ips()
        base_port = random.randint(5000, 5100)
        n = 0
        for ip in ips:
            n += 1
            src_mac = self.__create_mac(n, ip)
            pkt = scapy.Ether(src=src_mac) / scapy.IP(src=ip, dst=self.dst) / scapy.UDP(sport=base_port,
                                                                                        dport=base_port + 10)
            # print pkt.show()
            self.pkts.append(pkt)
        return self.pkts

    def sendpkt(self):
        scapy.sendp(self.pkts, inter=0.01, count=1, iface=self.iface)
        '''
        for pkt in self.pkts:
            scapy.sendp(pkt, inter=0.01, count=1, iface=self.iface)
            print pkt.src + " " + pkt.payload.src + "::" + pkt.dst + " " + pkt.payload.dst
        print "send %d pkts." % len(self.pkts)
        '''

if __name__ == '__main__':
    print "send start"

    src, dst = "192.168.73.1", "192.168.73.136"
    iface = "VMware Virtual Ethernet Adapter for VMnet8"
    message = "test"

    pkt = FakePkt(src, dst, iface, message)
    pkt.create_udp()
    pkt.sendpkt()
    print "send end"
