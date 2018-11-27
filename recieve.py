# -*-coding=utf-8 -*-
# by:hijack89
# date:2018-11-2

import scapy.all as scapy
import time
import threading

messages = []
flag = 0
mutex = threading.Lock()
src = ""
dst = "192.168.73.136"


def decode_num(pkt):
    mac_tail = pkt[0].src.split(":")[-1]
    ip_tail = pkt[1].src.split(".")[-1]
    num = int(mac_tail, 16) ^ int(ip_tail)
    return num


def decode_data(pkt):
    message = chr(int(pkt[1].src.split(".")[-1]) ^ int(pkt[1].dst.split(".")[-1]))
    return message


def check_pkt(pkt):
    if pkt[2].sport >= 5000 and pkt[2].sport <= 5100 and pkt[2].dport - pkt[2].sport == 10:
        return pkt
    else:
        return False


def sort_mes(pkt):
    global messages
    global src
    messages.append((decode_num(pkt), decode_data(pkt)))
    if messages[-1][0] == 1:
        src_tail = str(ord(messages[-1][1]))
        src = pkt[1].src.split(".")
        src.pop()
        src.append(src_tail)
        src = ".".join(i for i in src)
    messages = sorted(messages, key=lambda x: x[0])
    print "recieve pkt from ip::" + pkt[1].src
    return True


def check_mes():
    global messages
    global flag
    global src

    if messages[-1][0] != 1 and messages[0][1] == messages[-1][1] and messages[0][0] == 1:
        print "recieve the last pkt\n"

        print "srcIP::" + src

        if len(messages) == messages[-1][0]:
            message = ""
            messages.pop(0)
            messages.pop()
            for n, m in messages:
                message += m
            print "recieve message success:\n" + message
            messages = []
            src = ""
            return 1
        else:
            messages.pop(0)
            messages.pop()
            print "recieve message fail.\n"
            for n, m in messages:
                print str(n) + ":" + m,
            messages = []
            src = ""
            return 2
    elif flag == 2:
        if src:
            print "srcIP::" + src
            messages.pop(0)
        else:
            print "no srcIP."
        print "message:"
        for n, m in messages:
            print str(n) + ":" + m,
        print "\n"
        messages = []
        src = ""
        return 2
    else:
        return 3


def timer():
    global flag
    global messages
    start = time.time()
    while (True):
        if mutex.acquire():
            if flag == 2:
                break
            elif flag == 0:
                start = time.time()
            elif time.time() - start >= 10:
                flag = 2
                print "timeout.recieve fail.\n"
            res = check_mes()
            if res == 1:
                flag = 2
                pass
            elif res == 2:
                flag = 2
                pass
            elif res == 3:
                pass

            mutex.release()
            time.sleep(0.1)
    mutex.release()


def analyse(pkt):
    global flag
    flag = 0
    time.sleep(0.1)
    if mutex.acquire():

        pkt = check_pkt(pkt)
        if (not pkt):
            return False
        sort_mes(pkt)
        flag = 1
        if threading.activeCount() == 1:
            t = threading.Thread(target=timer)
            t.start()
        mutex.release()

    return True


if __name__ == '__main__':
    print "start"
    receive = scapy.sniff(iface="eth0", filter="udp and host 192.168.73.136",
                          prn=lambda pkt: analyse(pkt))
    print "end"
