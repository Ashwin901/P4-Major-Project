#!/usr/bin/env python3
import sys
import struct
import os
import socket
import random

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw, Ether
from scapy.layers.inet import _IPOption_HDR

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 1234:
        print("got a packet")
        pkt.show2()
        send_ack_packet(pkt=pkt)
        sys.stdout.flush()

def send_ack_packet(pkt):
    print("Sending ack packet to h1")
    addr = socket.gethostbyname("10.0.0.1")
    iface = get_if()
    
    print(("sending on interface %s to %s" % (iface, str(addr))))
    ack_pkt =  Ether(src=pkt.src, dst='ff:ff:ff:ff:ff:ff')
    ack_pkt = ack_pkt /IP(dst=addr) / TCP(dport=1235, sport=random.randint(49152,65535), seq=897,ack=897,flags="A")
    ack_pkt.show2()
    
    sendp(ack_pkt, iface=iface, verbose=False)



def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print(("sniffing on %s" % iface))
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
