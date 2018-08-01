import socket
import sys
import netifaces as netif# pip install netifaces

def get_victim_mac(victim_ip):
    for i in netif.interfaces():
        addrs = netif.ifaddresses(i)
        print addrs
        victim_mac = addrs[netif.AF_LINK][0]['addr']
        get_victim_ip = addrs[netif.AF_INET][0]['addr']

        if get_victim_ip == victim_ip:
            return vimctim_mac


def main(interface, victim_ip, gateway_ip):
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
    s.bind((interface, 0))

    my_mac = netif.ifaddresses(interface)[netif.AF_LINK][0]['addr']

    victim_mac = get_victim_mac(victim_ip)

    print victim_mac

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[3])
