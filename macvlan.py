#!/bin/python
import os
import sys
import socket
import struct
import argparse

def __generate_mac(ip):
    # magic is 0x484f
    b=[0x48, 0xf4, 0, 0, 0, 0]
    for i in range(0,4):
        b[2+i] = (ip >> (24 - i * 8))  & 0xff
    return ':'.join('%02x' % i for i in b)

def generate_mac(ips, num):
    start = socket.ntohl(struct.unpack("I",socket.inet_aton(str(ips)))[0])
    end = start + num
    mac = []
    for ip in range(start, end):
        mac.append(__generate_mac(ip))
    return mac

def create_mac_vlan(name, mac, eth):
    cmd = "ip link add link %s %s address %s type macvlan" % (eth, name, mac)
    ret = os.system(cmd)
    return ret >> 8

def create_mac_vlans(ips, num, name="mac", eth="eth0"):
    macs = generate_mac(ips, num)

    for i in range(0, len(macs)):
        mac = macs[i]
        ret = create_mac_vlan(name+str(i), mac, eth)
        if ret != 0:
            print("%s create error" % (name+str(i)))
            return ret

    return 0



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='create macvlan adapt to ip_map kernel module')
    parser.add_argument('--ip', help='the start of lan ip')
    parser.add_argument('--num', type=int, help='the number machine in lan')
    parser.add_argument('--name', help='prefix of the macvlan name')
    parser.add_argument('--eth', help='the macvlan based interface')
    args = parser.parse_args()
    sys.exit(create_mac_vlans(args.ip, args.num, args.name, args.eth))

