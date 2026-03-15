#!/usr/bin/env python3

import ipaddress
import argparse
import socket
import sys

def is_multicast(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_multicast and ip.version == 4
    except ValueError:
        return False

def main():
    p = argparse.ArgumentParser(description="Multicast Sender")
    p.add_argument("group", help="Multicast group address")
    p.add_argument("port", type=int, help="Port number")
    p.add_argument("message", help="Message to send")
    args = p.parse_args()

    if not is_multicast(args.group):
        print(f"error: {args.group} is not a valid IPv4 multicast address (224.0.0.0/4)", file=sys.stderr)
        sys.exit(2)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # allow reuse
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # ensure local loopback interface is used for multicast outgoing
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton("127.0.0.1"))
    # enable loopback so the sender also receives on localhost
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    # small TTL
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)

    msg = args.message.encode("utf-8")
    while True:
        sock.sendto(msg, (args.group, args.port))
        print(f"sent: {args.message}")
        sock.recvfrom(1024)  # receive response

if __name__ == "__main__":
    main()