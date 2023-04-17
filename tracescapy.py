import sys
from scapy.all import *

def traceroute(hostname):
    ttl = 1
    max_hops = 30
    timeout = 2

    while ttl <= max_hops:
        pkt = IP(dst=hostname, ttl=ttl) / UDP(dport=33434)
        reply = sr1(pkt, verbose=0, timeout=timeout)

        if reply is None:
            print("*\t*")
        elif reply.type == 3:
            print(ttl, "\t", reply.src)
            break
        else:
            print(ttl, "\t", reply.src)
        ttl += 1

if __name__ == "__main__":
    hostname = sys.argv[1]
    traceroute(hostname)