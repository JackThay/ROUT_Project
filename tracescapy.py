'''
Created on April 16, 2023
@author: Thierry Ung, Jack Thay
Main side of ROUT Project
'''
import sys
from scapy.all import *

def traceroute(hostname):
    ttl = 1 # Time to live
    max_hops = 30 # Maximum hops packet can do
    timeout = 2 # Time before packet is considered lost

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
    hostname = sys.argv[1] # ==> @Thierry, IndexError: list index out of range?
    traceroute(hostname)