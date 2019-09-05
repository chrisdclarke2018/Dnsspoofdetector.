  GNU nano 3.2        DNSprotect1.py                  


from scapy.all import *
import netaddr
dns_queries={}
def test(pkt):
   if pkt.haslayer(DNSRR):
         hostname=pkt.getlayer(DNS).qd.qname
         ip=pkt[DNS][DNSRR].rdata
#checks for valid ip addres
         if netaddr.valid_ipv4(ip) is True:
#is the ip in the dictionary
            if hostname in dns_queries:
#if the ip addr is for another hostname
               if dns_queries[hostname]!=ip:
                  print('Possible DNS spoofing attack DETECTED')
            else:
#put it in the dictioary
               dns_queries[hostname]=ip
sniff(filter="udp port 53", iface="wlan0",prn=test)

