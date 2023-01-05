from scapy.all import *
sendp(Ether()/IP(),iface='veth1')