from scapy.all import *
sendp(Ether()/IP(),iface='veth1',count=1000)
