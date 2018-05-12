import subprocess
import struct
import math

def magnitude(x):
        return 0 if x==0 else int(math.floor(math.log10(abs(x)))) + 1

def round_total_digits(x, digits=6):
        return round(x, digits - magnitude(x))

def hex_to_float(s):
	while(len(s) < 4):
		s = '\x00'+s
        return round_total_digits(struct.unpack('<f',s)[0])

def float_to_hex(f):
        h = hex(struct.unpack('<I',struct.pack('>f', f))[0])
        #print str(h)
        #if len(h)!=8:
        #	h=h[:2]+'0000'+h[2:]
        return hex_to_byte(h[2:])
#def hex_to_float(s):
#        return round_total_digits(struct.unpack('<f',s)[0])
#
#def float_to_hex(f):
#        h = hex(struct.unpack('<I',struct.pack('>f', f))[0])
#        return hex_to_byte(h[2:])

def hex_to_byte(hexstr):
        bytes = []
        hexstr = ''.join(hexstr.split(" "))
        for i in range(0, len(hexstr), 2):
                bytes.append(chr(int (hexstr[i:i+2], 16)))
        #print "IN HEX_TO_BYTES:"+str(bytes)
        return ''.join(bytes)
#print str(hex_to_float(float_to_hex(100.00)))
def byte_to_bits(s):
        data = map(hex, map(ord, s))
        bits = bin(int(data[0], base=16))[2:]
	i = len(bits)
	while(i < 8):
		bits = "0"+bits
		i=i+1
	return bits

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

