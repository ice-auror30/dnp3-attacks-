import sys

fd=open('packet_dump.txt','r')
payload=fd.read()
fd.close()
payload=payload[:292]
fd=open('dummy_packet.txt','w')
fd.write(payload)
fd.close()
print payload.encode('hex')
print "LEN:"+str(len(payload))
