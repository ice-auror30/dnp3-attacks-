#used for High School CDC 2015
import hashlib

email = raw_input("enter email: ")
m = hashlib.md5()
n = hashlib.sha1()
m.update(email)
str = m.hexdigest()
n.update(str)
print n.hexdigest()
