#!/usr/bin/python

import sys, re

ipaddr = re.compile("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}")
ipaddrFormatted = re.compile('''(
                              ((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}
                              (25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])
                              )''', re.X)

#regex for ("[0-255].[0-255].[0-255].[0-255]")


# iplist = ipaddr.search(f.read())
# print iplist.group()

f = open("sampleip.txt", "r")
#iplistcomplete = ipaddr.findall(f.read())
#for item in iplistcomplete:
#    print item

iplistnew = ipaddrFormatted.findall(f.read())
for item in iplistnew:
    print item[0]
f.close()

sample1 = "The ip address is: 192.168.0.30"
ipaddr2 = re.compile(r"(\d)+.(\d)+.(\d)+.(\d)+")
iplist2 = ipaddr2.search(sample1)
print iplist2.group()
