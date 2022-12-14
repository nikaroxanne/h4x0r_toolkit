#!/usr/bin/python

import re
import sys
import os
from base64 import b64encode,b64decode,b16decode,b16encode
import argparse

##use python2 not python3 for ease of generating strings for payloads 

################################################################################################################
#       Convert base64 string to hex
#	Operates on raw bytes, not encoded string
#
#
################################################################################################################


def b64_to_hex(b64s):
	b64bytearr=bytes(b64s)
	hex_arr=str(b64decode(b64bytearr))
	
	print("Base64 encoded string: \n int: {0:d};  hex: {0:X};  oct: {0:o};  bin: {0:b}".format(hex_arr))
	return hex_arr


#	hex_s=''.join(format(ord(c) for c in s[:-2])

#	b64_s=b64encode(bytes.fromhex(hex_arr)).decode()

def hex_to_b64(hex_bytes):
	hex_s=b16decode(hex_bytes, casefold=True)
	print(f"unhexlified string: {hex_s}")
	b64_s=b64encode(hex_s)
	print(f"base64 string: {b64_s}")
	return b64_s
	
#def hex_to_b64s(hex_arr):
#	print(hex_s)
#	hex_arr=bytes.fromhex(str(hex_s))
	hex_s=''.join(format(chr(c)) for c in hex_arr[:-2])
	print(hex_s)
	#hex_s_formatted=hex_arr.decode()
	#print(hex_s_formatted, hex_s_formatted.rstrip('\n'))	
	#b64s=str(b64encode(hex_arr))
	#b64_bytes=b64encode(hex_arr)
	#hex_arr_formatted=bytes(hex_s_formatted.hex)
	#b64_bytes=b64encode(hex_arr_formatted)
	#print("Base64 encoded string: \n {0} ".format(b64s, 'x'))
	#b64_bytes=b64encode(bytes(hex_s))

	hex_arr_final=hex_arr.rstrip()
	b64_bytes=b64encode(hex_arr_final)
	print("Base64 encoded string: \n", b64_bytes)
	b64_s=b64_bytes.decode()
	print("Base64 encoded string: \n", b64_s)
	return b64_s

#	#b64s_formatted='{0}'.format(b64_bytes, 'x')
#	print("Base64 encoded string: \n", b64s_formatted)
#	return b64s_formatted

################################################################################################################
#           Argparse template - more detailed/fine-grained command line controls
#
################################################################################################################

def setup_options():
	parser = argparse.ArgumentParser(description='Generate bytearray of hex representation for given base64-encoded string (converted to bytes')
	parser.add_argument('-infile', type=str, help='Filename of file containing base64-encoded string to convert; if file contains > 1 line, lines are read and converted sequentially')
	parser.add_argument('-outfile', type=str, help='Filename of output file containing hex representation of base64-encoded string(s) from input file')

#    parser.add_argument('-gdb', nargs='?', type=bool, default=False,  help='Run the program with gdb for debugging')
#parser.add_argument('-outfile', type=str, help='Filename of output file containing hex representation of base64-encoded string(s) from input file')
#    subparsers = parser.add_subparsers()
#    remote_subparser= subparsers.add_parser('remote', help='Send the exploit to the remote target at [IP] [PORT]')
#    remote_subparser.add_argument('IP', type=str,  help='IP Address of remote target')
#    remote_subparser.add_argument('PORT', type=int,  help='Port of remote target')
#    #subparsers = parser.add_subparsers()
#    #parser.add_argument('-write-payloads', action="store_true",  help='Option to retrieve file or files from generated list of all files on target device')
#    #parser.add_argument('-IP', type=int,  help='IP Address of remote target')
#    #parser.add_argument('-PORT', type=int,  help='Port of remote target')
#    #remote_args = remote_subparser.parse_args()
	args = parser.parse_args()
	return parser, args

def b64_to_hex_preamble(parser, args):
	ifile=args.infile
	ofile=args.outfile
	print("args:", args)
	print("ifile:", ifile)
	print("ofile:", ofile)
	return ifile,ofile
#    #payload_num=int(args.payloads)
#    #payload_data = '{"command":' + cmd + '}'

def generate_hex_rep(ifile,ofile):
	with open(ifile, 'rb') as file:
		while (line := file.readline().rstrip()):
			print(line)
			b64_s=hex_to_b64(line)
			print("b64s:", b64_s)	


################################################################################################################
#
################################################################################################################

if __name__ == '__main__':
	parser,args=setup_options()
	ifile,ofile=b64_to_hex_preamble(parser,args)
	generate_hex_rep(ifile,ofile)
		
