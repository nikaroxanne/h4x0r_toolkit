#!/usr/bin/python

import re
import sys
import os
from base64 import b64encode,b64decode,b16decode,b16encode
import argparse


################################################################################################################
#
#       Convert base64 string to hex
#	Operates on raw bytes, not encoded string
#
#
################################################################################################################


def b64_to_hex(b64s):
	#b64bytearr=bytes(b64s)
	hex_arr=b64decode(b64s)
	print(f"hex arr: {hex_arr}")
	hex_s=b16encode(hex_arr)
	print(f"hex string: {hex_s}")
	return hex_s



def hex_to_b64(hex_bytes):
	hex_s=b16decode(hex_bytes, casefold=True)
	print(f"unhexlified string: {hex_s}")
	b64_s=b64encode(hex_s)
	print(f"base64 string: {b64_s}")
	return b64_s
	
################################################################################################################
#           Argparse template - more detailed/fine-grained command line controls
#
################################################################################################################

def setup_options():
	parser = argparse.ArgumentParser(description='Generate base-64 encoded string from given hex string (read as bytes)')
	parser.add_argument('-infile', type=str, help='Filename of file containing base64-encoded string to convert; if file contains > 1 line, lines are read and converted sequentially')
	parser.add_argument('-outfile', type=str, help='Filename of output file containing hex representation of base64-encoded string(s) from input file')
	args = parser.parse_args()
	return parser, args

def b64_to_hex_preamble(parser, args):
	ifile=args.infile
	ofile=args.outfile
	return ifile,ofile

def generate_hex_rep(ifile,ofile):
	with open(ifile, 'rb') as file:
		while (line := file.readline().rstrip()):
			print(line)
			b64_s=hex_to_b64(line)
			print("b64s:", b64_s)	
			hex_s=b64_to_hex(b64_s)
			print("hex_s:", hex_s)	


################################################################################################################
#
################################################################################################################

if __name__ == '__main__':
	parser,args=setup_options()
	ifile,ofile=b64_to_hex_preamble(parser,args)
	generate_hex_rep(ifile,ofile)
		
