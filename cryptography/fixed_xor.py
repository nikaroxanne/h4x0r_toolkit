#!/usr/bin/python

import re
import sys
import os
from base64 import b64encode,b64decode,b16decode,b16encode
import argparse


################################################################################################################
#
#	Takes as input 2 equal-length sized buffers (buf_1, buf_2) of hexadecimal strings
#	Performs a fixed xor operation on buf_1 and buf_2 and stores the result in fixed_xor_res
#
################################################################################################################

fixed_buf_1=b""
fixed_buf_2=b'686974207468652062756c6c277320657965'


def hex_fixed_xor(buf_1,buf_2):
	#fixed_xor_res = [0]*min(len(buf_1), len(buf_2))
	#print(fixed_xor_res)
	#buf_1=bytes.fromhex(buf_1)	
	buf_1=b16decode(buf_1, casefold=True)	
	#buf_2=bytes(buf_2)	
	#print(f"unhexlified string: {buf_1}")
	
	for elem_a,elem_b in zip(buf_1,buf_2):
		print(elem_a, elem_b)
	
	fixed_xor_res=[(lambda x,y: bytes(x^y))(byte1,byte2) for byte1,byte2 in zip(buf_1,buf_2)]
	
	print(fixed_xor_res)

	#buf_1=b16decode(buf_1, casefold=True)
	buf_2=b16decode(buf_2, casefold=True)
	#print(f"unhexlified string: {buf_1}")
	print(f"unhexlified string: {buf_2}")
	
	#fixed_xor_res_2=(lambda x,y:bytes(x^y)(byte1,byte2) for byte1,byte2 in zip(buf_1,buf_2))
	#print("fixed_xor_res_2:",fixed_xor_res_2)
	
	##fixed_xor_res_3=bytes((lambda x,y:(x^y)(byte1,byte2)) for byte1,byte2 in zip(buf_1,buf_2))
	##print("fixed_xor_res_3:",fixed_xor_res_3)



#	fixed_xor_lambda=lambda x,y: (x^y)
	fixed_xor_lambda=lambda x: x[0]^x[1]
	
	fixed_xor_res_4=bytes(fixed_xor_lambda((a,b),) for a,b in zip(buf_1,buf_2))	
	print("fixed_xor_res_4:",fixed_xor_res_4)
	#fixed_xor_res_5=bytes(((elem[0]^elem[1]),) for elem in zip(buf_1,buf_2))	
	fixed_xor_res_5=bytes(a ^ b for a,b in zip(buf_1,buf_2))	
	print("fixed_xor_res_5:",fixed_xor_res_5)
	print(f"fixed_xor_res_5: {str(fixed_xor_res_5)}")
#	print("final_fixed_xor_res:",final_fixed_xor)

	#b64_s=b64encode(hex_s)
	#fixed_xor_res = hex(hex_s ^ buf_2)
	#print(f"Fixed XOR result string: {fixed_xor_res}")



################################################################################################################
#
#       Convert base64 string to hex
#	Operates on raw bytes, not encoded string
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
	
################################################################################################################
#
#           Argparse template - more detailed/fine-grained command line controls
#
################################################################################################################

def setup_options():
	parser = argparse.ArgumentParser(description='Generate bytearray of hex representation for given base64-encoded string (converted to bytes')
	parser.add_argument('-infile', type=str, help='Filename of file containing base64-encoded string to convert; if file contains > 1 line, lines are read and converted sequentially')
	parser.add_argument('-outfile', type=str, help='Filename of output file containing hex representation of base64-encoded string(s) from input file')
	args = parser.parse_args()
	return parser, args

def b64_to_hex_preamble(parser, args):
	ifile=args.infile
	ofile=args.outfile
	print("args:", args)
	print("ifile:", ifile)
	print("ofile:", ofile)
	return ifile,ofile

def generate_hex_rep(ifile,ofile):
	with open(ifile, 'rb') as file:
		while (line := file.readline().rstrip()):
			print(line)
			b64_s=hex_to_b64(line)
			print("b64s:", b64_s)	

def generate_fixed_xor(ifile,ofile):
	with open(ifile, 'rb') as file:
		while (line := file.readline().rstrip()):
			print(line)
			fixed_xor_result=hex_fixed_xor(line,fixed_buf_2)
			print("Fixed xor result:", fixed_xor_result)	

################################################################################################################
#
################################################################################################################

if __name__ == '__main__':
	parser,args=setup_options()
	ifile,ofile=b64_to_hex_preamble(parser,args)
	#generate_hex_rep(ifile,ofile)
	generate_fixed_xor(ifile,ofile)
		
