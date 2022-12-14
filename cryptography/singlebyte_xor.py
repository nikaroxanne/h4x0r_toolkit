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

def single_byte_xor(buf_1,buf_2):
	buf_1=b16decode(bytes(buf_1), casefold=True)	
#	buf_1=bytes(buf_1)
	fixed_xor_lambda=lambda x: x[0]^x[1]
#	decrypted_ciphertext=[bytes(fixed_xor_lambda(bytes((chr(i)*len(buf_1))),buf_1),) for i in range(0,256)] 
#	print(decrypted_ciphertext)
	

#	decryption_options=[b16encode(b'(chr(i)*len(buf_1))') for i in range(0,256)] 
#	decryption_options=[b16encode(chr(i)*len(buf_1)) for i in range(256)] 
#	decryption_options=[bytes[(i)]*len(buf_1) for i in range(256)] 
#	decryption_options=[0]*len(buf_1)
	decryption_options={i: [] for i in range(256)}
	decrypted_ciphertext={i: [] for i in range(256)}
	for i in range(256):
		decryption_options[i]=(bytes([(i)])*len(buf_1))
		print(f"Decryption candidate key {i}: {decryption_options[i]}")
		decrypted_ciphertext[i]=[bytes(fixed_xor_lambda((a,b),) for a,b in zip(decryption_options[i],buf_1))]
		print(f"Decrypted ciphertext with key {i}: {decrypted_ciphertext[i]}")

#	print("Decryption candidate key {i}: {decryption_options[i]})
	print(len(decryption_options))

	#decrypted_ciphertext=[bytes(fixed_xor_lambda((a,b),) for i in range(256) for a,b in zip(bytes(decryption_options[i]),buf_1))] 
#	decrypted_ciphertext={x: bytes(fixed_xor_lambda((a,b),) for x in range(256) for a,b in zip(decryption_options[x],buf_1))}
#	decrypted_ciphertext=[bytes(fixed_xor_lambda((a,b),) for x in range(256) for a,b in zip(decryption_options[x],buf_1))]
#	decrypted_ciphertext=[fixed_xor_lambda((a,b),) for i in range(256) for a,b in zip(decryption_options[i],buf_1)] 
#	decrypted_ciphertext=[fixed_xor_lambda((a,b),) for i in range(256) for a,b in zip(decryption_options[i],buf_1)] 
#	for j in range(256):
#		print(f"Decryption option: {decrypted_ciphertext[j]}\n")
		
	#return lambda_xor_res



################################################################################################################
#
#	Takes as input 2 equal-length sized buffers (buf_1, buf_2) of hexadecimal strings
#	Performs a fixed xor operation on buf_1 and buf_2 and stores the result in fixed_xor_res
#
################################################################################################################

fixed_buf_1=b""
fixed_buf_2=b'686974207468652062756c6c277320657965'

def hex_fixed_xor_lambda(buf_1,buf_2):
	buf_1=b16decode(buf_1, casefold=True)	
#	print(f"unhexlified string 1: {buf_1}")	
	buf_2=b16decode(buf_2, casefold=True)
#	print(f"unhexlified string 2: {buf_2}")
	
	fixed_xor_lambda=lambda x: x[0]^x[1]

	##two versions of the same functionality; this one using a lambda
	lambda_xor_res=bytes(fixed_xor_lambda((a,b),) for a,b in zip(buf_1,buf_2))	
	print("xor_res_lambda:", lambda_xor_res)
	return lambda_xor_res


def hex_fixed_xor(buf_1,buf_2):
	buf_1=b16decode(buf_1, casefold=True)	
#	print(f"unhexlified string 1: {buf_1}")
	
	buf_2=b16decode(buf_2, casefold=True)
#	print(f"unhexlified string 2: {buf_2}")
	
	##two versions of the same functionality; this one not using a lambdaa
	xor_res=bytes(a ^ b for a,b in zip(buf_1,buf_2))	
	print("xor_res:",xor_res)
	
	return xor_res


################################################################################################################
#
#       Convert base64 string to hex
#	Operates on raw bytes, not encoded string
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
			lambda_fixed_xor_result=hex_fixed_xor_lambda(line,fixed_buf_2)
			print("Fixed xor result with lambda:", lambda_fixed_xor_result)	

def encrypt_single_byte_xor(ifile,ofile):
	with open(ifile, 'rb') as file:
		while (line := file.readline().rstrip()):
			print(line)
			single_byte_xor_res=single_byte_xor(line,fixed_buf_2)

################################################################################################################
#
################################################################################################################

if __name__ == '__main__':
	parser,args=setup_options()
	ifile,ofile=b64_to_hex_preamble(parser,args)
	#generate_hex_rep(ifile,ofile)
	#generate_fixed_xor(ifile,ofile)
	encrypt_single_byte_xor(ifile,ofile)
		
