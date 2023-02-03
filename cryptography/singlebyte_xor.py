#!/usr/bin/python

import re
import sys
import os
from base64 import b64encode,b64decode,b16decode,b16encode
import argparse
from collections import Counter


################################################################################################################
#
#	Computes the frequency distribution of characters in a given plaintext file	
#
################################################################################################################

################################################################################################################
#	Computes the value of a canonical frequency distribution to use for comparison with the plaintext
#	A dictionary of the frequency distribution values for ascii letters is computed using a sample text
#	(Here, we have used a pdf of PoCGTFO; substitute a different value with the -pt command line param)
#
#
################################################################################################################
def get_freq(text, asciiletters):
	c = Counter()
	for ch in text:
		c[ch] += 1
	total_letter_counts=sum(c.values())
	letterfreq={letter: c[letter] / total_letter_counts for letter in asciiletters}
	return letterfreq

################################################################################################################
#	Computes the frequency distribution of characters in a provided ciphertext file by
#	dividing the character counts in c (Counter object c) / length_text and storing it in dictionary of
#	letter frequency distribution (freq)
#	Then creates an updated dictionary of most_common values, 
#	by comparing frequency distribution of all ascii letters in c with canonical frequency distribution
#	and taking the absolute value of that subtraction operation and storing it in newfreq (Counter object)
#	finally, creates the most_common dictionary using the Counter.most_common method
#	This selects the top 15 candidates of single-byte xor keys of length == length_ciphertext
#
################################################################################################################
#	computes the score of a candidate plaintext (decrypted from the given ciphertext) using single-byte 
#	xor key of length == len(plaintext)
#	The score is a measure of the number of ascii letters that appear in a decrypted_ciphertext string
#	A higher score corresponds to a higher number of ascii letters in a resultant plaintext,
#	Meaning that a decrypted ciphertext (new_pt) with a higher score is more likely to be a valid devryption
################################################################################################################

def score_ciphertext_decryption(new_pt, length_ciphertext, canonical_freq, asciiletters):
	#freq = {elem: float('inf') for elem in asciiletters}
	#c=Counter()
	#c=Counter((letter, new_pt.count(ord(letter))) for letter in asciiletters)
	
	#print("Original new_pt: {0}".format(new_pt))	
	#updated_new_pt=b16decode(new_pt, casefold=True)
	#print("Updated new_pt: {0}".format(updated_new_pt))	
	
	#freq = {elem: float('inf') for elem in updated_new_pt}
	freq = {elem: float('inf') for elem in new_pt}
	c=Counter(new_pt)
	print("Counter for chars in new_pt: {0}".format(c))	
	for char in new_pt:
		#if c[char] != float('inf'):
		#c[char] += 1
		#if char in ascii_letters:
		freq[char] = c[char] / length_ciphertext
	newfreq={key:abs(value - canonical_freq[key]) for key,value in freq.items() if value != float('inf')}
	#newfreq={key:abs(value - canonical_freq[key]) for key,value in freq.items()}
	score = sum(newfreq.values())
	print("Score for {0}: {1}".format(new_pt, score))
	return score

def freq_dist(pt, ciphertext, canonical_freq, asciiletters):
	length_ciphertext=len(ciphertext)
	#uppercase_ascii_letters=[chr(i) for i in range(65,91)]	
	#lowercase_ascii_letters=[chr(i) for i in range(97,123)]
	#print("lowercase ascii letters are: {0}".format(lowercase_ascii_letters))
	#print("uppercase ascii letters are: {0}".format(uppercase_ascii_letters))
	##freq = {chr(i): float('inf') for i in range(256)}

	freq = {elem: float('inf') for elem in asciiletters}
	c = Counter()
	for ch in pt:
		c[ch] += 1
	#freq=Counter({key:value for key,value in freq.items() if value != float('inf')})
	for char in c:
		if char in asciiletters:
			freq[char] = c[char] / length_ciphertext
	newfreq=Counter({key:abs(value - canonical_freq[key]) for key,value in freq.items() if value != float('inf')})
	print(f"Counts of chars in plainciphertext: {c}")
	print(f"frequency distribution for cipherciphertext: {freq}")
	print(f"Standard frequency distribution :{canonical_freq}")
	print(f"new frequency distribution of ciphertext: {newfreq}")
	#sorted_freq=sorted(freq.items(), sorted(freq.get), reverse=True)
	##don't need to use sorted() method, since a Counter object has most_common() method
	##Create ordered Counter dictionary object, ordered by most common character, for first 15 most common
	mostcommon_list=newfreq.most_common(30)
	mostcommon_freq={elem[0]:elem[1] for elem in mostcommon_list}	
	for key,val in mostcommon_freq.items():
		print("Most common element {0}: {1}".format(key,val))
	#for elem in mostcommon_freq:
	#	print("Most common element (index: {0}): {1}".format(elem[0], elem[1]))
	return mostcommon_freq		

def test_decryptions(decrypted_ciphertexts, len_ciphertext, canonical_freq, asciiletters):
	decryption_estimate=[]
	print("Decrypted ciphertext options: {0}".format(decrypted_ciphertexts))
	for key,val in decrypted_ciphertexts.items():
		score_ciphertext_decryption(bytes(val[0]), len_ciphertext, canonical_freq, asciiletters)
		#score_ciphertext_decryption(option, len_ciphertext, canonical_freq, asciiletters)
	
		

################################################################################################################
#
#	Takes as input 2 equal-length sized buffers (buf_1, buf_2) of hexadecimal strings
#	Performs a fixed xor operation on buf_1 and buf_2 and stores the result in fixed_xor_res
#
################################################################################################################


#def single_byte_xor(buf_1,buf_2):
def single_byte_xor(buf_1,freq_elems):
	print("type of freq elems: {0}".format(type(freq_elems)))
	print("Test of freq elems: {0}".format(freq_elems))
	buf_1=b16decode(bytes(buf_1), casefold=True)	
	fixed_xor_lambda=lambda x: x[0]^x[1]
	
	decryption_options={i: [] for i in range(256)}
	decrypted_ciphertext={i: [] for i in range(256)}
	#for i in range(len(buf_2.keys()):
	#for key,val in freq_elems:
		#decryption_options[i]=(bytes([(i)])*len(buf_1))
	for i in range(256):
	#for i,val in freq_elems.items():
	#	index=ord(i)
	#	if bytes(chr(i)) in freq_elems:
		decryption_options[i]=(bytes([(i)])*len(buf_1))
		print(f"Decryption candidate key {i}: {decryption_options[i]}")
		#decryption_options[index]=(bytes([(index)])*len(buf_1))
		#print(f"Decryption candidate key {i}: {decryption_options[index]}")
		#decrypted_ciphertext[index]=[bytes(fixed_xor_lambda((a,b),) for a,b in zip(decryption_options[index],buf_1))]
		#print(f"Decrypted ciphertext with key {i}: {decrypted_ciphertext[index]}")
		decrypted_ciphertext[i]=[bytes(fixed_xor_lambda((a,b),) for a,b in zip(decryption_options[i],buf_1))]
		print(f"Decrypted ciphertext with key {i}: {decrypted_ciphertext[i]}")

	#decrypted_ciphertext=[bytes(fixed_xor_lambda((a,b),) for i in range(256) for a,b in zip(bytes(decryption_options[i]),buf_1))] 
	return decrypted_ciphertext	
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
	buf_2=b16decode(buf_2, casefold=True)
	
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
	parser.add_argument('-pt', type=str, help='Filename of input file used for generating frequency counts of characters in plaintext')
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

def generate_plaintext_bytes(pt):
	pt_bytearr=bytearray()
	with open(pt, 'rb') as file:
		while (line := file.readline().rstrip()):
			pt_bytearr.append(line)
	return pt_bytearr

def generate_fixed_xor(ifile,ofile):
	with open(ifile, 'rb') as file:
		while (line := file.readline().rstrip()):
			print(line)
			fixed_xor_result=hex_fixed_xor(line,fixed_buf_2)
			print("Fixed xor result:", fixed_xor_result)	
			lambda_fixed_xor_result=hex_fixed_xor_lambda(line,fixed_buf_2)
			print("Fixed xor result with lambda:", lambda_fixed_xor_result)	

def encrypt_single_byte_xor(ifile, key_dict):
	singlebyte_xor_results={}
	with open(ifile, 'rb') as file:
		while (line := file.readline().rstrip()):
			print(line)
			singlebyte_xor_results=single_byte_xor(line,key_dict)
	return singlebyte_xor_results

################################################################################################################
#
################################################################################################################

if __name__ == '__main__':
	parser,args=setup_options()
	pt=args.pt
	ifile,ofile=b64_to_hex_preamble(parser,args)
	#generate_hex_rep(ifile,ofile)
	#generate_fixed_xor(ifile,ofile)
	text=""
	with open(pt, 'r') as pt:
		text=pt.read()
	
	#plaintext_bytes=generate_plaintext_bytes(pt)

	length_text=len(text)
	uppercase_ascii=[chr(i) for i in range(65,91)]	
	lowercase_ascii=[chr(i) for i in range(97,123)]
	print("lowercase ascii letters are: {0}".format(lowercase_ascii))
	print("uppercase ascii letters are: {0}".format(uppercase_ascii))
	asciiletters=uppercase_ascii + lowercase_ascii
	canonical_freq=get_freq(text, asciiletters)
	print("Canonical frequency: {0}".format(canonical_freq))
	

	len_ciphertext=len(text)	

	#mostcommonfreq = freq_dist(plaintext_bytes)
	mostcommonfreq = freq_dist(ofile, text, canonical_freq, asciiletters)
	#print("Sorted frequency distribution for item: {1}".format(freq_dist[i]) 
	
	#encrypt_single_byte_xor(ifile,ofile)
	decrypted_ciphertext=encrypt_single_byte_xor(ofile,mostcommonfreq)
	print("Decrypted ciphertexts: {0}".format(decrypted_ciphertext))
	test_decryptions(decrypted_ciphertext, len_ciphertext, canonical_freq, asciiletters)
