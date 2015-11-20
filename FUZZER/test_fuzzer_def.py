#!/usr/bin/python
# -*- coding: utf-8 -*-
import gsm_um

def mobileFillID(packet, currentPermutation):
	# 00666666
	# 04666666
	length = len(currentPermutation);
	for i in range (0, length):
		currentByte = currentPermutation[i];

		currentHexByte = format(currentByte, '02x');
		hexdigit_1 = currentHexByte[0];
		hexdigit = currentHexByte[1];

		exec "packet.idDigit%s_1 = 0x%c " % (i + 2, hexdigit_1)
		exec "packet.idDigit%s = 0x%c " % (i + 2, hexdigit)

	return packet

def correctMobileID(p):
	#5220670380
	p.lengthMI=8;
	p.idDigit1=2;
	p.oddEven=1; p.typeOfId=1; 
	p.idDigit2_1=4; p.idDigit2=0; 
	p.idDigit3_1=4; p.idDigit3=0;
	p.idDigit4_1=2; p.idDigit4=5; 
	p.idDigit5_1=0; p.idDigit5=2;
	p.idDigit6_1=7; p.idDigit6=6;
	p.idDigit7_1=3; p.idDigit7=0;
	p.idDigit8_1=0; p.idDigit8=8;
	#p.idDigit9_1=2; p.idDigit9=2;
	return p

def fakeMobileID(p, length, currentPermutation):
	#length = len(currentPermutation);
	# if length>8:
	# 	p.lengthMI=8;
	# elif length>1:
	# 	p.lengtMI=length - 2;
	# else:
	p.lengtMI=8;

	# Settings
	p.idDigit1=2; p.oddEven=1; p.typeOfId=1; 

	# digits start with length of packet p
	p = mobileFillID(p, currentPermutation);

	return p

def correctLocalAreaID(a):
	a.mccDigit1=0x1; 
	a.mccDigit2=0x0; 
	a.mccDigit3=0x0; 

	a.mncDigit1=0x0;
	a.mncDigit2=0x1; 
	a.mncDigit3=0x0;

	a.lac1=0x03; a.lac2=0xe9;
	return a

# A function to fuzz fields with variable length
# First picked a few interesting fields and searched
# for functions that are using this field.
# Returns a packet of the given function with a
# Field of the given length.
def fuzzingLengthFields():


	p = gsm_um.tmsiReallocationCommand();
	p = correctMobileID(p);
	p = correctLocalAreaID(p)
	return p
