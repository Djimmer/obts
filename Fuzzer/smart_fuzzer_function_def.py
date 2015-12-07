#!/usr/bin/python
# -*- coding: utf-8 -*-
import gsm_um
import random


########################################### CORRECT FUNCTIONS #########################################
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

def correctLocalAreaID(p):
	p.mccDigit1=0x1; 
	p.mccDigit2=0x0; 
	p.mccDigit3=0x0; 

	p.mncDigit1=0x0;
	p.mncDigit2=0x1; 
	p.mncDigit3=0x0;

	p.lac1=0x03; p.lac2=0xe9;
	return p

########################################## FUZZ FUNCTIONS #############################################
def mobileFillID(packet, permutation):
	length = len(permutation);
	current_packet_digit = 2;

	for i in range (0, length, 2):

		currentHexDigit1 = permutation[i];
		currentHexDigit2 = permutation[i+1];

		exec "packet.idDigit%s_1 = 0x%c " % (current_packet_digit, currentHexDigit1)
		exec "packet.idDigit%s = 0x%c " % (current_packet_digit, currentHexDigit2)
		
		current_packet_digit = current_packet_digit + 1;
	return packet

def fuzzMobileId(p, permutation):
	
	p.lengthMI=random.randint(1, 100);
	p.idDigit1=random.randint(1, 3);
	p.oddEven=random.randint(1, 2); 
	p.typeOfId=random.randint(1, 5);

	# digits start with length of packet p
	p = mobileFillID(p, permutation);

	return p

########################################### FIELD SELECTOR ############################################
def fuzzingLengthFields(field, function, permutation):
	# Default backup value
	p = '\x05\x18\x01';

	if(field == 1):
		if(function == 1):
			p = gsm_um.tmsiReallocationCommand();

			# Use protocol knowledge to fuzz specific fields 
			p = fuzzMobileId(p, permutation);

			p = correctLocalAreaID(p);
			return p
	
	return p