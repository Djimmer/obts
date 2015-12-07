#!/usr/bin/python
# -*- coding: utf-8 -*-
import gsm_um

def mobileFillID(packet, currentPermutation):
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
def fuzzingLengthFields(field, function):

	######## 1 MobileID() ########
	# 1 imsiDetachIndication !!
	# 2 locationUpdatingRequest !!
	# 3 tmsiReallocationCommand !!
	# 4 configurationChangeAcknowledge
	# 5 notificationResponse
	# 6 pagingRequestType1
	# 7 pagingRequestType2
	# 8 pagingResponse
	# 9 talkerIndication
	# 10 cmReestablishmentRequest
	# 11 cmServiceRequest
	# 12 identityResponse
	# 13 ptmsiReallocationCommand
	p = '\x05\x18\x01';
	if(field == 1):
		if(function == 1):
			p = gsm_um.imsiDetachIndication();
			p = fakeMobileID(p, length, currentPermutation);
			return p
		elif(function == 2):
			# not implemented
			p = gsm_um.locationUpdatingRequest();
			# c = LocationUpdatingTypeAndCiphKeySeqNr()

			# e = LocalAreaId()
			p = correctLocalAreaID(p);
			# f = MobileStationClassmark1()

			# g = MobileId()
			p = fakeMobileID(p, length, currentPermutation);
			return p
		elif(function == 3):
			# Length check
			p = gsm_um.tmsiReallocationCommand();
			# 051a01001003e9082a3377777733777777
			p = fakeMobileID(p, length, currentPermutation);
			#p = correctMobileID(p);
			# 051a01001003e9082940402502763008
			#p = correctMobileID(p);
			p = correctLocalAreaID(p);
			return p
	# 	# For testing, works fine
	# 	elif(function == 4):
	# 		p = gsm_um.identityRequestMM();
	# 		return p
		elif(function == 5):
			# Call confirmed, but no ringing
			p = gsm_um.setupMobileOriginated();
			p = '\x05\x18';
			return p
		elif(function == 6):
			p = gsm_um.connectAcknowledge();
			return p
	# 	elif(function == 7):
	# 		p = gsm_um.disconnectNetToMs();
	# 		return p
	# 	elif(function == 8):
	# 		#61 - RR-Cause (reason of event) = Message type non-existent or not implemented"
	# 		p = gsm_um.configurationChangeAcknowledge();
	# 		p = fakeMobileID(p, length);
	# 		return p
	# 	elif(function == 9):
	# 		#61 - RR-Cause (reason of event) = Message type non-existent or not implemented"
	# 		p = gsm_um.notificationResponse();
	# 		p = fakeMobileID(p, length);
	# 		return p
	# 	elif(function == 10):
	# 		#61 - RR-Cause (reason of event) = Message type non-existent or not implemented"
	# 		p = gsm_um.pagingRequestType1();
	# 		p = fakeMobileID(p, length);
	# 		p.l2pLength =0x15;
	# 		return p
	# 	elif(function == 11):
	# 		#61 - RR-Cause (reason of event) = Message type non-existent or not implemented"
	# 		p = gsm_um.pagingRequestType2();
	# 		p = fakeMobileID(p, length);
	# 		return p
	# 	elif(function == 12):
	# 		#61 - RR-Cause (reason of event) = Message type non-existent or not implemented"
	# 		p = gsm_um.pagingResponse();
	# 		p = fakeMobileID(p, length);
	# 		return p
	# 	elif(function == 13):
	# 		#61 - RR-Cause (reason of event) = Message type non-existent or not implemented"
	# 		p = gsm_um.talkerIndication();
	# 		p = fakeMobileID(p, length);
	# 		return p
	# 	elif(function == 14):
	# 		#Not implemented"
	# 		p = gsm_um.cmReestablishmentRequest();
	# 		p = fakeMobileID(p, length);
	# 		return p
	# 	elif(function == 15):
	# 		#Not implemented"
	# 		p = gsm_um.locationUpdatingAccept();
	# 		p = correctLocalAreaID(p);
	# 		#p = fakeMobileID(p, length);
	# 		return p
	# 	elif(function == 16):
	# 		#Not implemented"
	# 		p = gsm_um.locationUpdatingReject();
	# 		return p
	# ######## 2 NetworkName() ########
	#elif(field == 2):
		# 1 mmInformation
		# 2 gmmInformation
	######## 3 ChannelDescription() ########
	#elif(field == 3):
		# 1 systemInformationType1
		# 2 partialRelease
		# 3 immediateAssignmentExtended
		# 4 immediateAssignment
		# 5 frequencyRedefinition
		# 6 additionalAssignment

	######## 4 UserUser() ########
	#elif(field == 4):
		# 1 alertingNetToMs
		# 2 connectNetToMs !!
		# 3 disconnectNetToMs
		# 4 progress
		# 5 releaseNetToMs !!
		# 6 userInformation !!
	else:
		return '\x05\x18\x01'
	
	return p