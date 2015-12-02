#!/usr/bin/python
# -*- coding: utf-8 -*-
import socket
import time
import binascii
import os
from libmich.formats import *
import gsm_um
import test_fuzzer_def as fuzzer
from adb import ADB
import itertools
from math import factorial

############################################### SETTINGS #############################################
# Default OpenBTS port
TESTCALL_PORT = 28670;
adb = ADB();

# Fill in current mobile device
# device = "UNKOWN";
#device = "SAMSUNG";
# device = "BLACKPHONE";
#device = "NEXUS";
#device = "IPHONE";
#device = "NOKIA";
device = "HUAWEI";

# Log file location
log_packets_title = "logs/logs_packets/smarter_fuzzer/" + device + "_log_" + str(time.strftime("%Y%m%d-%H%M%S")) + ".txt";

# Turn on/off prints
verbose = True;
# Turn on/off adb logs
adb_logging = False;

# Creat socket
tcsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tcsock.settimeout(2)

ocsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ocsock.settimeout(2)

################################################# LOG ################################################
def saveRadioLog(adb,title):
	adb.logcatRadio(title);
	return

def saveLogcat(adb,title):
	adb.logcat(title);
	return

def clearLogs():
	adb.logcatRadioClear();
	adb.logcatClear();
	return

def log_adb(adb, packet_field, packet_function, maxLength, maxRun):
	log_directory = "logs/logs_adb/smarter";
	log_title = device + "_field_" + str(packet_field) 
	+ "_function_" + str(packet_function) 
	+ str(time.strftime("%Y%m%d-%H%M%S")) 
	+ "_length_" + str(maxLength) 
	+ "_runs_" + str(maxRun) +"x_";
	
	saveRadioLog(adb, log_directory + log_title);
	saveLogcat(adb, log_directory + log_title);
	clearLogs();

def log_packets(length, lengthField, id, field, function, packet, parsed_packet, reply, parsed_reply):
	with open(log_packets_title, "a") as myfile:
		myfile.write("-------------------------------------------------------------------------------\n"
			+ "INPUT" + '\n'
			+ "Field: "       + str(field) + "\n" 
			+ "Function: "    + str(function) + "\n" 
			+ "Length: "      + str(length) + "\n" 
			+ "LengthField: " + str(lengthField) + "\n" 
			+ "id: "          + str(id) + "\n" 
			+ "Packet: " + str(packet).encode("hex") + "\n" 
			+ parsed_packet + "\n\n"
			+ "OUTPUT" + "\n"
			+ str(reply).encode("hex") + "\n"
			+ parsed_reply + "\n\n");

def log_restart():
	with open(log_packets_title, "a") as myfile:
		myfile.write("\n\nCHANNEL RESTART \n \n");

############################################## CHANNEL ###############################################
# Send a restart to OpenBTS to establish a new channel
def establishNewChannel():
   restart = "RESTART";
   print("Channel restart: Establishing a new channel, this may take a second.");
   tcsock.sendto(restart, ('127.0.0.1', TESTCALL_PORT));
   # Log when the channel restars
   log_restart();
   # Wait for OpenBTS to confirm new channel.
   try:
   	reply = tcsock.recv(1024)
   except:
   	print "Could not establish a new channel.";
   	return False;
   
   print reply;
   print "New channel established, fuzzing will continue.";
   time.sleep(2);
   return True;

def send(tcsock, packet):
		try:
			tcsock.sendto(packet, ('127.0.0.1', TESTCALL_PORT))
			reply = tcsock.recv(1024)
		except socket.timeout:
			print "socket.timeout: Mobile device is not responding";
			return False

		#Libmich parses the output
		parsed_reply = repr(L3Mobile.parse_L3(reply));

		# Can the reply be parsed by Libmich?
		if "ERROR" not in parsed_reply:
			print "Received packet: ", str(reply).encode("hex") + "\n";
			print "GSM_UM interpetation: " + '\n' + parsed_reply + "\n\n";
		# Create a new channel if a incorrect package has been send by the mobile device.
		else:
			return False

		return reply

def ping():
	try:
		tcsock.sendto('\x05\x18\x01', ('127.0.0.1', TESTCALL_PORT));
		reply = tcsock.recv(1024);
	except socket.timeout:
		return False;


	parsed_reply = repr(L3Mobile.parse_L3(reply));

	if "IDENTITY RESPONSE" not in parsed_reply:
		print("Channel is still alive, go to next input.");
		return True;

	return False;
############################################### UTILS ################################################
def printPacket(packet):
		print('------------------------------- INPUT  -------------------------------' + '\n');
		# Make the packet readable
		printable = str(packet).encode("hex");
		print "Current complete packet: " + printable + '\n';

		# Decode printable hex to make it usable for L3Mobile.
		# Adding the \x for the bytes.
		l3msg = printable.decode('hex');
		l3msg_input = repr(L3Mobile.parse_L3(l3msg));

		print "GSM_UM interpetation: \n " + l3msg_input + '\n\n';
		print "------------------------------- OUTPUT -------------------------------" + '\n';


############################################ TEST FUZZER ############################################
packet = fuzzer.fuzzingLengthFields();
id50 = "00000000000000000000000000000000000000000000000000";
id50 = "ffffffffffffffffffffffffffffffffffffffffffffffffff";
packet = "051a02440003e9ff29" + id50 + id50 + id50 + id50 + "ffffff";


packet = "0330"# + id50 + id50 + id50;



#if(verbose):
#	printPacket(packet);

# Send packet to the mobile device.

#packet = str(packet);

#packet = '\x05\x1a\x02';
#id50 = "00818181818181818181818181818181818181810000000000";

# 254
# 255
#051a02440003e9fe2940806066020639818181818181818181818181818181818181
#051a02440003e9ff2940806066020639818181818181818181818181818181818181
#051a02440003e9ff2940806066020639818181818181818181818181818181818181
#packet = str(packet).encode("hex");
#result = send(tcsock, packet);


# packet = gsm_um.setupMobileOriginated();
# gsm_um.sendum(packet);
# printPacket(packet);
# time.sleep(3);

# #RECEIVE CALL CONFIRMED


# packet = "\x06\x2e\x11\x11\x11\x11"
# #packet = str(packet).encode("hex");
# # packet = gsm_um.assignmentCommand();
# gsm_um.sendum(packet);
# printPacket(packet);
# time.sleep(2);

# # RECEIVE ASSIGNMENT COMPLETE


# # packet = gsm_um.alertingNetToMs();
# # gsm_um.sendum(packet);
# # printPacket(packet);
# # time.sleep(2);


# # packet = gsm_um.progress();
# # gsm_um.sendum(packet);
# # printPacket(packet);
# # time.sleep(2);


# packet = gsm_um.connectAcknowledge();
# printPacket(packet);
# gsm_um.sendum(packet);


packet = gsm_um.authenticationAndCipheringRequest("12345678");
packet = gsm_um.authenticationRequest();
packet = '\x05\x12\x03';
packetRAND = '\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x11';

#type - #length - #value
packetAUTNtype = '\x14';
packetAUTN10 = '\xaa\xff\xaa\xff\xaa\xff\xaa\xff\xaa\xff';

#packetAUTNLength = '\x21'; # = 33
packetAUTNLength = '\x10'; # = 18 
# packetAUTNLength = '\x41'; # = 65
# packetAUTN = packetAUTNtype + packetAUTNLength + packetAUTN10 + packetAUTN10 + packetAUTN10 + packetAUTN10 + packetAUTN10 + packetAUTN10 + '\xff\xff\xff\xff\xff';
packetAUTN = packetAUTNtype + packetAUTNLength + packetAUTN10 + '\xaa\xff\xaa\xaa\xff\xaa';
packet = packet + packetRAND + packetAUTN;
printPacket(packet);
gsm_um.sendum(packet);


#packet = str(packet).encode("hex");
#result = send(tcsock, packet);
