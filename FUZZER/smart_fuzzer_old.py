#!/usr/bin/python
# -*- coding: utf-8 -*-
import socket
import time
import binascii
import os
from libmich.formats import *
import gsm_um
import fuzzer
from adb import ADB
import itertools 

######################### SETTINGS ######################
# Default OpenBTS port
TESTCALL_PORT = 28670
adb = ADB();

########################### ADB #########################
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

########################### UDP #########################
# Send a restart to OpenBTS to establish a new channel
def establishNewChannel():
   restart = "RESTART";
   tcsock.sendto(restart, ('127.0.0.1', TESTCALL_PORT));
   # Log when the channel restars
   with open("log.txt", "a") as myfile:
   	myfile.write("\n\nCHANNEL RESTART \n \n");
   return

# Fuzzing loop
length = 64;
maxLength = 65;
while length <= maxLength:

	# Generate all permutations for this length
	perms = list(itertools.combinations_with_replacement(range(1, 3),length));
	print len(perms);
	#print perms;

	permutation = 0; 
	while permutation < len(perms):

		# Fuzzing counter
		print "Fuzzing: ", length;
		print perms[permutation];
		print "Faking MobileID with length: " , length;
		#packet = fuzzer.fuzzingLengthFields(1, 3, length, perms[permutation]);
		packet = fuzzer.fuzzingLengthFields(1, 5, length, perms[permutation]);
		
		# Make the packet readable
		printable = str(packet).encode("hex");
		print printable;

		# Decode printable hex to make it usable for L3Mobile.
		# Adding the \x for the bytes.
		l3msg = printable.decode('hex');
		print(l3msg);
		l3msg_input = repr(L3Mobile.parse_L3(l3msg));

		print l3msg_input + '\n';
		#Creating a socket"
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
				permutation = permutation - 1;
			# Log the input and output to a seperate file.
			with open("log.txt", "a") as myfile:
				myfile.write("INPUT " + str(length) + "\n" + l3msg_input + "\nOUTPUT " + str(length) + "\n" + parsed_reply + "\n\n");
		except socket.timeout:
			print "no reply received. potential crash?"
			# Create a new channel if a incorrect package has been send by the mobile device.
			establishNewChannel();
			permutation = permutation - 1;
			# Give OpenBTS time to setup a new channel
			time.sleep(6);
		permutation = permutation + 1;

	length = length + 1;

# Save the radio log from mobile device
saveRadioLog(adb, "" + str(time.strftime("%Y%m%d-%H%M%S")) + "_" + str(length) +"x_");
saveLogcat(adb, "" + str(time.strftime("%Y%m%d-%H%M%S")) + "_" + str(length) +"x_");
clearLogs();