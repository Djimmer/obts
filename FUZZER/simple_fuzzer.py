#!/usr/bin/python
# -*- coding: utf-8 -*-
import socket
import time
import binascii
import os
from libmich.formats import *
import gsm_um
import simple_fuzzer_def
from adb import ADB
import itertools
from math import factorial

############################################### SETTINGS #############################################
# Default OpenBTS port
TESTCALL_PORT = 28670;
adb = ADB();
log_packets_title = "logs/logs_packets/log_" + str(time.strftime("%Y%m%d-%H%M%S")) + ".txt";

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

def log(adb, packet_field, packet_function, maxLength, maxRun):
	saveRadioLog(adb, "logs/logs_adb/" + "field_" + str(packet_field) + "_function_" + str(packet_function) + str(time.strftime("%Y%m%d-%H%M%S")) + "_length_" + str(maxLength) + "_runs_" + str(maxRun) +"x_");
	saveLogcat(adb, "logs/logs_adb/" + "field_" + str(packet_field) + "_function_" + str(packet_function) + str(time.strftime("%Y%m%d-%H%M%S")) + "_length_" + str(maxLength) + "_runs_" + str(maxRun) +"x_");
	clearLogs();

############################################## CHANNEL ###############################################
# Send a restart to OpenBTS to establish a new channel
def establishNewChannel():
   restart = "RESTART";
   tcsock.sendto(restart, ('127.0.0.1', TESTCALL_PORT));
   # Log when the channel restars
   with open(log_packets_title, "a") as myfile:
   	myfile.write("\n\nCHANNEL RESTART \n \n");
   return

def send(packet, counter):
		tcsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		tcsock.settimeout(6)
		try:
			#Send message and wait for a reply
			tcsock.sendto(packet, ('127.0.0.1', TESTCALL_PORT))
			reply = tcsock.recv(1024)

			#Libmich tries to parse the received packet
			parsed_reply = repr(L3Mobile.parse_L3(reply));
			
			# Can the reply be parsed by Libmich?
			if "ERROR" not in parsed_reply:
				print "reply received: ", parsed_reply + "\n";
			# Create a new channel if a incorrect package has been send by the mobile device.
			else:
				establishNewChannel();
				# Give OpenBTS time to setup a new channel
				time.sleep(6);
				return false
			# Log the input and output to a seperate file.
			with open(log_packets_title, "a") as myfile:
				myfile.write("INPUT " + str(counter) + "\n" + packet + "\nOUTPUT " + str(counter) + "\n" + parsed_reply + "\n\n");
		except socket.timeout:
			print "no reply received. potential crash?"
			# Create a new channel if a incorrect package has been send by the mobile device.
			establishNewChannel();
			return false
			# Give OpenBTS time to setup a new channel
			time.sleep(6);
		return True

############################################### UTILS ################################################
def printPacket(packet, length, permsCurrent, permutation, prefix):
		print('\n\n' + '------------------------- NEW PERMUTATION -------------------------' + '\n');
		print('Current permutation: ' + str(permsCurrent));
		print('Current hexvalue: ' + permutation.encode("hex"));
		print('Current function prefix: ' + str(prefix).encode("hex") + '\n');
		# Fuzzing counter
		print "Current fuzzing length: ", length;

		# Make the packet readable
		printable = str(packet).encode("hex");
		print "Current complete packet: " + printable + '\n';

		# Decode printable hex to make it usable for L3Mobile.
		# Adding the \x for the bytes.
		l3msg = printable.decode('hex');
		l3msg_input = repr(L3Mobile.parse_L3(l3msg));

		print "GSM_UM interpetation: \n " + l3msg_input + '\n\n';
		print "------------------------- END PERMUTATION -------------------------";

def convert(int_value):
   encoded = format(int_value, '02x')

   length = len(encoded)
   encoded = encoded.zfill(length+length%2)

   return encoded.decode('hex')  

########################################### SIMPLE FUZZER ############################################
# Fuzzer specific settings

# From current length till end
currentLength = 0;
maxLength = 2;

# Select specific field and function
# Detailed list in simple_fuzzer_def.py
packet_field = 1;
packet_function = 5;

# Turn on/off prints
verbose = True;

while currentLength <= maxLength:

	# Get and store the magic bytes for a specific function
	packet = simple_fuzzer_def.fuzzingLengthFields(packet_field, packet_function);
	prefix = packet;

	# Limits for permutations
	permsCurrent = 0;
	permsEnd = 16 ** currentLength;

	if not verbose:
		print('Current length: ' + str(currentLength));

	while permsCurrent < permsEnd:
		# Convert permutation to hexadecimal
		permutation = convert(permsCurrent);
		# Create the packet using the prefix and converted permutation
		packet = prefix + permutation;
		if(verbose):
			printPacket(packet, currentLength, permsCurrent, permutation, prefix);

		# Send packet to the mobile device.
		result = send(packet, permsCurrent);

		if(result):
			permsCurrent = permsCurrent + 1;
		# else:
		# 	# do some error handling / restart channel.
		# 	permsCurrent = permsCurrent;

	# Hexadecimal value, so to keep length consistent with actualoutput, + 2 is added.
	currentLength = currentLength + 2;

# Save the radio log from mobile device
#log(adb, packet_field, packet_function, maxLength, maxRun);