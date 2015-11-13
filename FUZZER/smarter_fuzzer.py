#!/usr/bin/python
# -*- coding: utf-8 -*-
import socket
import time
import binascii
import os
from libmich.formats import *
import gsm_um
import smarter_fuzzer_function_def as fuzzer
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
def printPacket(packet, function, field, length, lengthField, id, permutation, prefix, currentRun, total_runs):
		print('------------------------------- INPUT  -------------------------------' + '\n');
		print('Run ' + str(currentRun) + "/" + str(total_runs) + '\n');
		print('Current function: ' + str(function));
		print('Current field: ' + str(field));
		print "Current hexbytes: ", length;
		print('Current hexvalue: ' + permutation.encode("hex"));
		print('Current lengthField: ' + str(lengthField));
		print('Current id: ' + str(id));

		# Fuzzing counter
		

		# Make the packet readable
		printable = str(packet).encode("hex");
		print "Current complete packet: " + printable + '\n';

		# Decode printable hex to make it usable for L3Mobile.
		# Adding the \x for the bytes.
		l3msg = printable.decode('hex');
		l3msg_input = repr(L3Mobile.parse_L3(l3msg));

		print "GSM_UM interpetation: \n " + l3msg_input + '\n\n';
		print "------------------------------- OUTPUT -------------------------------" + '\n';

############################################ SMART FUZZER ############################################
# This fuzzer targets fields with variable length
# Tries all different bytes for length byte
# Tries random bytes for a range of lengths
######################################################################################################
# Fuzzer specific settings
# From current length till end

currentField = 1;
lastField = 1;

currentFunction = 1;
lastFunction = 1;

lengths = [0, 8, 16, 17, 32, 33, 64, 65, 255];
lengthFields = [0, 8, 16, 17, 32, 33, 64, 65, 255];
ids = [-2, 0, 1, 2, 3, 4, 5, 65, 129];

maxLength = len(lengths);
maxLengthField = len(lengthFields);
lastId = len(ids);

total_runs = lastFunction * lastField * maxLength * lastId * maxLengthField;
currentRun = 1;

try:
	reply = tcsock.recv(1024);
	print reply;
except socket.timeout:
	print "socket.timeout: Testcall not running.";

if(adb_logging):
	clearLogs();
	
print "Cleaning logs on mobile device.";
print "Total amount of runs: " + str(total_runs);
time.sleep(1);
while currentField <= lastField:
	while currentFunction <= lastFunction:
		for i in range(len(lengths)):
			currentLength = lengths[i];
			permutation = (os.urandom(currentLength));
			perm = permutation.encode("hex");

			for j in range(maxLengthField):
				currentLengthField = lengthFields[j];

				k = 0;
				while k < lastId:
					currentId = ids[k];
					packet = fuzzer.fuzzingLengthFields(currentField, 
						currentFunction,
						currentId,
						currentLengthField, 
						perm);

					prefix = packet;


					if(verbose):
						printPacket(packet, currentFunction, currentField, currentLength, currentLengthField, currentId, permutation, prefix, currentRun, total_runs);

					# Send packet to the mobile device.
					packet = str(packet);
					result = send(tcsock, packet);

					if not result:
						establishNewChannel();
					else:
						parsed_result = repr(L3Mobile.parse_L3(result));
						parsed_packet = repr(L3Mobile.parse_L3(packet));
						log_packets(currentLength, currentLengthField, currentId, currentField, currentFunction, packet, parsed_packet, result, parsed_result);
						currentRun = currentRun + 1;
						k = k + 1;


		currentFunction = currentFunction + 1;

	currentField = currentField + 1;

	if(adb_logging):
		log_adb(adb, currentField, currentFunction, maxLength, maxRun);
			