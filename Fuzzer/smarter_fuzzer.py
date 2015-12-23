#!/usr/bin/python
# -*- coding: utf-8 -*-
import socket
import time
import binascii
import os
import sys
import itertools
import logging
import smarter_fuzzer_function_def as fuzzer

from adb import ADB
from libmich.formats import *
from random import randint
from pythonjsonlogger import jsonlogger


# Fill in current mobile device

if len(sys.argv) > 2:
    device = sys.argv[1];
    imsi = sys.argv[2];
else:
	print("ERROR: Device name not found.")
	print("Call the script with: ./smarter_fuzzer #DEVICE #IMSI");
	print("Where #DEVICE is the name and #IMSI is the IMSI of the mobile device.");
	sys.exit(0);

############################################### SETTINGS #############################################
# Default OpenBTS port
TESTCALL_PORT = 28670;
adb = ADB();

# Log file location
date = str(time.strftime("%Y%m%d-%H%M%S"));
location_prefix = "logs/logs_packets/smarter_fuzzer/";

location_log = location_prefix + device + "_" + date + ".log";
location_log_crash = location_prefix + "crash/" + device + "_" + date + ".log";
location_log_crash_JSON = location_prefix + "crash/json/" + device + "_" + date + ".json";
location_log_JSON = location_prefix + "json/" + device + "_" + date + ".json";

# Turn on/off prints
verbose = True;
# Turn on/off adb logs
adb_logging = False;

############################################### SOCKETS ##############################################

# Creat socket
tcsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tcsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcsock.settimeout(1)

ocsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ocsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

HOST = 'localhost'        # Symbolic name meaning all available interfaces
PORT = 21337              # Arbitrary non-privileged port
ocsock.bind((HOST, PORT))
ocsock.settimeout(20)


############################################### LOGGER ###############################################

# Initialize JSON logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# create a file handler
handler = logging.FileHandler(location_log_JSON)
handler.setLevel(logging.INFO)

error = logging.FileHandler(location_log_crash_JSON)
error.setLevel(logging.ERROR)

# create a logging format
formatter = jsonlogger.JsonFormatter()
handler.setFormatter(formatter)
error.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(handler)
logger.addHandler(error)

logger.info({
		"message": "Device and SIM information",
		"device": device,
		"imsi" : imsi});

########################################### LOG FUNCTIONS ############################################
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

def log_packets(run, maxRun, length, lengthField, id, field, function, packet, 
	parsed_packet, reply, parsed_reply):
	with open(location_log, "a") as myfile:
		myfile.write("----------------------------------------------------------------------\n"
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

	logger.info({
		"message": run,
		"maxRun" : maxRun, 
		"field": field,
		"function": function,
		"length": length,
		"lengthField": lengthField,
		"id": id,
		"packet": str(packet).encode("hex"),
		"parsed_packet": parsed_packet,
		"reply": reply,
		"parsed_reply": parsed_reply
		})

def log_restart():
	with open(location_log, "a") as myfile:
		myfile.write("\n\nCHANNEL RESTART \n \n");

def log_crash(run, maxRun, length, lengthField, id, field, function, packet, parsed_packet):
	with open(location_log_crash, "a") as myfile:
		myfile.write("----------------------------------------------------------------------\n"
			+ "INPUT" + '\n'
			+ "Field: "       + str(field) + "\n" 
			+ "Function: "    + str(function) + "\n" 
			+ "Length: "      + str(length) + "\n" 
			+ "LengthField: " + str(lengthField) + "\n" 
			+ "id: "          + str(id) + "\n" 
			+ "Packet: " + str(packet).encode("hex") + "\n" 
			+ parsed_packet + "\n\n");

	logger.error({
		"message": run,
		"maxRun" : maxRun, 
		"field": field,
		"function": function,
		"length": length,
		"lengthField": lengthField,
		"id": id,
		"packet": str(packet).encode("hex"),
		"parsed_packet": parsed_packet
		})

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
   	reply = ocsock.recv(20000)
   except:
   	print "Could not establish a new channel.";
   	return False;

   print "New channel established, fuzzing will continue.";
   time.sleep(1);
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
			print "Received packet: ", str(reply).encode("hex") + "\n";
			print "GSM_UM interpetation: " + '\n' + parsed_reply + "\n\n";
			return False

		return reply

############################################### UTILS ################################################
def printPacket(packet, function, field, length, lengthField, id, permutation, prefix, currentRun, 
	total_runs):
		print('------------------------------- INPUT  -------------------------------' + '\n');
		print('Run ' + str(currentRun) + "/" + str(total_runs) + '\n');
		print('Current function: ' + str(function));
		print('Current field: ' + str(field));
		print "Current hexbytes: ", length;
		print('Current MobileId: ' + permutation);
		print('Current lengthField: ' + str(lengthField));
		print('Current id: ' + str(id));

		# Make the packet readable
		if(len(packet) % 2 == 0):
			printable = str(packet).encode("hex");
			print "Current complete packet: " + printable + '\n';

		#Decode printable hex to make it usable for L3Mobile.
		#Adding the \x for the bytes.
		l3msg_input = repr(L3Mobile.parse_L3(str(packet)));

		print "GSM_UM interpetation: \n " + l3msg_input + '\n\n';
		print "------------------------------- OUTPUT -------------------------------" + '\n';

def fill_with_N_digits(n):
	result = "";
	for x in range(n):
		if(x % 2 == 0):
			result = result + "1";
		else:
			result = result + "8";

	return result
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

lengths = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,32,64,65,128,129];
lengthFields = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,32,64,65,128,129];
ids = [0,1,2,3,4,5,6,7,8,9,10,32,64];

maxLength = len(lengths);
maxLengthField = len(lengthFields);
lastId = len(ids);

if 1 in ids: 
	numberOfTriedIds = lastId + 1;

total_runs = lastFunction * lastField * maxLength * numberOfTriedIds * maxLengthField;
currentRun = 1;

maxPacketAttempt = 5;
currentPacketAttempt = 1;

# Remove leading 2 from the imsi.
imsi = imsi[1:];

if(adb_logging):
	clearLogs();

try:
   	reply = ocsock.recvFrom(('127.0.0.1', 21337), 20000)
except:
	print "Could not determine if the channel is active. Trying to send data anyway.";

tcsock.settimeout(2)
print "Cleaning logs on mobile device.";
print "Total amount of runs: " + str(total_runs);
time.sleep(2);
while currentField <= lastField:
	while currentFunction <= lastFunction:
		# Determines the length of the packet
		for i in range(len(lengths)):
			currentLength = lengths[i];

			if(currentLength != 0):
				permutation = str(fill_with_N_digits(currentLength));
			else:
				permutation = "";
			# Determines the value of the lengthfield
			for j in range(maxLengthField):
				currentLengthField = lengthFields[j];
				useRealImsiNow = True;
				# Determines the value of the Id
				k = 0;
				while k < lastId:
					currentId = ids[k];

					# Id 1 == IMSI. The script uses both random data and
					# the real IMSI to test if the message is accepted.
					if(currentId == 1 and (useRealImsiNow)):
						if (currentLength > 14):
							permutation = imsi + permutation[14:];
						elif (currentLength == 14):
							permutation = imsi;
						else:
							permutation = imsi[:currentLength];

					# Create the packet.
					print "permutation is now:" + permutation;
					packet = fuzzer.fuzzingLengthFields(currentField, 
						currentFunction,
						currentId,
						currentLengthField, 
						permutation);

					prefix = packet;

					if(verbose):
						printPacket(packet, currentFunction, currentField, 
							currentLength, currentLengthField, currentId, 
							permutation, prefix, currentRun, total_runs);

					# Send packet to the mobile device.
					packet = str(packet);
					result = send(tcsock, packet);

					# The response is not recognized or the channel is released
					# A new channel is established and the crash is logged.
					# This happens till max packet attempt is reached and move on
					if not result:
						currentPacketAttempt = currentPacketAttempt + 1;
						establishNewChannel();
						if(currentPacketAttempt >= maxPacketAttempt):
							parsed_packet = repr(L3Mobile.parse_L3(packet));
							log_crash(currentRun, total_runs, currentLength,
								currentLengthField, currentId, 
								currentField, currentFunction, 
								packet, parsed_packet);

							currentRun = currentRun + 1;
							k = k + 1;
					# The response is accepted and logged.
					# The Boolean useRealImsiNow is flipped so that both random data
					# and the real IMSI are tried when the Id == 1		
					else:
						parsed_result = repr(L3Mobile.parse_L3(result));
						parsed_packet = repr(L3Mobile.parse_L3(packet));
						log_packets(currentRun, total_runs, currentLength,
							currentLengthField, currentId, currentField, 
							currentFunction, packet, parsed_packet, 
							result, parsed_result);
						currentRun = currentRun + 1;
						if(currentId == 1 and not useRealImsiNow):
							useRealImsiNow = True;
						else:
							k = k + 1;
						currentPacketAttempt = 0;

		currentFunction = currentFunction + 1;

	currentField = currentField + 1;

	if(adb_logging):
		log_adb(adb, currentField, currentFunction, maxLength, maxRun);
			