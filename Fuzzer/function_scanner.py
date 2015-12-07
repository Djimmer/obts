#!/usr/bin/python
# -*- coding: utf-8 -*-
import socket
import time
import binascii
import os
import sys
from libmich.formats import *
import gsm_um
import smarter_fuzzer_function_def as fuzzer
import itertools
from random import randint

from math import factorial
import logging
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

# Log file location
date = str(time.strftime("%Y%m%d-%H%M%S"));
log_all_functions_JSON = "logs/functions/" + device + "_log_" + date + ".json";

# Creat socket
tcsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tcsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcsock.settimeout(2)

ocsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ocsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

HOST = 'localhost'        # Symbolic name meaning all available interfaces
PORT = 21337              # Arbitrary non-privileged port
ocsock.bind((HOST, PORT))
ocsock.settimeout(20)

# Initialize JSON logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# create a file handler
handler = logging.FileHandler(log_all_functions_JSON)
handler.setLevel(logging.INFO)

# create a logging format
formatter = jsonlogger.JsonFormatter()
handler.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(handler)

logger.info({
		"message": "Function Scanner; Device and SIM information",
		"device": device,
		"imsi" : imsi});

################################################# LOG ################################################
def log_packets(run, maxRun, packet, parsed_packet, reply, parsed_reply):
	if "ERROR" in parsed_reply:
		parsed_reply = "libmich ERROR";

	logger.info({
		"message": run,
		"maxRun" : maxRun,
		"packet": str(packet).encode("hex"),
		"parsed_packet": parsed_packet,
		"reply": str(reply).encode("hex"),
		"parsed_reply": parsed_reply
		})


############################################## CHANNEL ###############################################
# Send a restart to OpenBTS to establish a new channel
def establishNewChannel():
   restart = "RESTART";
   print("Channel restart: Establishing a new channel, this may take a second.");
   tcsock.sendto(restart, ('127.0.0.1', TESTCALL_PORT));

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

		return packetImplemented(reply)


def packetImplemented(reply):
	parsed_reply = repr(L3Mobile.parse_L3(reply));

	print "Received packet: ", str(reply).encode("hex") + "\n";
	print "GSM_UM interpetation: " + '\n' + parsed_reply + "\n\n";

	if "RELEASE_COMPLETE" in parsed_reply:
		return "Restart";
	elif((str(reply).encode("hex") == "786e430200")): #MDL_ERROR_INDICATION
		return "Restart";
	elif((str(reply).encode("hex") == "789ea400")): #MDL_ERROR_INDICATION
		return "Restart";	
	elif((str(reply).encode("hex") == "06126100")):
		return "Skip";
	elif "Message type non-existent or not implemented" in parsed_reply:
		return "Skip";
	else:
		return reply;

############################################### UTILS ################################################
def printPacket(packet, currentRun, total_runs):
		print('------------------------------- INPUT  -------------------------------' + '\n');
		print('Run ' + str(currentRun) + "/" + str(total_runs) + '\n');
		# Make the packet readable
		if(len(packet) % 2 == 0):
			printable = str(packet).encode("hex");
			print "Current complete packet: " + printable + '\n';

		# Decode printable hex to make it usable for L3Mobile.
		# Adding the \x for the bytes.
		l3msg_input = repr(L3Mobile.parse_L3(str(packet)));

		print "GSM_UM interpetation: \n " + l3msg_input + '\n\n';
		print "------------------------------- OUTPUT -------------------------------" + '\n';

############################################ SMART FUZZER ############################################
# This fuzzer targets fields with variable length
# Tries all different bytes for length byte
# Tries random bytes for a range of lengths
######################################################################################################
# Fuzzer specific settings

maxPacketAttempt = 5;
currentPacketAttempt = 1;

protocols = [3];

currentRun = 1;
total_runs = len(protocols) * 256;


print "Total amount of runs: " + str(total_runs);
time.sleep(1);

for i in protocols:
	firstByte = "{0:0{1}x}".format(i,2);
	n = 1;
	while n < 256:
		secondByte = "{0:0{1}x}".format(n,2);

		if(i == 5 and n == 17):
			# Skip because the packet 0511 is a Authentication Reject 
			# and disconnects the mobile device
			secondByte = "{0:0{1}x}".format(n+1,2);
		
		packet = "\\x" + str(firstByte) + "\\x" + str(secondByte);
		packet = packet.replace('\\x', '').decode('hex');

		print "Packet: " + str(packet).encode("hex");
		printPacket(packet, currentRun, total_runs);

		# Send packet to the mobile device.
		result = send(tcsock, packet);

		if(result == "Restart" or result == False):
			currentPacketAttempt = currentPacketAttempt + 1;
			establishNewChannel();
			if(currentPacketAttempt >= maxPacketAttempt):
				parsed_packet = repr(L3Mobile.parse_L3(packet));
				log_packets(currentRun, total_runs, packet, parsed_packet, "None", "None");
				currentRun = currentRun + 1;
				n = n + 1;
		elif(result =="Skip"):
			currentRun = currentRun + 1;
			currentPacketAttempt = 0;
			n = n + 1;
		else:
			parsed_result = repr(L3Mobile.parse_L3(result));
			parsed_packet = repr(L3Mobile.parse_L3(packet));
			log_packets(currentRun, total_runs, packet, parsed_packet, result, parsed_result);
			currentRun = currentRun + 1;
			currentPacketAttempt = 0;
			n = n + 1;
		