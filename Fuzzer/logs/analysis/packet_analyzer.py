#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import division
import json
import glob
import time
import sys

from pprint import pprint

# This script will analyze the results of the fuzzing scripts.
# It will give a list of the accepted lengths, lengthfields and ids.
# This gives an impression of the precision of the implementation 
# of the GSM protocol for each baseband processor.

accepted = [];
notAccepted = [];
incomplete = [];

# Possible functions
tmsiReallocationCommand = [];
locationUpdatingRequest = [];
imsiDetachIndication = [];

# Possible fields
lengths = [];
lengthFields = [];
ids = [];

# The mobile device.
device = sys.argv[1];

# load the json data from the log file
data = []
for fileName in glob.glob('../logs_packets/smarter_fuzzer/json/' + device + '*.json'):
	with open(fileName) as f:
	    for line in f:
	        data.append(json.loads(line))

for json in data:
	packetNumber = json["message"];

	if 'parsed_reply' not in json:
		incomplete.append(packetNumber)
	else:
		if "COMPLETE" not in json["parsed_reply"]:
			notAccepted.append(packetNumber);
		else:
			accepted.append(packetNumber);
			jid = json["id"];
			jLength = json["length"];
			jLengthField = json["lengthField"];

			if jLength not in lengths:
				lengths.append(jLength);

			if jLengthField not in lengthFields:
				lengthFields.append(jLengthField);

			if jid not in ids:
				ids.append(jid);

############################
# Print data			   #
############################

print("----------      General information     ---------- ");
print("Mobile device:" + device);
print("Total number of packages: " + str(len(data)));
if(len(data) > 0):
	percentage = "{0:.2f}".format((len(accepted)/len(data) * 100));
	print("Percentage accepted: " + percentage + "%\n");
print("Accepted packets: " + str(len(accepted)));
print("Not Accepted packets: " + str(len(notAccepted)));
print("Incomplete packets: " + str(len(incomplete)));

print("---------- Accepted package information ---------- ");
print("Accepted lengths:");
pprint(lengths);

print("Accepted lengthsFields:");
pprint(lengthFields);

print("Accepted ids:");
pprint(ids);

############################
# Log data				   #
############################


date = str(time.strftime("%Y%m%d-%H%M%S"));
packetAnalyzerResult = "packet_analysis_" + device + "_" + date + ".txt";
with open(packetAnalyzerResult, "a") as myfile:
	stringIds = str(ids).strip('[]');
	stringLengthFields = str(lengthFields).strip('[]');
	stringLengths = str(lengths).strip('[]');
	stringAccepted = str(accepted).strip('[]');
	stringNotAccepted = str(notAccepted).strip('[]');

	myfile.write("---------------------------------------------------------------\n"
		+ "Mobile device:" + device + '\n'
		+ "Total number of packages: " + str(len(data)) + "\n" 
		+ "Accepted packet numbers:"      + stringAccepted + "\n" 
		+ "Not accepted packet numbers:"      + stringNotAccepted + "\n" 
		+ "Accepted lengths:"      + stringLengths + "\n" 
		+ "Accepted lengthsFields:"      + stringLengthFields + "\n" 
		+ "Accepted ids:"      + stringIds + "\n");