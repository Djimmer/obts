#!/usr/bin/python
# -*- coding: utf-8 -*-
import json
import glob
from pprint import pprint

# This script will analyze the results of the fuzzing scripts.
# It will give a list of the accepted lengths, lengthfields and ids.
# This gives an impression of the precision of the implementation 
# of the baseband processor.

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
device = "NEXUS";

# load the json data from the log file
data = []
for fileName in glob.glob('../logs_packets/smarter_fuzzer/json/' + device + '*.json'):
	with open(fileName) as f:
	    for line in f:
	        data.append(json.loads(line))

for json in data:
	packetNumber = json["message"];

	if 'parsed_reply' not in json:
		#print "Packet is incomplete";
		incomplete.append(packetNumber)
	else:
		if "COMPLETE" not in json["parsed_reply"]:
			#print "Run " + str(packetNumber) + " was not accepted by the mobile device.";
			notAccepted.append(packetNumber);
		else:
			#print "Run " + str(packetNumber) + " was accepted by the mobile device!";
			accpted.append(packetNumber);
			jid = json["id"];
			jLength = json["length"];
			jLengthField = json["lengthField"];

			if jLength not in lengths:
				lengths.append(jLength);

			if jLengthField not in lengthFields:
				lengthFields.append(jLengthField);

			if jid not in ids:
				ids.append(jid);

print("----------      General information     ---------- ");
print("Mobile device:" + device);
print("Total number of packages: " + str(len(data)));
if(len(data) > 0):
	print("Percentage accepted: " + str(len(accepted)/len(notAccepted)) + "%\n");
print("Accepted packets:" + str(len(accepted)));
print("Not Accepted packets:" + str(len(notAccepted)));
print("Incomplete packets:" + str(len(incomplete)));

print("---------- Accepted package information ---------- ");
print("Accepted lengths:");
pprint(lengths);

print("Accepted lengthsFields:");
pprint(lengthFields);

print("Accepted ids:");
pprint(ids);


packetAnalyzerResult = "crash_analysis_" + device + ".txt";
with open(packetAnalyzerResult, "a") as myfile:
	stringIds = str(ids).strip('[]');
	stringLengthFields = str(lengthFields).strip('[]');
	stringLengths = str(lengths).strip('[]');
	stringAccepted = str(accepted).strip('[]');
	stringNotAccepted = str(notAccepted).strip('[]');

	myfile.write("-------------------------------------------------------------------------------\n"
		+ "Mobile device:" + device + '\n'
		+ "Total number of packages: " + str(len(data)) + "\n" 
		+ "Accepted packet numbers:"      + stringAccepted + "\n" 
		+ "Not accepted packet numbers:"      + stringNotAccepted + "\n" 
		+ "Accepted lengths:"      + stringLengths + "\n" 
		+ "Accepted lengthsFields:"      + stringLengthFields + "\n" 
		+ "Accepted ids:"      + stringIds + "\n");