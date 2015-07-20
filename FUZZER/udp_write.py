#!/usr/bin/python
# -*- coding: utf-8 -*-
import socket
import time
import binascii
from libmich.formats import *
from scapy.contrib import gsm_um
   
TESTCALL_PORT = 28670

# Send a restart to OpenBTS to establish a new channel
def establishNewChannel():

   restart = "RESTART";
   tcsock.sendto(restart, ('127.0.0.1', TESTCALL_PORT))
   with open("log.txt", "a") as myfile:
   	myfile.write("\n\nCHANNEL RESTART \n \n");
   return

# def tmsiLength(length):
#    restart = "restartChannel";
#    tcsock.sendto(restart, ('127.0.0.1', TESTCALL_PORT))
#    return

# Fuzzing loop
for x in range (0,100):
	print "Fuzzing: ", x;
	l3msg = '\x05\x18\x01';
	l3msg_input = repr(L3Mobile.parse_L3(l3msg));

	tcsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	tcsock.settimeout(5)
	try:
		tcsock.sendto(l3msg, ('127.0.0.1', TESTCALL_PORT))
		reply = tcsock.recv(1024)
		parsed_reply = repr(L3Mobile.parse_L3(reply));
		if "GPRS" not in parsed_reply:
			print "reply received: ", parsed_reply;
		else:
			establishNewChannel();
			time.sleep(3);
		with open("log.txt", "a") as myfile:
			myfile.write("INPUT " + str(x) + "\n" + l3msg_input + "\nOUTPUT " + str(x) + "\n" + parsed_reply + "\n\n");
	except socket.timeout:
		print "no reply received. potential crash?"
		establishNewChannel();
		time.sleep(3);



#############################################################################
############################## Trying stuff #################################
#############################################################################


################################ OLD OVERFLOW ################################
# len = 19
# lai = 42
# hexstr = "051a00f110"
# hexstr += "%02x%02x%02xfc" % (lai>>8, lai&255, (4*len+1))
# hexstr += ''.join('%02x666666' % (4*i) for i in range(len))
# r = binascii.unhexlify(hexstr)
# gsm_um.hexdump(r);


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