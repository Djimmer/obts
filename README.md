# OpenBTS 5.0 with "testcall"

This repo consists of:

 * OpenBTS 5.0 with the implemented testcall function (removed since OpenBTS 2.8 for security reasons)
 * 3 Fuzzing Scripts


# Motiviation
Security through obscurity is just wrong. 

Thats why I re-implemented the function in the newest OpenBTS and I am making it publicly available. Besides that, the function can provide great insights for security specialists into baseband processor of mobile devices. It will improve the security and will reveal flaws in the implementation of baseband processors. 

The discussion on the "testcall" subject by the creators can be found [here](http://sourceforge.net/p/openbts/mailman/openbts-discuss/thread/026f01ce30e8%24bf12f680%243d38e380%24%40schmid.xxx/#msg30679550).


# Installation guide OpenBTS + Testcall
This guide provides a step-by-step manual to install OpenBTS 5.0 with the "Testcall"  function and the capability to fuzz a mobile device. The guide also covers any libraries or additional programs to be able to run OpenBTS. The guide starts from scratch and assumes the use of BladeRF. Other SDR's are also supported by OpenBTS and can be installed using the manufacturers guide.

Setting up a virtual machine with Ubuntu:
```javascript
step 1: Install VMware workstation 12 player from: https://my.vmware.com/web/vmware/free#desktop_end_user_computing/vmware_workstation_player/12_0
Step 2: Download Ubuntu from  http://www.ubuntu.com/download/desktop
Step 3: Createa a Virtual machine with the downloaded Ubuntu iso
Step 4: After the installation start Ubuntu.
````

```javascript
sudo apt-get install autoconf libtool libosip2-dev libortp-dev libusb-1.0-0-dev g++ sqlite3 
libsqlite3-dev erlang libreadline6-dev libncurses5-dev git dpkg-dev debhelper libssl-dev
````


Clone the OpenBTS and Testcall Git repositories.
```javascript
% OpenBTS
git clone https://github.com/RangeNetworks/dev
% TestCall
git clone https://github.com/Djimmer/obts
````


Go to the OpenBTS folder, dev/
```javascript
% Download all of the components
./clone.sh

cd libcoredumper;
./build.sh && \
   sudo dpkg -i *.deb;
cd ..
cd liba53;
make && \
   sudo make install;
cd ..;

cd NodeManager;
./install_libzmq.sh 
````

Installing bladeRF.
```javascript
sudo add-apt-repository ppa:bladerf/bladerf
sudo apt-get update
sudo apt-get install bladerf
````

Install Yate.
```javascript
sudo svn checkout http://voip.null.ro/svn/yate/trunk yate
cd yate/
sudo ./autogen.sh
sudo ./configure
sudo make install-noapi
````

Install YateBTS.
```javascript
wget http://voip.null.ro/tarballs/yatebts4/yate-bts-4.0.2-1.tar.gz
tar -xzf yate-bts-4.0.2-1.tar.gz
cd yate-bts/
./autogen.sh
./configure
````
Build and install libbladeRF
```javascript
git clone https://github.com/Nuand/bladeRF.git
cd bladeRF/host
mkdir -p build
cd build
#install smake if required
cmake ../
make
sudo make install
sudo ldconfig
````

Create a transceiver suitable for the bladeRF.
```javascript
cd yate-bts/mbts/Peering/
make

cd ../TransceiverRAD1
sudo nano Makefile

PROGS_BRF := transceiver-bladerf
ifneq (no,no)
FILES:= \$(FILES) firmware.img hostedx40.rbf hostedx115.rbf
PROGS:= $(PROGS) $(PROGS_BRF)
endif

Change to ifneq (yes,no) and save.

make
%if at this point you get an error like "libbladeRF.h: No such file or directory compilation terminated" then you didn't install the libbladeRF tools

cp transceiver-bladerf ../../../obts/apps/
cd ../../../obts/apps/
ln -sf transceiver-bladerf transceiver
````

Import the Testcall code into OpenBTS
```javascript
cd obts/
cp -r CLI/ ../../dev/openbts/
cp -r Control/ ../../dev/openbts/
cp -r GSM ../../dev/openbts/
cp -r FUZZER ../../dev/openbts/
````


Install OpenBTS
```javascript
cd /home/openbts/obts/openbts
./autogen.sh
./configure --with-uhd
make
````

Initialize the OpenBTS database
```javascript
sudo mkdir /etc/OpenBTS
sudo sqlite3 -init ./apps/OpenBTS.example.sql /etc/OpenBTS/OpenBTS.db ".quit"
Test this by running:

sqlite3 /etc/OpenBTS/OpenBTS.db .dump
````

In order to run OpenBTS some additional programs are required: Subscriber Registery and Smqueue.

Installing Subscriber Registery:
```javascript
sudo mkdir -p /var/lib/asterisk/sqlite3dir

cd /dev/subscriberRegistry/
./autogen.sh
./configure
make

sudo sqlite3 -init sipauthserve.penBTS/sipauthserve.db ".quit"

sudo ./sipauthserve
````

Installing Smqueue:
```javascript
cd /dev/smqueue/
./autogen.sh
./configure
make

sudo mkdir /var/lib/OpenBTS
sudo touch /var/lib/OpenBTS/smq.cdr

sudo ./smqueue
````

To start OpenBTS
```javascript
cd dev/openbts/apps
sudo ./OpenBTS

cd dev/subscriberRegistry/apps
sudo ./sipauthserve

cd dev/smqueue/smqueue
sudo ./smqueue
````
# Fuzzing
First start OpenBTS and call the testcall function.
````
Start OpenBTS
Connect and Register a mobile device
testcall IMSI 
     where IMSI is the IMSI of the mobile device
````

This will take a moment. OpenBTS is now listening on UDP and will send any received data to the mobile device.
To start the actual fuzzing you have to run one of the three scripts:
````
cd obts/FUZZER/
./simple_fuzzer.py
or
./smart_fuzzer.py
or
./smarter_fuzzer.py
````

More information on the fuzzing settings and the differences between the scripts can be found [here](www.google.com).

