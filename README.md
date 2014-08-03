# VMCam
VMCam is a VCAS SoftCAM for IPTV.

## Configuration
Configuration of VCAS can be put in vmcam.ini

## Development
The development is done using git. VMCam repository is hosted
at http://github.com/irtimmer/vmcam

To clone the repository issue the following commands:

	$ git clone git://github.com/irtimmer/vmcam.git
	$ cd vmcam
	$ make
	
## Usage
	vmcam -i [interface] -c [configfile]
	-i [interface]	Name of interface to connect to server [default: eth0]\n");
	-c [configfile]	VCAS configfile [default: vmcam.ini]
	-C [camd interface] Set CAMD network protocol (CS378X / NEWCAMD) [default: CS378X]
	
## CAMD35-TCP/CS378x
Clients need to be changed to use AES instead of DES3
- Port: 8282
- Username: user
- Password: pass

## NEWCAMD
- Port 8282
- Username: user
- Password: pass
- DES key: 0102030405060708091011121314

## Thanks
Code is based upon the work of
- [vm_api](https://github.com/spdfrk1/vm_api)
- [OSCam](http://www.streamboard.tv/oscam/)
- [tsdecrypt] (http://georgi.unixsol.org/programs/tsdecrypt/)
