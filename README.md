# VMCam
VMCam is a VCAS SoftCAM for IPTV.

## Configuration
Configuration of VCAS can be put in /etc/vmcam.ini or specified in arguments

## Development
The development is done using git. VMCam repository is hosted
at http://github.com/irtimmer/vmcam

To clone the repository issue the following commands:

	$ git clone git://github.com/irtimmer/vmcam.git
	$ cd vmcam
	$ ./configure
	$ make
	$ make install
	$ mkdir /var/cache/vmcam
	
## Usage
	vmcam [options]

	-e [directory]  Directory to store files
	-d [debug level] Set debug level [default: 0]

	VCAS/VKS:

	-c [configfile]  VCAS configfile [default: vmcam.ini]
	-ss [VCAS address] Set VCAS hostname to connect to
	-sk [VKS address] Set VKS hostname to connect to
	-ps [VCAS port]  Set VCAS port number to connect to
	-pk [VKS port]  Set VKS port number to connect to
	-C [Company name] Set name of company for key retreival
	-t [interval]  Interval for updating keys [default: 300]
	-i [interface]  Name of connecting interface [default: eth0]
	-m [mac addres]  Set mac addres [default from interface]
	-noinitial  Skip initial keyblock retrieval

	Newcamd/CS378x:

	-pn [Newcamd port] Set Newcamd port number or 0 to disable [default: 15050]
	-pc [CS378x port] Set CS378x port number or 0 to disable [default: 15080]
	-l [ip addres]  Listen on ip address [default: 0.0.0.0]
	-u [username]  Set allowed user on server [default: user]
	-p [password]  Set password for server [default: pass]
	-k [DES key]  Set DES key for Newcamd [default: 0102030405060708091011121314]
	
## CAMD35-TCP/CS378x
Clients need to be changed to use AES instead of DES3
- Port: 15080
- Username: user
- Password: pass

## NEWCAMD
Clients need to be changed to use AES instead of DES3
- Port 15050
- Username: user
- Password: pass
- DES key: 0102030405060708091011121314

## Thanks
Code is based upon the work of
- [vm_api](https://github.com/spdfrk1/vm_api)
- [OSCam](http://www.streamboard.tv/oscam/)
- [tsdecrypt] (http://georgi.unixsol.org/programs/tsdecrypt/)
