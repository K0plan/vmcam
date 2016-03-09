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

	-e [directory]  Directory to store cache files [default: /var/cache/vmcam]
	-d [debug level] Set debug level [default: 0]

	VCAS/VKS:

	-c [configfile]  VCAS configfile [default: vmcam.ini]
	-a [Amino MAC]  Your Amino MAC address [format: 010203040506]
	-ss [VCAS address] Set VCAS hostname to connect to
	-sk [VKS address] Set VKS hostname to connect to
	-ps [VCAS port]  Set VCAS port number to connect to
	-pk [VKS port]  Set VKS port number to connect to
	-C [Company name] Set name of company for key retreival
	-t [interval]  Interval for updating keys [default: 300]
	-noinitial  Skip initial keyblock retrieval

	Newcamd/CS378x:

	-pn [Newcamd port] Set Newcamd port number or 0 to disable [default: 15050]
	-pc [CS378x port] Set CS378x port number or 0 to disable [default: 15080]
	-l [ip addres]  Listen on ip address [default: 0.0.0.0]
	-u [username]  Set allowed user on server [default: user]
	-p [password]  Set password for server [default: pass]
	-k [DES key]  Set DES key for Newcamd [default: 0102030405060708091011121314]

## vmcam.ini
In vmcam.ini you can use the following configuration options

	CACHE_DIR=[Cache directory, default /var/cache/vmcam]
	DEBUG_LEVEL=[Debug level]
	AMINOMAC=[MAC address of your Amino]
	VCASSERVERADDRESS=[VCAS address]
	VCASSERVERPORT=[VCAS port]
	VKSSERVERADDRESS=[VKS address]
	VKSSERVERPORT=[VKS port]
	COMPANY=[Company name] 
	KEY_INTERVAL=[Key update interval]
	NEWCAMD_PORT=[Newcamd listening port]
	CS378X_PORT=[CS378x listening port]
	LISTEN_IP=[Address to listen for Newcamd/CS378x connections]
	USERNAME=[Newcamd/CS378x username]
	PASSWORD=[Newcamd/CS378x password]
	DES_KEY=[DES key for Newcamd]

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
- vm_api (abandoned)
- OSCam fork (abandoned)
- [tsdecrypt] (http://georgi.unixsol.org/programs/tsdecrypt/)
