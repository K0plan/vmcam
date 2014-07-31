# VMCam
VMCam is a SoftCAM for Verimatrix VCAS for IPTV.

## Configuration
Configuration of Verimatrix can be put in vmcam.ini

## Development
The development is done using git. VMCam repository is hosted
at http://github.com/irtimmer/vmcam

To clone the repository issue the following commands:

	$ git clone git://github.com/irtimmer/vmcam.git
	$ cd vmcam
	$ make
	
## Usage
	vmcam -i [interface] -c [configfile]
	-i [interface]	Name of interface to connect to Verimatrix server [default: eth0]\n");
	-c [configfile]	Verimatrix configfile [default: vmcam.ini]
	
## CAMD35-TCP/CS378x
Clients need to be changed to use AES instead of DES3
- Port: 8282
- Username: user
- Password: pass

