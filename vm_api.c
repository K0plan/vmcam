/**
 * Copyright (c) 2014 Iwan Timmer
 * 
 * This file is part of VMCam.
 * 
 * VMCam is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * VMCam is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with VMCam.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * vmapi code derived from work by spdfrk1
 */

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <ucontext.h>
#include <string.h>

#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>   //ifreq

#include "ssl-client.h"
#include "tcp-client.h"

#define uchar unsigned char
#define GETKEYS_BUFFSIZE (1024 * 100)

#define RETURN_ERR(s) printf("[API] %s\n", s); goto cleanup;

// Connection data
char vcasServerAddress[31];			// Your VCAS server address
char vksServerAddress[31];			// Your VCAS server address
int VCAS_Port_SSL;				// Your VCAS port
int VKS_Port_SSL;				// Your VKS port

// API data
char api_company[31];				// Your company
const char * api_msgformat = "1154"; 		// Only 1154 is supported for now

// Cert data
const char * szCountry = "US";
const char * szProvince = "CA";
const char * szCity = "San Diego";
const char * szOrganization = "PCPlayer";
const char * szCommon = "STB";
char * szEmail;

// Client data
char * api_clientID;
char * clientMAC;

// Session data
uchar * session_key;
uchar * timestamp;
char * ski;

// Files used
char * f_signedcert = "SignedCert.der";
char * f_csr = "csr.pem";
char * f_rsa_private_key = "priv_key.pem";
char * f_keyblock = "keyblock";
char * f_ClientId = "clientid.dat";

int load_config(char* f_config) {
	FILE * fp;
	int scan;
	
	char key[31], value[31];
	if ((fp = fopen(f_config, "r"))) {
		while ((scan = fscanf(fp, "%30[^=\n]=%30s\n?", key, value)) != EOF) {
			if (scan == 1) {
				fseek(fp, 1, SEEK_CUR); //Skip EOL
			} else {
				if (strcasecmp(key, "COMPANY") == 0) {
					strncpy(api_company, value, 30);
				} else if (strcasecmp(key, "SERVERADDRESS") == 0) {
					strncpy(vcasServerAddress, value, 30);
				} else if (strcasecmp(key, "SERVERPORT") == 0) {
					VCAS_Port_SSL = atoi(value);
				} else if (strcasecmp(key, "PREFERRED_VKS") == 0) {
					sscanf(value, "%30[^/]/%d", vksServerAddress, &VKS_Port_SSL);
				}
			}
		}
	} else {
		RETURN_ERR("Unable to read vm_api.ini");
	}
	return -1;
	
cleanup:

	return 0;
}

int load_clientid() {
	int i, j = 0;
	api_clientID = calloc(57, 1);
	FILE * fp;

	fp = fopen(f_ClientId, "r");
	if (fp) {
		i = fread(api_clientID, 1, 56, fp);
		fclose(fp);
		if (i == 56) {
			return 0;
		}
	}

	for (i = 0; i < 28; i++) {
		j += sprintf(api_clientID + j, "%02X", rand() & 0xFF);
	}
	fp = fopen(f_ClientId, "w");
	fwrite(api_clientID, j, 1, fp);
	fclose(fp);
	return 0;
}

void load_MAC(char* iface) {
	int fd;
	struct ifreq ifr;

	unsigned char *mac;

	clientMAC = calloc(13, 1);

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);

	close(fd);

	mac = (unsigned char *) ifr.ifr_hwaddr.sa_data;

	//display mac address
	sprintf(clientMAC, "%.2x%.2x%.2x%.2x%.2x%.2x", mac[0], mac[1], mac[2],
			mac[3], mac[4], mac[5]);
	clientMAC[12] = 0;
	printf("Detected MAC: %s for interface: %s\n", clientMAC, iface);
	return;
}

void generate_rsa_pkey() {
	FILE * fp;
	RSA * rsa_priv_key;
	const int kBits = 1024;
	const int kExp = 65537;
	int keylen;
	char *pem_key;

	rsa_priv_key = RSA_generate_key(kBits, kExp, 0, 0);

	/* To get the C-string PEM form: */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(bio, rsa_priv_key, NULL, NULL, 0, NULL, NULL);

	keylen = BIO_pending(bio);
	pem_key = calloc(keylen + 1, 1); /* Null-terminate */
	BIO_read(bio, pem_key, keylen);

	fp = fopen(f_rsa_private_key, "w");
	if (fp) {
		fwrite(pem_key, keylen, 1, fp);
		fclose(fp);
	}

	printf("Private key created:\n%s\n", pem_key);

	BIO_free_all(bio);
	free(pem_key);
}

void load_rsa_pkey(RSA ** rsa_priv_key) {
	FILE *fp;
	// Read PEM Private Key
	fp = fopen(f_rsa_private_key, "r");
	if (fp) {
		printf("Private key found\n");
		*rsa_priv_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
		fclose(fp);
	} else {
		generate_rsa_pkey();
		fp = fopen(f_rsa_private_key, "r");
		*rsa_priv_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	}
}

int generate_signed_hash(uchar ** signed_hash) {
	RSA * rsa_priv_key;
	uchar md5hash[MD5_DIGEST_LENGTH];
	uchar buf[129];
	*signed_hash = calloc(257, 1);
	MD5(timestamp, 19, md5hash);
	unsigned int n = 0;
	load_rsa_pkey(&rsa_priv_key);
	RSA_sign(NID_md5, md5hash, MD5_DIGEST_LENGTH, buf, &n, rsa_priv_key);
	int i, j = 0;
	for (i = 0; i < 128; i++) {
		j += sprintf((char*) *signed_hash + j, "%02x", buf[i]);
	}
	return j + 2;
}

int generate_csr(char** pem_csr) {
	FILE* fp;
	RSA * rsa_priv_key;
	int ret = 0;
	int nVersion = 0;
	int keylen = 0;

	X509_REQ *x509_req = NULL;
	X509_NAME *x509_name = NULL;
	EVP_PKEY *pKey = NULL;
	BIO *bio = NULL;

	char * CN = calloc(64, 1);
	sprintf(CN, "%s/%s", szCommon, szEmail);

	// 2. set version of x509 req
	x509_req = X509_REQ_new();
	ret = X509_REQ_set_version(x509_req, nVersion);
	if (ret != 1) {
		goto free_all;
	}

	// 3. set subject of x509 req
	x509_name = X509_REQ_get_subject_name(x509_req);

	ret = X509_NAME_add_entry_by_txt(x509_name, "C", MBSTRING_ASC,
			(const unsigned char*) szCountry, -1, -1, 0);
	if (ret != 1) {
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "ST", MBSTRING_ASC,
			(const unsigned char*) szProvince, -1, -1, 0);
	if (ret != 1) {
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "L", MBSTRING_ASC,
			(const unsigned char*) szCity, -1, -1, 0);
	if (ret != 1) {
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "O", MBSTRING_ASC,
			(const unsigned char*) szOrganization, -1, -1, 0);
	if (ret != 1) {
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC,
			(const unsigned char*) CN, -1, -1, 0);
	if (ret != 1) {
		goto free_all;
	}

	// 4. set public key of x509 req
	load_rsa_pkey(&rsa_priv_key);
	pKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pKey, rsa_priv_key);

	ret = X509_REQ_set_pubkey(x509_req, pKey);
	if (ret != 1) {
		goto free_all;
	}

	// 5. set sign key of x509 req
	ret = X509_REQ_sign(x509_req, pKey, EVP_sha1()); // return x509_req->signature->length
	if (ret <= 0) {
		goto free_all;
	}

	/* To get the C-string PEM form: */
	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_REQ(bio, x509_req);
	keylen = BIO_pending(bio);
	*pem_csr = malloc(keylen + 1); /* Null-terminate */

	BIO_read(bio, *pem_csr, keylen);

	/* Write to file */
	fp = fopen(f_csr, "w");
	if (fp) {
		fwrite(*pem_csr, keylen, 1, fp);
		fclose(fp);
	}

	printf("CSR created:\n%s", *pem_csr);
	// 6. free
	free_all: X509_REQ_free(x509_req);
	BIO_free_all(bio);
	return (keylen);
}

int generate_ski_string() {
	FILE *fp;
	int i, j = 0, loc = 0;
	char* buf2 = ski = calloc(40 + 1, 1);
	X509 * signed_cert = 0;
	X509_EXTENSION *ext;

	fp = fopen(f_signedcert, "r");
	if (fp) {
		signed_cert = d2i_X509_fp(fp, &signed_cert);
		fclose(fp);
	} else { 	//Create new one
		return -1;
	}

	loc = X509_get_ext_by_NID(signed_cert, NID_subject_key_identifier, -1);
	ext = X509_get_ext(signed_cert, loc);

	if (ext == NULL) {
		return -1;
	}

	for (i = 2; i < 22; i++) {
		j += sprintf(buf2 + j, "%02X", ext->value->data[i]);
	}
	return j + 2;
}

int API_GetSessionKey() {
	uchar response_buffer[64];
	uchar msg[128];
	int msglen = sprintf((char*) msg, "%s~%s~CreateSessionKey~%s~%s~",
			api_msgformat, api_clientID, api_company, clientMAC);
			
	printf("[API] Requesting Session Key: %s\n", msg);

	if(ssl_client_send(msg, msglen, response_buffer, 64, vcasServerAddress,
	VCAS_Port_SSL) < 45) {
		return -1;
	}
	session_key = calloc(16, 1);
	timestamp = calloc(20, 1);
	memcpy(session_key, response_buffer + 4, 16);
	memcpy(timestamp, response_buffer + 20, 20);
	printf("Session key obtained, timestamp: %s\n", timestamp);
	return 0;
}

int API_GetCertificate() {
	FILE * fp;
	const uchar * cert;
	char * csr;
	int response_len;
	int msglen;
	uchar msg[1024];
	uchar * response_buffer = calloc(1024, 1);
	/******* Get the current time64 *******/
	long long unsigned int t64 = (long long unsigned int) time(NULL);

	/******* Generate the CSR *******/
	printf("Generating CSR\n");
	szEmail = calloc(64, 1);
	sprintf(szEmail, "%s.%llu@Verimatrix.com", clientMAC, t64);
	printf("Using email: %s\n", szEmail);
	generate_csr(&csr);

	/******* Generate the request string *******/
	msglen =
			sprintf((char*) msg,
					"%s~%s~getCertificate~%s~NA~NA~%s~STB~6650 Lusk Blvd, Suite B203~ ~San Diego~CA~92021~US~858-677-7800~%s~%s~ ~",
					api_msgformat, api_clientID, api_company, csr, szEmail,
					clientMAC);

	fp = fopen("getcertreq.txt", "w");
	fwrite(msg, 1, msglen, fp);
	fclose(fp);

	printf("[API] Requesting Certificate: %s\n", msg);

	/******* Send the request *******/
	response_len = ssl_client_send(msg, msglen, response_buffer, 1024,
	vcasServerAddress, VCAS_Port_SSL);

	if (response_len < 12) {
		free(response_buffer);
		return -1;
	}

	/******* Get the Signed cert from the response *******/
	cert = response_buffer + 12;

	/******* Write to file *******/
	fp = fopen(f_signedcert, "w");
	fwrite(cert, response_len - 12, 1, fp);
	fclose(fp);

	free(response_buffer);
	return 0;
}

int API_GetAllChannelKeys() {
	uchar * signedhash;
	uchar msg[512];
	uchar * response_buffer = calloc(GETKEYS_BUFFSIZE, 1);
	uchar * keyblock;
	int msglen, retlen, plainlen;
	RC4_KEY rc4key;
	FILE * fp;

	if (response_buffer == NULL) {
		printf("[API] GetAllChannelKeys failed, unable to allocate memory");
		return -1;
	}

	plainlen = strlen(api_company) + 39;

	generate_signed_hash(&signedhash);
	msglen = sprintf((char*) msg,
			"%s~%s~%s~%s~%s~GetAllChannelKeys~%s~%s~%s~%s~ ~ ~", api_msgformat,
			api_company, timestamp, clientMAC, api_clientID, api_company, ski,
			signedhash, clientMAC);

	printf("[API] Requesting master keys: %s\n", msg);
	RC4_set_key(&rc4key, 16, session_key);
	RC4(&rc4key, msglen - plainlen, msg + plainlen, msg + plainlen);

	retlen = tcp_client_send(msg, msglen, response_buffer, GETKEYS_BUFFSIZE,
	vksServerAddress, (VKS_Port_SSL + 1));
	if (retlen < 10) {
		free(response_buffer);
		return -1;
	}

	keyblock = response_buffer + 4;
	retlen -= 4;
	
	printf("[API] GetAllChannelKeys completed, size: %d\n", retlen);

	RC4_set_key(&rc4key, 16, session_key);
	RC4(&rc4key, retlen, keyblock, keyblock);

	fp = fopen(f_keyblock, "w");
	if (fp) {
		fwrite(keyblock, retlen, 1, fp);
		fclose(fp);
		free(response_buffer);
		return 0;
	} else {
		printf("[API] GetAllChannelKeys failed, could not write keyblock\n");	
	}
	free(response_buffer);
	return -1;
}

int init_vmapi(char* config, char* iface) {
	// Init SSL Client
	ssl_client_init();

	int exit_code = EXIT_FAILURE;
	
	if (load_config(config) == 0) {
		RETURN_ERR("Check your configuration file!");
	}
	
	// Get client ID and MAC
	load_clientid();
	load_MAC(iface);

	// Some configuration checks
	if(VKS_Port_SSL == 0 || VKS_Port_SSL == 0) {
		RETURN_ERR("Check your port configuration!");	
	}
	
	if(strlen(vcasServerAddress) == 0) {
		RETURN_ERR("Check your VCAS server ip!");
	}
	
	if(strlen(vksServerAddress) == 0) {
		RETURN_ERR("Check your VKS server ip!");
	}

	if(strlen(api_clientID) != 56) {
		remove(f_ClientId);
		RETURN_ERR("Incorrect clientID length, length should be 56");	
	}

	if(strlen(clientMAC) != 12) {
		RETURN_ERR("Incorrect MAC length, format should be: \"615243342516\"");
	}

	if(strlen(api_company) == 0) {
		RETURN_ERR("Please add your company name to the configuration");
	}

	return EXIT_SUCCESS;
cleanup:
	if (api_clientID) {
		free(api_clientID);
	}

	if (clientMAC) {
		free(clientMAC);
	}

	return exit_code;
}

int load_keyblock(void) {
	int exit_code = EXIT_FAILURE;
	char retry_count = 0, res, t = 0;

retry:
	// Get Session key from server
	while(API_GetSessionKey() != 0) {
		if (t > 2) {
			RETURN_ERR("GetSessionKey failed");
		}
		sleep(1);
		t++;
	}
	// Give the server some time
	usleep(500 * 1000);
	
	// Read X509 Signed Certificate, if not present or when SKI could not be retrieved request new one
	if (generate_ski_string() < 0) {
		if (API_GetCertificate() < 0) {
			RETURN_ERR("Unable to get Signed Certificate");
		}
		if (generate_ski_string() < 0) {
			RETURN_ERR("Got a Signed Certificate but unable to get SKI");
		}
	}

	printf("Using Subject Key Identifier: %s\n", ski);

	// Give the server some time
	sleep(1);

	// Get the Master Keys
	if(API_GetAllChannelKeys() < 0) {
		printf("GetAllChannelKeys failed\n");
		if(retry_count < 2){
			retry_count += 1;
			printf("Will cleanup and retry in 5 seconds... Retry count: %d\n", retry_count);
			res = remove(f_signedcert);
			res += remove(f_rsa_private_key);
			res += remove(f_csr);
			if(res == 0) {
				sleep(5);
				goto retry;
			} else {
				RETURN_ERR("Unable to remove files, please remove manually");
			}
		}
		goto cleanup;
	}
	
	exit_code = EXIT_SUCCESS;
cleanup:
	if (session_key) {
		free(session_key);
	}
	if (timestamp) {
		free(timestamp);
	}

	return exit_code;
}

