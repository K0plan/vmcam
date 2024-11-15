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
 */

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <net/if.h>   // ifreq
#include <net/if_arp.h>

#include "vm_api.h"
#include "ssl-client.h"
#include "tcp-client.h"
#include "base64.h"
#include "log.h"
#include "var_func.h"

#define uchar unsigned char
#define GETKEYS_BUFFSIZE (1024 * 100)

#define RETURN_ERR(s) LOG(ERROR, "[API] %s", s); goto cleanup;

// Данные подключения
char *vcasServerAddress = NULL;     // Адрес VCAS сервера
char *vksServerAddress = NULL;      // Адрес VKS сервера
int VCAS_Port_SSL = 0;              // Порт VCAS
int VKS_Port_SSL = 0;               // Основной порт VKS

// API данные
char *api_company = NULL;           // Название компании
int api_msgformat;

// Данные сертификата
const char *szAddress = "6650 Lusk Blvd, Suite B203";
const char *szZipCode = "92021";
const char *szCountry = "US";
const char *szProvince = "CA";
const char *szCity = "San Diego";
const char *szOrganization = "vr2.3.1-candidate-amino-A130.11-hwonly";
const char *szCommon = "STB";
const char *szTelephone = "858-677-7800";
const char *szChallengePassword = "VODPassword";
char *szEmail = NULL;

// Данные клиента
char api_clientID[13];
char api_machineID[64];

// Данные сессии
uchar *session_key = NULL;
uchar *timestamp = NULL;
char *ski = NULL;

// Файлы, используемые
char *f_signedcert = NULL;
char *f_csr = NULL;
char *f_rsa_private_key = NULL;
char *f_keyblock = NULL;
char *f_dir = NULL;

char* strconcat(char* str1, char* str2) {
    int length = strlen(str1) + strlen(str2) + 1;
    char* result = malloc(length);
    if (result == NULL) {
        LOG(ERROR, "[API] Not enough memory");
        exit(-1);
    }

    strncpy(result, str1, strlen(str1)+1);
    strncat(result, str2, strlen(str2)+1);
    return result;
}

/**
 * addHeader() prepends a header to @msg according to @version
 * @param msg char** to which the header should be prepended
 * @param version int protocol version to use
 * @return int length of message with header
 */
int addHeader(char** msg, int version) {
    if (version == 1155) {
        char header[12];
        int len = 11 + strlen(*msg);
        sprintf(header, "1155~%05i~", len);
        char* oldmsg = *msg;
        *msg = strconcat(header, *msg);
        free(oldmsg);
        return len;
    } else if (version == 1154) {
        char header[] = "1154~";
        char* oldmsg = *msg;
        *msg = strconcat(header, *msg);
        free(oldmsg);
        return strlen(*msg);        
    }
}

void set_cache_dir(char* dir) {
    if (f_dir != NULL && f_dir[0] != 0) {
        free(f_signedcert);
        free(f_csr);
        free(f_rsa_private_key);
        free(f_keyblock);
    }

    f_signedcert = strconcat(dir, "/SignedCert.der");
    f_csr = strconcat(dir, "/csr");
    f_rsa_private_key = strconcat(dir, "/priv_key.pem");
    f_keyblock = strconcat(dir, "/keyblock");
    f_dir = dir;
}

void vm_config(char* vcas_address, unsigned int vcas_port, char* vks_address,
               unsigned int vks_port, char* company, char* dir, char* amino_mac,
               char* machine_id, int protocolVersion) {
    
    struct stat st = {0};

    if (vcas_address != 0)
        str_realloc_copy(&vcasServerAddress, vcas_address);

    if (vks_address != 0)
        str_realloc_copy(&vksServerAddress, vks_address);

    if (company != 0)
        str_realloc_copy(&api_company, company);

    if (vcas_port > 0)
        VCAS_Port_SSL = vcas_port;

    if (vks_port > 0)
        VKS_Port_SSL = vks_port;

    if (dir != 0)
        set_cache_dir(dir);

    if (amino_mac != 0) {
        memcpy(api_clientID, amino_mac, 13);
    }
    
    if (machine_id != 0) {
        memcpy(api_machineID, machine_id, 64);
    } else if (amino_mac != 0) {
        memcpy(api_machineID, amino_mac, 13);
    }
    
    if (protocolVersion != 0) {
        api_msgformat = protocolVersion;
    }

    if (stat(f_dir, &st) == -1) {
        LOG(ERROR, "[API] Directory %s doesn't exist", f_dir);
    } else if (access(f_dir, W_OK) != 0) {
        LOG(ERROR, "[API] Directory %s isn't writable", f_dir);
        exit(-1);
    }
}

int load_rsa_pkey(RSA ** rsa_priv_key) {
	FILE *fp;
	// Read PEM Private Key
	fp = fopen(f_rsa_private_key, "r");
	if (fp) {
		LOG(DEBUG, "[API] Private key found");
		*rsa_priv_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	} else {
                LOG(DEBUG, "[API] No private key found, generating new key");
                if (generate_rsa_pkey() < 0)
			return -1;

		fp = fopen(f_rsa_private_key, "r");
		*rsa_priv_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	}
	fclose(fp);
	return 0;
}

int generate_signed_hash(uchar ** signed_hash) {
	RSA * rsa_priv_key;
	uchar md5hash[MD5_DIGEST_LENGTH];
	uchar buf[129];
	*signed_hash = calloc(257, 1);
	MD5(timestamp, 19, md5hash);
	unsigned int n = 0;
	if (load_rsa_pkey(&rsa_priv_key) < 0)
		return -1;

	RSA_sign(NID_md5, md5hash, MD5_DIGEST_LENGTH, buf, &n, rsa_priv_key);
	OPENSSL_free(rsa_priv_key);

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

	// 2. set version of x509 req
	x509_req = X509_REQ_new();
	ret = X509_REQ_set_version(x509_req, nVersion);
	if (ret != 1) {
		goto free_all;
	}

	// 3. set subject of x509 req
	x509_name = X509_REQ_get_subject_name(x509_req);

	ret = X509_NAME_add_entry_by_txt(x509_name, "C", V_ASN1_PRINTABLESTRING,
			(const unsigned char*) szCountry, -1, -1, 0);
	if (ret != 1) {
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "ST", V_ASN1_PRINTABLESTRING,
			(const unsigned char*) szProvince, -1, -1, 0);
	if (ret != 1) {
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "L", V_ASN1_PRINTABLESTRING,
			(const unsigned char*) szCity, -1, -1, 0);
	if (ret != 1) {
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "O", V_ASN1_PRINTABLESTRING,
			(const unsigned char*) api_company, -1, -1, 0);
	if (ret != 1) {
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "OU", V_ASN1_PRINTABLESTRING,
			(const unsigned char*) szOrganization, -1, -1, 0);
	if (ret != 1) {
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "CN", V_ASN1_PRINTABLESTRING,
			(const unsigned char*) szCommon, -1, -1, 0);
	if (ret != 1) {
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "emailAddress", V_ASN1_IA5STRING,
			(const unsigned char*) szEmail, -1, -1, 0);
	if (ret != 1) {
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "challengePassword", V_ASN1_PRINTABLESTRING,
			(const unsigned char*) szChallengePassword, -1, -1, 0);
	if (ret != 1) {
		goto free_all;
	}

	// 4. set public key of x509 req
	if (load_rsa_pkey(&rsa_priv_key) < 0)
		goto free_all;

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

	LOG(VERBOSE, "[API] CSR created:%s", *pem_csr);
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

	OPENSSL_free(signed_cert);

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
	char* msg = malloc(128);
        sprintf((char*) msg, "%s~CreateSessionKey~%s~%s~",
			api_clientID, api_company, api_machineID);
	int msglen = addHeader(&msg, api_msgformat);

	LOG(DEBUG, "[API] Requesting Session Key: %s", msg);

	if(ssl_client_send(msg, msglen, response_buffer, 64, vcasServerAddress,
	VCAS_Port_SSL) < 45) {
		return -1;
	}
        free(msg);
	session_key = calloc(16, 1);
	timestamp = calloc(20, 1);
	memcpy(session_key, response_buffer + 4, 16);
	memcpy(timestamp, response_buffer + 20, 20);
	LOG(DEBUG, "[API] Session key obtained, timestamp: %s", timestamp);
	return 0;
}

int API_GetCertificate() {
	FILE * fp;
	const uchar * cert;
	char * csr;
	int response_len;
	int msglen;
	char* msg = malloc(2048);
	uchar * response_buffer = calloc(2048, 1);
	/******* Get the current time64 *******/
	long long unsigned int t64 = (long long unsigned int) time(NULL);

	/******* Generate the CSR *******/
	LOG(DEBUG, "[API] Generating CSR");
	szEmail = calloc(128, 1);
	sprintf(szEmail, "%s.%llu@Verimatrix.com", api_machineID, t64);
	LOG(DEBUG, "[API] Using email: %s", szEmail);
	generate_csr(&csr);
        LOG(DEBUG, "[API] CSR generated, sending...");
	/******* Generate the request string *******/
        sprintf((char*) msg,
                        "%s~getCertificate~%s~NA~NA~%s~%s~%s~ ~%s~%s~%s~%s~%s~%s~%s~%s~",
                        api_clientID, api_company, csr,
                        szCommon, szAddress, szCity, szProvince, szZipCode, szCountry, szTelephone, szEmail,
                        api_machineID, szChallengePassword);
        
        msglen = addHeader(&msg, api_msgformat);
	
	LOG(VERBOSE, "[API] Requesting Certificate: %s", msg);

	/******* Send the request *******/
	response_len = ssl_client_send(msg, msglen, response_buffer, 2048,
	vcasServerAddress, VCAS_Port_SSL);

	if (response_len < 12) {
		free(response_buffer);
                response_buffer = NULL;
		return -1;
	}
        free(msg);

	/******* Get the Signed cert from the response *******/
	cert = response_buffer + 12;

	/******* Write to file *******/
	fp = fopen(f_signedcert, "w");
	fwrite(cert, response_len - 12, 1, fp);
	fclose(fp);

	free(response_buffer);
	free(csr);
        response_buffer = NULL;
        csr = NULL;
	return 0;
}

int API_SaveEncryptedPassword() {
	char* msg = malloc(512);
	uchar * response_buffer = calloc(1024, 1);
	uchar password[65];
	uchar random[32];
	int msglen, retlen, plainlen;
	RC4_KEY rc4key;
	int i;
	char* unencryptedAPICompare = malloc(128);

	if (!RAND_bytes(random, 32)) {
		return -1;
	}

	RC4_set_key(&rc4key, 16, session_key);
	RC4(&rc4key, 32, random, random);

	for(i=0; i<32; i++) {
		sprintf(password + i*2,"%02x", random[i]);
	}
	password[64] = 0;

	if (response_buffer == NULL) {
		LOG(ERROR, "[API] SaveEncryptedPassword failed, unable to allocate memory");
		return -1;
	}

	sprintf((char*) unencryptedAPICompare, "%s~%s~%s~",
			api_company, timestamp, api_machineID);
        plainlen = addHeader(&unencryptedAPICompare, api_msgformat);
	free(unencryptedAPICompare);
        
        sprintf((char*) msg,
			"%s~%s~%s~%s~SaveEncryptedPassword~%s~%s~%d~%s~", 
			api_company, timestamp, api_machineID, api_clientID, api_company, ski, 64, password);
        msglen = addHeader(&msg, api_msgformat); 
                
	LOG(VERBOSE, "[API] Save encryption password: %s", msg);

	RC4_set_key(&rc4key, 16, session_key);
	RC4(&rc4key, msglen - plainlen, msg + plainlen, msg + plainlen);

	retlen = tcp_client_send(msg, msglen, response_buffer, 1024,
	vcasServerAddress, VCAS_Port_SSL+1);
        free(msg);
        
	if (retlen < 8) {
		free(response_buffer);
                response_buffer = NULL;
		return -1;
	}

	LOG(DEBUG, "[API] SaveEncryptedPassword completed, size: %d", retlen);

	free(response_buffer);
        response_buffer = NULL;
	return 0;
}

int API_GetEncryptedPassword() {
	char* msg = malloc(512);
	uchar * response_buffer = calloc(1024, 1);
	int msglen, retlen, plainlen;
	RC4_KEY rc4key;
	char* unencryptedAPICompare = malloc(128);

	if (response_buffer == NULL) {
		LOG(ERROR, "[API] GetEncryptedPassword failed, unable to allocate memory");
		return -1;
	}

	sprintf((char*) unencryptedAPICompare, "%s~%s~%s~",
			api_company, timestamp, api_machineID);
        plainlen = addHeader(&unencryptedAPICompare, api_msgformat);
        free(unencryptedAPICompare);
        
	sprintf((char*) msg,
			"%s~%s~%s~%s~GetEncryptedPassword~%s~%s~",
			api_company, timestamp, api_machineID, api_clientID, api_company, ski);
        
        msglen = addHeader(&msg, api_msgformat);
	
        LOG(VERBOSE, "[API] Get encryption password: %s", msg);

	RC4_set_key(&rc4key, 16, session_key);
	RC4(&rc4key, msglen - plainlen, msg + plainlen, msg + plainlen);

	retlen = tcp_client_send(msg, msglen, response_buffer, 1024,
	vcasServerAddress, VCAS_Port_SSL+1);
        free(msg);

	if (retlen < 8) {
		free(response_buffer);
                response_buffer = NULL;
		return -1;
	}

	RC4_set_key(&rc4key, 16, session_key);
	RC4(&rc4key, retlen-4, response_buffer+4, response_buffer+4);

	LOG(DEBUG, "[API] GetEncryptedPassword: %s", response_buffer+8);

	free(response_buffer);
        response_buffer = NULL;
	return 0;
}

// Добавленная функция для получения единственного ключа канала
int API_GetSingleChannelKey(const char *channel_id) {
    uchar *signedhash = 0;
    char *msg = malloc(512);
    uchar *response_buffer = calloc(GETKEYS_BUFFSIZE, 1);
    uchar *keyblock;
    int msglen, retlen, plainlen;
    RC4_KEY rc4key;
    FILE *fp;
    char *unencryptedAPICompare = malloc(128);

    if (response_buffer == NULL) {
        LOG(ERROR, "[API] GetSingleChannelKey failed, unable to allocate memory");
        return -1;
    }

    sprintf((char*) unencryptedAPICompare, "%s~%s~%s~",
            api_company, timestamp, api_machineID);
    plainlen = addHeader(&unencryptedAPICompare, api_msgformat);
    free(unencryptedAPICompare);
    
    if (generate_signed_hash(&signedhash) < 0) {
        OPENSSL_free(signedhash);
        return -1;
    }

    sprintf((char*) msg,
            "%s~%s~%s~%s~GetSingleChannelKey~%s~%s~",
            api_company, timestamp, api_machineID, api_clientID, channel_id, signedhash);
    
    msglen = addHeader(&msg, api_msgformat);

    LOG(VERBOSE, "[API] GetSingleChannelKey: %s", msg);

    RC4_set_key(&rc4key, 16, session_key);
    RC4(&rc4key, msglen - plainlen, msg + plainlen, msg + plainlen);

    retlen = tcp_client_send(msg, msglen, response_buffer, GETKEYS_BUFFSIZE, 
                             vcasServerAddress, VCAS_Port_SSL + 1);
    free(msg);

    if (retlen < 8) {
        free(response_buffer);
        response_buffer = NULL;
        OPENSSL_free(signedhash);
        return -1;
    }

    RC4_set_key(&rc4key, 16, session_key);
    RC4(&rc4key, retlen - 4, response_buffer + 4, response_buffer + 4);

    LOG(DEBUG, "[API] Channel Key for %s obtained: %s", channel_id, response_buffer + 8);

    fp = fopen(f_keyblock, "w");
    if (fp) {
        fwrite(response_buffer + 8, retlen - 8, 1, fp);
        fclose(fp);
    }

    free(response_buffer);
    OPENSSL_free(signedhash);
    return 0;
}

int init_vmapi() {
	// Init SSL Client
	ssl_client_init();

	int exit_code = EXIT_FAILURE;

	// Some configuration checks
	if(VCAS_Port_SSL == 0 || VKS_Port_SSL == 0) {
		RETURN_ERR("Check your port configuration!");
	}

	if(strlen(vcasServerAddress) == 0) {
		RETURN_ERR("Check your VCAS server ip!");
	}

	if(strlen(vksServerAddress) == 0) {
		RETURN_ERR("Check your VKS server ip!");
	}

	if(strlen(api_clientID) != 12) {
		RETURN_ERR("Incorrect AMINOMAC length, length should be 12");
	}

	if(strlen(api_company) == 0) {
		RETURN_ERR("Please add your company name to the configuration");
	}

	return EXIT_SUCCESS;
cleanup:
	return exit_code;
}

int load_keyblock(const char *channel_id) {
	int exit_code = EXIT_FAILURE;
	char retry_count = 0, res, t = 0;

retry:
	// Получить сессионный ключ от сервера
	while(API_GetSessionKey() != 0) {
		if (t > 2) {
			RETURN_ERR("GetSessionKey failed");
		}
		sleep(1);
		t++;
	}
	// Подождать немного
	usleep(500 * 1000);

	// Чтение X509 подписанного сертификата; запросить новый, если он отсутствует или если SKI не удалось получить
	if (generate_ski_string() < 0) {
		if (API_GetCertificate() < 0) {
			RETURN_ERR("Unable to get Signed Certificate");
		}
		if (generate_ski_string() < 0) {
			RETURN_ERR("Got a Signed Certificate but unable to get SKI");
		}
		if (API_SaveEncryptedPassword() < 0) {
			RETURN_ERR("Unable to save encrypted password");
		}
	} else {
		if (API_GetEncryptedPassword() < 0) {
			RETURN_ERR("Unable to get encrypted password");
		}
	}

	LOG(DEBUG, "[API] Using Subject Key Identifier: %s", ski);

	// Подождать немного
	sleep(1);

	// Получение ключа для единственного канала
	if (API_GetSingleChannelKey(channel_id) < 0) {
		LOG(ERROR, "[API] GetSingleChannelKey failed for channel ID: %s", channel_id);
		if (retry_count < 2) {
			retry_count += 1;
			LOG(INFO, "[API] Will cleanup and retry in 5 seconds... Retry count: %d", retry_count);
			res = remove(f_signedcert);
			res += remove(f_rsa_private_key);
			res += remove(f_csr);
			if (res == 0) {
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
		session_key = NULL;
	}
	if (timestamp) {
		free(timestamp);
		timestamp = NULL;
	}

	return exit_code;
}
