/**
 * Copyright (C) 2011-2012 Unix Solutions Ltd.
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

#include <string.h>
#include <stdio.h>

#include <openssl/md5.h>

#include "crc32.h"
#include "cs378x.h"

#define CAMD35_HDR_LEN (20)
#define CAMD35_BUF_LEN (CAMD35_HDR_LEN + 256 + 16)

int32_t boundary(int32_t exp, int32_t n) {
	return ((((n - 1) >> exp) + 1) << exp);
}

uint8_t *init_4b(uint32_t val, uint8_t *b) {
	b[0] = (val >> 24) & 0xff;
	b[1] = (val >> 16) & 0xff;
	b[2] = (val >> 8) & 0xff;
	b[3] = (val) & 0xff;
	return b;
}
uint8_t *init_2b(uint32_t val, uint8_t *b) {
	b[0] = (val >> 8) & 0xff;
	b[1] = (val) & 0xff;
	return b;
}

int cs378x_init(struct cs378x *c, const unsigned char* user, const unsigned char* pass) {
	unsigned char dump[16];
	
	c->auth_token = crc32(0L, MD5((unsigned char *)user, strlen(user), dump), 16);
	MD5((unsigned char *)pass, strlen(pass), dump);

	AES_set_encrypt_key(dump, 128, &c->aes_encrypt_key);
	AES_set_decrypt_key(dump, 128, &c->aes_decrypt_key);
}

int cs378x_handle(struct cs378x *c, int32_t (*f)(unsigned char*, unsigned char*)) {
	unsigned char data[CAMD35_BUF_LEN];
	unsigned char dcw[32];
	int data_len;
	
	if (cs378x_recv(c, data) == -1)
		return -1;

	if (data[0] == 0x00) {
		short service_id = (data[8] << 8) | data[9];
		short ca_id = (data[10] << 8) | data[11];
		int provider_id = (((data[12] << 24) | (data[13] << 16) | (data[14]<<8) | data[15]) & 0xffffffffL);
		short message_id = (data[16] << 8) | data[17];
		printf("Request %d:%d %d %d\n", service_id, ca_id, provider_id, message_id);
		
		f(dcw, data+CAMD35_HDR_LEN);
		
		memset(data, 0, CAMD35_HDR_LEN);
		memset(data + CAMD35_HDR_LEN, 0xff, CAMD35_BUF_LEN - CAMD35_HDR_LEN);
		
		data_len = 32;
		data[0] = 0x01;
		init_2b(ca_id, data + 10);
		init_2b(message_id, data + 16);
		memcpy(data + CAMD35_HDR_LEN, dcw, data_len);
		
		cs378x_send(c, data, data_len);
	}
}

int cs378x_recv(struct cs378x *c, unsigned char* data) {
	int ret;
	int data_len = 256;
	int i;
	uint32_t auth_token;
	
	if (!read(c->client_fd, data, 4))
		return -1;
	
	auth_token = (((data[0] << 24) | (data[1] << 16) | (data[2]<<8) | data[3]) & 0xffffffffL);

	if (auth_token != c->auth_token) {
		printf("Auth key is not valid %u != %u\n", auth_token, c->auth_token);
		return -1;
	}
	
	for (i = 0; i < data_len; i += 16) { // Read and decrypt payload
		if (!read(c->client_fd, (char *)data + i, 16))
			return -1;
		
		AES_decrypt(data + i, data + i, &c->aes_decrypt_key);
		if (i == 0)
			data_len = boundary(4, data[1] + 20); // Initialize real data length
	}
}

int cs378x_send(struct cs378x *c, unsigned char* data, int data_len) {
	unsigned char token[4];
	int i;
	
	init_4b(c->auth_token, token);
	write(c->client_fd, token, 4);
		
	data[1] = data_len;

	init_4b(crc32(0L, data + CAMD35_HDR_LEN, data_len), data + 4);
		
	data_len += CAMD35_HDR_LEN;
	for (i = 0; i < data_len; i += 16) // Encrypt payload
		AES_encrypt(data + i, data + i, &c->aes_encrypt_key);
		
	write(c->client_fd, data, boundary(4, data_len));
}