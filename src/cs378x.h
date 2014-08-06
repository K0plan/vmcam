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

#include <stdint.h>

#include <openssl/aes.h>

struct cs378x {
	int client_fd;
	AES_KEY aes_encrypt_key;
	AES_KEY aes_decrypt_key;
	uint32_t auth_token;
	uint16_t msg_id;
};

int cs378x_init(struct cs378x *c, const unsigned char* user, const unsigned char* pass);
int cs378x_handle(struct cs378x *c, int32_t (*f)(unsigned char*, unsigned char*));

int cs378x_recv(struct cs378x *c, unsigned char* data);
int cs378x_send(struct cs378x *c, unsigned char* data, int data_len);
