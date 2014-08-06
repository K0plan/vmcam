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
#include <openssl/des.h>

struct newcamd {
	int client_fd;
	DES_key_schedule ks1, ks2;
	char key[14];
	char* pass;
	char* user;
};

int newcamd_init(struct newcamd *c, const unsigned char* user, const unsigned char* pass, const unsigned char* key);
int newcamd_handle(struct newcamd *c, int32_t (*f)(unsigned char*, unsigned char*));

int newcamd_recv(struct newcamd *c, unsigned char* data, uint16_t* service_id, uint16_t* msg_id, uint32_t* provider_id);
int newcamd_send(struct newcamd *c, unsigned char* data, int data_len, uint16_t service_id, uint16_t msg_id, uint32_t provider_id);
