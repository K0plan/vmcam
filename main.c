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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <err.h>
#include <string.h>
#include <pthread.h>

#include "newcamd.h"
#include "cs378x.h"
#include "keyblock.h"
#include "vm_api.h"

const char* user = "user";
const char* pass = "pass";
const char key[14] = {0x01, '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\x09', '\x10', '\x11', '\x12', '\x13', '\x14'};
const int port = 8282;

void *handle_client_newcamd(void* client_fd) {
	int fd = *((int*) client_fd);
	struct newcamd c;

	c.client_fd = fd;
	newcamd_init(&c, user, pass, key);
	while (newcamd_handle(&c, keyblock_analyse_file) != -1);
	printf("Connection closed");

	close(fd);
}

void *handle_client_cs378x(void* client_fd) {
	int fd = *((int*) client_fd);
	struct cs378x c;

	c.client_fd = fd;
	cs378x_init(&c, user, pass);
	while (cs378x_handle(&c, keyblock_analyse_file) != -1);
	printf("Connection closed");

	close(fd);
}

void *reload_keyblock() {
	while (1) {
		sleep(60 * 60 * 24);
		load_keyblock();
	}
}
 
int main(int argc, char *argv[]) {
	int ret;
	int i;
	int usage = 0;
	int one = 1, client_fd;
	char* iface = "eth0";
	char* config = "vmcam.ini";
	int protocol = 0;
	struct sockaddr_in svr_addr, cli_addr;
	socklen_t sin_len = sizeof(cli_addr);
	pthread_t thread;

	printf("VMCam - VCAS SoftCAM for IPTV\n");

	for (i = 1; i < argc && usage == 0; i++) {
		if (strcmp(argv[i], "-i") == 0) {
			if (i+1 >= argc) {
				printf("Need to provide a interface\n");
				return -1;
			}
			iface = argv[i+1];
			i++;
		} else if (strcmp(argv[i], "-c") == 0) {
			if (i+1 >= argc) {
				printf("Need to provide a configfile\n");
				return -1;
			}
			config = argv[i+1];
			i++;
		} else if (strcmp(argv[i], "-C") == 0) {
			if (i+1 >= argc) {
				printf("Need to provide a CAMD network protocol (CS378X/NEWCAMD)\n");
				return -1;
			}
			if (strcasecmp(argv[i+1], "CS378X") == 0) {
				protocol = 0;
			} else if (strcasecmp(argv[i+1], "NEWCAMD") == 0) {
				protocol = 1;
			}
			i++;
		} else {
			printf("Unknown option '%s'\n", argv[i]);
			usage = 1;
		}
	}

	if (usage) {
		printf("Usage: vmcam -i [interface] -c [configfile] %d\n");
		printf("\t-i [interface]\tName of interface to connect to server [default: eth0]\n");
		printf("\t-c [configfile]\VCAS configfile [default: vmcam.ini]\n");
		printf("\t-C [camd interface]\tSet CAMD network protocol (CS378X / NEWCAMD) [default: CS378X]\n");
		return -1;
	}

	if ((ret = init_vmapi(config, iface)) == EXIT_FAILURE)
		return ret;
	
	if ((ret = load_keyblock()) == EXIT_FAILURE)
		return ret;

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	err(1, "[SERVER] Can't open socket");

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));

	svr_addr.sin_family = AF_INET;
	svr_addr.sin_addr.s_addr = INADDR_ANY;
	svr_addr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr *) &svr_addr, sizeof(svr_addr)) == -1) {
		close(sock);
		err(1, "[SERVER] Can't bind");
	}

	listen(sock, 5);
	printf("[SERVER] Start VMCam server on port %d\n", port);
	
	pthread_create(&thread, NULL, reload_keyblock, NULL);
	
	while (1) {
		client_fd = accept(sock, (struct sockaddr *) &cli_addr, &sin_len);
		if (client_fd == -1) {
			perror("[SERVER] Can't accept");
			continue;
		}

		printf("[SERVER] Got connection\n");
		
		if (protocol == 0)
			pthread_create(&thread, NULL, handle_client_cs378x, &client_fd);
		else if (protocol == 1)
			pthread_create(&thread, NULL, handle_client_newcamd, &client_fd);
	}
}