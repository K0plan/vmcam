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
#include "log.h"

const char* user = "user";
const char* pass = "pass";
const char key[14] = {0x01, '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\x09', '\x10', '\x11', '\x12', '\x13', '\x14'};
const int port = 8282;

struct handler {
	int sock;
	void* (*callback)(void*);
};

void *handle_client(void* handle) {
	struct sockaddr_in cli_addr;
	socklen_t sin_len = sizeof(cli_addr);
	struct handler* server = handle;
	pthread_t thread;
	int client_fd;

	while (1) {
		client_fd = accept(server->sock, (struct sockaddr *) &cli_addr, &sin_len);
		if (client_fd == -1) {
			perror("[VMCAM] Can't accept");
			continue;
		}

		LOG(INFO, "[VMCAM] Got connection");
		pthread_create(&thread, NULL, server->callback, &client_fd);
	}
}

void *handle_client_newcamd(void* client_fd) {
	int fd = *((int*) client_fd);
	struct newcamd c;

	c.client_fd = fd;
	newcamd_init(&c, user, pass, key);
	while (newcamd_handle(&c, keyblock_analyse_file) != -1);
	LOG(INFO, "[VMCAM] Connection closed");

	close(fd);
}

void *handle_client_cs378x(void* client_fd) {
	int fd = *((int*) client_fd);
	struct cs378x c;

	c.client_fd = fd;
	cs378x_init(&c, user, pass);
	while (cs378x_handle(&c, keyblock_analyse_file) != -1);
	LOG(INFO, "[VMCAM] Connection closed");

	close(fd);
}

int open_socket(char* interface, int port) {
	int one = 1;
	struct sockaddr_in svr_addr;
	int sock = socket(AF_INET, SOCK_STREAM, 0);

	if (sock < 0)
		err(1, "[VMCAM] Can't open socket");

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));

	svr_addr.sin_family = AF_INET;
	svr_addr.sin_addr.s_addr = INADDR_ANY;
	svr_addr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr *) &svr_addr, sizeof(svr_addr)) == -1) {
		close(sock);
		err(1, "[VMCAM] Can't bind on port %d for %s", port, interface);
	}

	listen(sock, 5);
	LOG(INFO, "[VMCAM] Start %s server on port %d", interface, port);

	return sock;
}

int main(int argc, char *argv[]) {
	int ret;
	int i;
	int usage = 0;
	int sock;
	unsigned int port_cs378x = 15080;
	unsigned int port_newcamd = 15050;
	char* iface = "eth0";
	char* config = "vmcam.ini";
	struct handler newcamd_handler, cs378x_handler;
	pthread_t thread;

	debug_level = 0;

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
		} else if (strcmp(argv[i], "-pn") == 0) {
			if (i+1 >= argc) {
				printf("Need to provide a Newcamd port number\n");
				return -1;
			}
			port_newcamd = atoi(argv[i+1]);
			i++;
		} else if (strcmp(argv[i], "-pc") == 0) {
			if (i+1 >= argc) {
				printf("Need to provide a CS378x port number\n");
				return -1;
			}
			port_cs378x = atoi(argv[i+1]);
			i++;
		} else if (strcmp(argv[i], "-d") == 0) {
			if (i+1 >= argc) {
				printf("Need to provide a debug level\n");
				return -1;
			}
			debug_level = atoi(argv[i+1]);
			i++;
		} else {
			printf("Unknown option '%s'\n", argv[i]);
			usage = 1;
		}
	}

	if (port_cs378x == 0 && port_newcamd)
		err(1, "[VMCAM] Both CS378x and Newcamd are disabled");

	if (usage) {
		printf("Usage: vmcam -i [interface] -c [configfile] %d\n");
		printf("\t-i [interface]\tName of interface to connect to server [default: eth0]\n");
		printf("\t-c [configfile]\tVCAS configfile [default: vmcam.ini]\n");
		printf("\t-pn [Newcamd port]\tSet Newcamd port number or 0 to disable [default: 15050]\n");
		printf("\t-pc [CS378x port]\tSet CS378x port number or 0 to disable [default: 15080]\n");
		printf("\t-d [debug level]\tSet debug level [default: 0]\n");
		return -1;
	}

	if ((ret = init_vmapi(config, iface)) == EXIT_FAILURE)
		return ret;
	
	if ((ret = load_keyblock()) == EXIT_FAILURE)
		return ret;

	if (port_newcamd > 0) {
		newcamd_handler.sock = open_socket("Newcamd", port_newcamd);
		newcamd_handler.callback = handle_client_newcamd;
		pthread_create(&thread, NULL, handle_client, &newcamd_handler);
	}

	if (port_cs378x > 0) {
		cs378x_handler.sock = open_socket("CS378x", port_cs378x);
		cs378x_handler.callback = handle_client_cs378x;
		pthread_create(&thread, NULL, handle_client, &cs378x_handler);
	}
	
	while (1) {
		LOG(INFO, "[VMCAM] Next keyblock update in %d seconds", key_interval);
		sleep(key_interval);
		load_keyblock();
	}
}