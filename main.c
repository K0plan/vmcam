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

#include "cs378x.h"
#include "keyblock.h"
#include "vm_api.h"

const char* user = "user";
const char* pass = "pass";
const int port = 8282;

void *handle_client(void* client_fd) {
	int fd = *((int*) client_fd);
	struct cs378x c;

	c.client_fd = fd;
	cs378x_init(&c, user, pass);
	while (cs378x_handle(&c, keyblock_analyse_file) != -1);

	close(fd);
}

void *reload_keyblock() {
	while (1) {
		sleep(60 * 60 * 24);
		load_keyblock();
	}
}
 
int main() {
	int ret;
	int one = 1, client_fd;
	struct sockaddr_in svr_addr, cli_addr;
	socklen_t sin_len = sizeof(cli_addr);
	pthread_t thread;
	
	if ((ret = init_vmapi()) == EXIT_FAILURE)
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
		
		pthread_create(&thread, NULL, handle_client, &client_fd);
	}
}