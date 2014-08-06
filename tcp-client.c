/*
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#ifdef __VMS
#include <socket.h>
#include <inet.h>

#include <in.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "log.h"

#define RETURN_NULL(x) if ((x)==NULL) exit (1)
#define RETURN_ERR(err,s) if ((err)==-1) { LOG(ERROR, "[tcp-client] %s", s); return(-1); }
#define RETURN_TCP(err) if ((err)==-1) { LOG(ERROR, "[tcp-client] error: %d", err); return(-1);

int tcp_client_send(unsigned char *msg, uint16_t msglen,
		unsigned char*buf_received, int responsebuflen, const char *s_addr,
		short int s_port) {
	int err;
	int sock;
	int received = 0;
	/* Use getaddrinfo to get server address */
	char port_str[7];
	struct addrinfo *aires;
	struct addrinfo hints = {0};
	const struct addrinfo *ai;

	/* Establish a TCP/IP connection to the SSL client */

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	snprintf(port_str, 7, "%d", s_port);
	err = getaddrinfo(s_addr, port_str, &hints, &aires);
	RETURN_ERR(err, "getaddrinfo");

	ai = aires;
	for (;ai != NULL &&
		((sock = socket(ai->ai_family, ai->ai_socktype, 0)) < 0 ||
		(err = connect(sock, ai->ai_addr, ai->ai_addrlen)) < 0);
		close(sock), sock = 0, ai = ai->ai_next);

	freeaddrinfo(aires);

	RETURN_ERR(sock, "socket");
	RETURN_ERR(err, "connect");

	err = write(sock, msg, msglen);
	if (err < 0)
		RETURN_ERR(err, "ERROR writing to socket");

	do {
		err = read(sock, &buf_received[received], 1024);
		received += err;
	} while (err > 0);

	if (err < 0)
		RETURN_ERR(err, "ERROR reading from socket");

	LOG(DEBUG, "[tcp-client] Received %d", received);

	/* Terminate communication on a socket */
	err = close(sock);
	return received;
}
