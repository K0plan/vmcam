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

#define RETURN_NULL(x) if ((x)==NULL) exit (1)
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); return(-1); }
#define RETURN_TCP(err) if ((err)==-1) { printf("%d", err); return(-1);

int tcp_client_send(unsigned char *msg, uint16_t msglen,
		unsigned char*buf_received, int responsebuflen, const char *s_ipaddr,
		short int s_port) {
	int err;
	int sock;
	int received = 0;
	struct sockaddr_in server_addr;

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	RETURN_ERR(sock, "socket");

	memset(&server_addr, '\0', sizeof(server_addr));
	server_addr.sin_family = AF_INET;

	server_addr.sin_port = htons(s_port); /* Server Port number */

	server_addr.sin_addr.s_addr = inet_addr(s_ipaddr); /* Server IP */

	/* Establish a TCP/IP connection to the client */

	err = connect(sock, (struct sockaddr*) &server_addr, sizeof(server_addr));

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

	printf("Received %d\n", received);

	/* Terminate communication on a socket */
	err = close(sock);
	return received;
}
