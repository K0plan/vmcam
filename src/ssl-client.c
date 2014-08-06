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

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "log.h"

#define RETURN_NULL(x) if ((x)==NULL) exit (1)
#define RETURN_ERR(err,s) if (err<0) { LOG(ERROR, "[ssl-client] %s", s); return(-1); }
#define RETURN_SSL(err) if (err<0) { LOG(ERROR, "[ssl-client] error: %d", err); return(-1); }

//static int verify_callback(int ok, X509_STORE_CTX *ctx);

#define RSA_CLIENT_CERT       "client.crt"
#define RSA_CLIENT_KEY  "client.key"

//#define RSA_CLIENT_CA_CERT      "client_ca.crt"
#define RSA_CLIENT_CA_PATH      "sys$common:[syshlp.examples.ssl]"

#define ON      1
#define OFF     0

int verify_client = OFF; /* To verify a client certificate, set ON */

X509 *server_cert;
EVP_PKEY *pkey;

void ssl_client_init() {
	/* Load encryption & hashing algorithms for the SSL program */
	SSL_library_init();

	/* Load the error strings for SSL & CRYPTO APIs */
	SSL_load_error_strings();

}

int ssl_client_send(unsigned char * msg, uint16_t msglen,
		unsigned char*buf_received, uint16_t responsebuflen, const char *s_addr,
		short int s_port) {
	SSL_CTX *ctx;
	SSL *ssl_sock;
	int err;
	int sock;
	int datarecv;
	/* Use getaddrinfo to get server address */
	char port_str[7];
	struct addrinfo *aires;
	struct addrinfo hints = {0};
	const struct addrinfo *ai;
	/* Create an SSL_METHOD structure (choose an SSL/TLS protocol version) */
	const SSL_METHOD *meth = TLSv1_method();
	char *str;
	/* Create an SSL_CTX structure */
	ctx = SSL_CTX_new(meth);

	RETURN_NULL(ctx);

	/* Load the RSA CA certificate into the SSL_CTX structure */
	/* This will allow this client to verify the server's     */
	/* certificate.                                           */

	/*if (!SSL_CTX_load_verify_locations(ctx, RSA_CLIENT_CA_CERT, NULL)) {
	 ERR_print_errors_fp(stderr);
	 exit(1);
	 }
	 */
	/* Set flag in context to require peer (server) certificate */
	/* verification */

	//SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	//SSL_CTX_set_verify_depth(ctx, 1);
	/* ------------------------------------------------------------- */

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

	/* ----------------------------------------------- */
	/* An SSL structure is created */

	ssl_sock = SSL_new(ctx);

	RETURN_NULL(ssl_sock);

	/* Assign the socket into the SSL structure (SSL and socket without BIO) */
	SSL_set_fd(ssl_sock, sock);

	/* Perform SSL Handshake on the SSL client */
	err = SSL_connect(ssl_sock);

	RETURN_SSL(err);

	/* Informational output (optional) */
	LOG(DEBUG, "[ssl-client] SSL connection using %s", SSL_get_cipher(ssl_sock));

	/* Get the server's certificate (optional) */
	server_cert = SSL_get_peer_certificate(ssl_sock);

	if (server_cert != NULL) {
		LOG(VERBOSE, "[ssl-client] Server certificate:");

		str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
		RETURN_NULL(str);
		LOG(VERBOSE, "\t subject: %s", str);
		free(str);

		str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
		RETURN_NULL(str);
		LOG(VERBOSE, "\t issuer: %s", str);
		free(str);

		X509_free(server_cert);

	} else
		LOG(DEBUG, "[ssl-client] The SSL server does not have certificate.");

	/*-------- DATA EXCHANGE - send message and receive reply. -------*/
	/* Send data to the SSL server */
	err = SSL_write(ssl_sock, msg, msglen);

	RETURN_SSL(err);

	/* Receive data from the SSL server */

	err = SSL_read(ssl_sock, buf_received, responsebuflen);

	RETURN_SSL(err);

	datarecv = err;

	LOG(DEBUG, "[ssl-client] Received %d", datarecv);

	/*--------------- SSL closure ---------------*/
	/* Shutdown the client side of the SSL connection */
	err = SSL_shutdown(ssl_sock);
	RETURN_SSL(err);

	/* Terminate communication on a socket */
	err = close(sock);

	RETURN_ERR(err, "close");

	/* Free the SSL structure */
	SSL_free(ssl_sock);

	/* Free the SSL_CTX structure */
	SSL_CTX_free(ctx);
	return datarecv;
}
