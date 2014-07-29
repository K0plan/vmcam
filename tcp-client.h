/*
 * ssl-client.h
 *
 *  Created on: Jul 1, 2014
 *      Author: root
 */

#ifndef TCP_CLIENT_H_
#define TCP_CLIENT_H_

int tcp_client_send(unsigned char *msg, uint16_t msglen,
		unsigned char*buf_received, int responselen, const char *s_addr,
		short int s_port);

#endif /* SSL_CLIENT_H_ */
