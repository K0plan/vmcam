/*
 * ssl-client.h
 *
 *  Created on: Jul 1, 2014
 *      Author: root
 */

#ifndef SSL_CLIENT_H_
#define SSL_CLIENT_H_

int ssl_client_send(unsigned char *msg, uint16_t msglen, unsigned char*buf_received,uint16_t responselen,
		const char *s_addr, short int s_port);
void ssl_client_init();



#endif /* SSL_CLIENT_H_ */
