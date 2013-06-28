/*
 * test_live.h
 *
 *  Created on: Mar 22, 2013
 *      Author: root
 */

#ifndef TEST_LIVE_H_
#define TEST_LIVE_H_
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <tls_handshake.h>
extern RESULT http_rx( yh_socket* );
extern RESULT tls_rx( yh_socket* );
#endif /* TEST_LIVE_H_ */
