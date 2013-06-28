#ifndef _NET_TEST_H
#define _NET_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include "pcaptest.h"
#include "test_live.h"

extern yh_socket conn;
extern BYTE __MAC[6];
extern SHORT __MYPORT;

#define ip_hdr_addr_to_str_fmt( x )    \
            *(  (BYTE*) (&(x) ))     , \
            *(( (BYTE*) (&(x)) + 1 )), \
            *(( (BYTE*) (&(x)) + 2 )), \
            *(( (BYTE*) (&(x)) + 3 ) )

typedef struct test_pkt
{
    ip_header_p iph;
    SHORT ipl;
    tcp_header_p tcph;
    SHORT tcpl;
} test_pkt, *test_pkt_p;

int test_live(void);
#endif
