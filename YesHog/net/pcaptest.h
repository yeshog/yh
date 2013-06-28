/*
 * pcaptest.h
 *
 *  Created on: Mar 21, 2013
 *      Author: ynagarkar
 */

#ifndef PCAPTEST_H_
#define PCAPTEST_H_
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <pcap.h>
#include <stdint.h>

#define PCAP_NO_ERR 0
#define PCAP_OOM_ERR -1
#define PCAP_OPEN_OFFLINE_ERR -2
#define PCAP_OPEN_DEAD_ERR -3
#define PCAP_DUMP_OPEN_ERR -4
#define PCAP_INDX_NT_FOUND_ERR -5
#define PCAP_DUMP_NOT_INITIALIZED -6
#define PCAP_READ_PKT_PRIOR_ERRS -50
#define MAX_LEN 65535

typedef struct yh_pcap {
    pcap_t *pcap_in;
    pcap_t *pcap_out;
    pcap_dumper_t *pcap_dumper;
    uint32_t cli_tcp_ack;
    int err;
} yh_pcap, *yh_pcap_p;

yh_pcap_p yh_pcap_init( char*, char* );
void yh_pcap_append_pkt( yh_pcap_p, u_char*, int );
void yh_pcap_close( yh_pcap_p );
extern uint32_t get_initial_seq(void);
#endif /* PCAPTEST_H_ */
