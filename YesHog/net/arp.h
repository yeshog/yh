/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/
#ifndef _ARP_H
#define _ARP_H

#include <common.h>

#define   ARP_REQUEST        1
#define   ARP_REPLY          2
extern    BYTE         __MAC[6];
extern    BYTE          __IP[4];
extern    BYTE __TRUSTED_MAC[6];
extern    BYTE  __TRUSTED_IP[4];

typedef struct arp_packet
{
     /* hardware type */
    BYTE h_type_zero;
    BYTE h_type;

    /* protocol type */
    SHORT p_type;

    /* hw len */
    BYTE  h_len;

    /* protocol len */
    BYTE  p_len;

    /* operation req = 1 repl = 2
       Not sure why it was decided 
       to reserve a SHORT for this */
    BYTE  oper_zero;
    BYTE oper;

    /* Sender hw address */
    BYTE  sender_mac[ 6 ];

    /* Sender proto address */
    BYTE sender_proto[ 4 ];

    /* Target hw address */
    BYTE  target_mac[ 6 ];

    /* Target proto address */
    BYTE target_proto[ 4 ];

} arp_packet, *arp_packet_p;

RESULT arp_process( BYTE*, SHORT );

#endif
