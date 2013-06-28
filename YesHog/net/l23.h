/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/

#include "arp.h"
#include "ip.h"
#include "tcp.h"

/* Offsets */
#define ETH_DST_MAC(x)            0x00 + x
#define ETH_SRC_MAC(x)            0x06 + x
#define ETH_PKT_TYPE_OFFSET       0x0C
#define ETH_PKT_DATA_OFFSET       0x0E
#define ETH_PKT_TYPE_ARP        0x0806
#define ETH_PKT_TYPE_IP         0x0800
#define ETH_PKT_BROADCAST       "\xFF\xFF\xFF\xFF\xFF\xFF"
#define ETH_TYPE_TCPIP               1
#define ETH_TYPE_APP_DATA            2
/* structs */

RESULT process_arp_pkt( BYTE*, SHORT );
RESULT process_ip_pkt( BYTE**, SHORT );
RESULT process_rx( BYTE**, SHORT );
RESULT send_packet( yh_socket*, BYTE );
extern RESULT ip_process( ip_header_p, SHORT );
extern RESULT snd_packet( BYTE*, SHORT );

#define eth_plug_mac( e, m )     \
    memcpy( e->dst, e->src, 6 ); \
    memcpy( e->src, m, 6 )
