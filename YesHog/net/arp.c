/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/

#include "arp.h"

/*!
    \brief: process an arp packet
            We only send reply to requests making
            changes in place
    \param1: pkt, received arp packet
    \param2: len, arp packet len
    \return: error if any. Function also sends
             makes an arp reply modifying pkt
*/
RESULT arp_process( BYTE* pkt, SHORT len )
{
    if( len < sizeof( arp_packet ) )
    {
        return ARP_PKT_TOO_SMALL;
    }

    BYTE tmp_mac[ 6 ];
    BYTE tmp_ip [ 4 ];

    arp_packet_p apk = (arp_packet_p) pkt;

    /* debug */
    printf( "ARP IP [%u.%u.%u.%u] ",
           apk->target_proto[0], apk->target_proto[1],
           apk->target_proto[2], apk->target_proto[3] );
    printf( "MY IP [%u.%u.%u.%u ]",
           __IP[0], __IP[1],
           __IP[2], __IP[3] );
    /* end debug */

    
    if( memcmp( apk->target_proto,
                __IP, 4 ) )
    {
        printf( " is Not for ME\r\n" );
        return OK;
    }

    if( apk->oper == ARP_REQUEST )
    {
        apk->oper = ARP_REPLY;
    } else {
        /* we are not interested in
           a reply */
        return OK;
    }

    /* MAC and IP can be easily spoofed
       but we are compiled with _CHECK_TRUSTED
    */
#ifdef _CHECK_TRUSTED
    if( memcmp( apk->sender_mac,
            __TRUSTED_MAC, 6 ) )
        return ARP_PKT_SRC_MAC_UNTRUSTED;

    if( memcmp( apk->sender_proto,
             __TRUSTED_IP, 4 ) )
        return ARP_PKT_SRC_IP_UNTRUSTED;
#endif
    /* debug */
    printf( " is ME, sending reply\r\n");
    /* end debug */
    /* simply reverse */
    memcpy( tmp_mac, apk->sender_mac, 6 );
    memcpy( apk->sender_mac,   __MAC, 6 );
    memcpy( apk->target_mac, tmp_mac, 6 );
    memcpy( tmp_ip, apk->sender_proto, 4 );
    memcpy( apk->sender_proto, __IP, 4 );
    memcpy( apk->target_proto, tmp_ip, 4 );
    return ARP_PKT_SEND_RESPONSE;
}
