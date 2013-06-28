/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/
#include "l234.h"
extern SHORT __MYPORT;
/*!
  TCP State is maintained via sock->state which is SM + FLAGS

  The first 0-B flags map into 0-B of tcp_header->flags
  SNT Marks a sent packet with ACK expected
  EST Marks connection established. Although ACK
      is sufficient to mark connection establishment
  XXX Unused state that can be used in the future for XXX
  Remember when and only when a SYN or TX gets acked
  the seq is incremented.
  Also our tcp hardly guarantees reliability, thats
  because we simply overwrite the packet and dont store
  earlier packets for retransmission to save memory.
  +---------------------------------------------------------------+
  | F   E   D   C   B   A   9   8   7   6   5   4   3   2   1   0 |
  |BUS|XXX|XXX|EST|RES|RES|RES|NON|CWR|ECN|URG|ACK|PSH|RST|SYN|FIN|
  +---------------------------------------------------------------+
                                        Seq Ack
    STATE SYN         C-->S Syn received 0   0
    STATE SYN|ACK     C<--S SynAck       0   1   nxt = 1
    STATE ACK         C-->S Ack          1   1   seq = nxt
    STATE EST|ACK     C-->S Ack,RX(334)  1   335 ack += RX set
    STATE EST|ACK     C<--S Ack 335      1   335 Send Ack
    STATE EST|ACK C<--S TX(385),Ack      1   335 Set SNT
    STATE EST|ACK     C-->S Ack 386              Set seq += TX
    STATE EST|ACK     C-->S Ack,RX(285) 386  620 Set ack += RX
*/

#define    TCP_HANDSHAKE_ACK              1
#define    TCP_INITIAL                    0x00
#define    TCP_SYN                        0x02
#define    TCP_SYN_ACK                    0x12
#define    TCP_ACK                        0x10
#define    TCP_CON_EST                    0x1010
#define    TCP_CON_BUSY                   0x8000
#define    TCP_FLMASK                     0xF017
/* We dont give a rats's a$$ about these flags */
#define    TCP_WINDOW_SCALING_OPT         "\x03\x03"
#define    TCP_SACK                       "\x04\x02"
#define sock_zero( x ) memset( x, 0, sizeof( yh_socket ) )

RESULT tcp_process( yh_socket* );
SHORT tcp_checksum( yh_socket* );
SHORT pchksum( WORD, void*, SHORT );
RESULT tcp_check_flow( yh_socket* );
RESULT tcp_syn_ack( yh_socket* );
RESULT tcp_app_process( yh_socket* );
RESULT register_app( yh_socket*, yh_app, BYTE );
SHORT get_id(void);
void set_initial_seq( WORD );
WORD get_initial_seq( void );
yh_socket* tcp_get_sock( ip_header_p );
RESULT resize_tx( yh_socket*, SHORT );
RESULT tcp_handle_opts( yh_socket* );
RESULT tcp_err_cleanup( yh_socket*, RESULT );
