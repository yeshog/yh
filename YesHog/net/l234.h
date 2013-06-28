/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/
#ifndef L234_H_
#define L234_H_

#define MAX_APPS 1

typedef struct eth_frame {
    BYTE dst[6];
    BYTE src[6];
    SHORT typ;
} eth_frame, *eth_frame_p;

typedef struct ip_header
{
    BYTE version_and_hdrlen;
    BYTE dscp_and_ecn;
    SHORT data_len;
    SHORT id;
    SHORT flags_and_frag_offset;
    BYTE ttl;
    BYTE protocol;
    SHORT csum;
    WORD src;
    WORD dst;
} ip_header, *ip_header_p;

typedef struct tcp_header
{
    SHORT src_port;
    SHORT dst_port;
    WORD  seq;
    WORD  ack;
    BYTE  data_offset_ns;
    BYTE  flags;
    SHORT window_sz;
    SHORT csum;
    SHORT urgent_ptr;
} tcp_header, *tcp_header_p;

typedef struct pseudo_hdr
{
    WORD ph_src_addr;
    WORD ph_dest_addr;
    BYTE ph_zero;
    BYTE ph_protocol;
    SHORT ph_len;
} pseudo_hdr, *pseudo_hdr_p;

#define TX_TYPE_NONE 0
#define TX_TYPE_ACK  1
#define TX_TYPE_APP  2
/*!
  \brief: socket structure. Keeps just about everything
           needed by l2,l3,l4
  \note:  size matters: 338 bytes (x86 upper limit)
*/
typedef struct tcp_yh_socket
{
    WORD src;                            /*< ip                */
    WORD dst;                            /*< ip                */
    SHORT src_port;                      /*<                   */
    SHORT dst_port;                      /*<                   */
    WORD seq;                            /*< whaddyathink      */
    WORD ack;                            /*< tcp ack num       */
    WORD nxt;                            /*< expect to be acked*/
    SHORT id;                            /*< if we ever have >1*/
    SHORT  state;                        /*< sock state        */
    SHORT txid;                          /*< WTF#2             */
    SHORT rxid;                          /*< WTF               */
    SHORT rxlen;                         /* cannot change      */
    SHORT txlen;                         /*< can be < pkt_len  */
    BYTE** pktp;                         /*< entire eth frame  */
    SHORT pkt_len;                       /*< tx/rx pkt size    */
    tcp_header_p tcph;                   /*< tcp header        */
    SHORT tcpl;                          /*< tcp header len    */
    ip_header_p  iph;                    /*< ip header         */
    SHORT ipl;                           /*< ip header len     */
    BYTE* app;                           /*< l5 app data       */
    SHORT applen;                        /*< l5 len            */
    BYTE tx_type;                        /*< ACK or APP        */
    /* yh config sec data size */
    BYTE opaque_sec_data[MAX_OPAQUE_SEC_DATA_SZ]; /*< tls data */
    /* end yh config sec data size */
    RESULT (*apps [MAX_APPS]) (struct tcp_yh_socket*);
                                         /*< tcp app callbacks */
    RESULT (*resize_cb) (struct tcp_yh_socket*, SHORT);
                                            /* resize callback */
    BYTE   err_num;                      /*< ctr for err_stack */
    RESULT err_stack[MAX_ERR_STACK];     /*< err/warning       */
} yh_socket;

typedef RESULT (*yh_app) ( yh_socket* );

#define get_ip_header_len( x ) \
       ( (x->version_and_hdrlen & 0x0F) * 4 )

#define get_ip_data_len( x ) \
       R_STRUCT_VAR_TYPE( SHORT, x->data_len )

#define l345_offset( p ) ( p + sizeof( eth_frame ) )
#define l345_len( l )    ( l - sizeof( eth_frame ) )

/*! \brief offset of tcp layer (and above) */
#define l45_offset( p, i ) ( p + sizeof( eth_frame ) + \
                              get_ip_header_len( i ) )

/*! \brief len of tcp and app layer */
#define l45_len( p, i )  (   l - sizeof( eth_frame ) - \
                         get_ip_header_len( ip_hdr ) )

#define get_tcp_hdr_data_len( x ) \
  ( ( ( (x)->data_offset_ns >> 4 ) & 0x0F ) * 4 )

/* sock macros */
#define sock_tcp_opts_len( x ) ( get_tcp_hdr_data_len( x ) - \
                                 sizeof( tcp_header ) )
#define sock_tcp_opts_offset( s ) ( *s->pktp + \
             sizeof( eth_frame ) + s->ipl + sizeof( tcp_header ) )
#define sock_tcp_opts_len( x ) ( get_tcp_hdr_data_len( x ) - \
                                 sizeof( tcp_header ) )
#define sock_app_offset( s ) ( *s->pktp + \
             sizeof( eth_frame ) + s->ipl + s->tcpl )

/*! \brief app data offset from tcp layer */
#define l5_offset_from_l4( p )   \
    p + get_tcp_hdr_data_len( (tcp_header_p) p )
/*! \brief app data len, p = tcp header, l = len from tcp layer to above */
#define l5_len_from_l4( p, l )     \
    ((l > 60)? (l - get_tcp_hdr_data_len( (tcp_header_p) p )):0)

/* set sock members */
#define sock_set_offsets( sock, len )                                      \
    sock->pkt_len =                                                  len;  \
    sock->iph     =           (ip_header_p) (l345_offset( *sock->pktp ));  \
    sock->ipl     =                       get_ip_header_len( sock->iph );  \
    sock->tcph    = (tcp_header_p) l45_offset( *sock->pktp , sock->iph );  \
    sock->tcpl    =                   get_tcp_hdr_data_len( sock->tcph );  \
    sock->applen  = MAX( 0, ( sock->pkt_len - sock->ipl - sock->tcpl -     \
                                                   sizeof(eth_frame) ) );  \
    sock->app     = ( sock->applen )? sock_app_offset( sock ): NULL;       \
    sock->resize_cb = resize_tx;                                           \
    sock->tx_type = TX_TYPE_NONE

/* for printf */
#define ip_hdr_addr_to_str_fmt( x )    \
            *(  (BYTE*) (&(x) ))     , \
            *(( (BYTE*) (&(x)) + 1 )), \
            *(( (BYTE*) (&(x)) + 2 )), \
            *(( (BYTE*) (&(x)) + 3 ) )

#define ip_word_addr_to_str_fmt( x )   \
            *(  (BYTE*) &x + 3  ), \
            *( (BYTE*)  &x + 2  ), \
            *( (BYTE*)  &x + 1  ), \
            *( (BYTE*)  &x )

#define tx_reset(sock)             \
    sock->txid = 0;                \
    sock->rxid = 0;                \
    sock->txlen = 0;               \
    *sock->pktp = NULL;            \
    sock->pktp = NULL;             \
    sock->pkt_len = 0;             \
    sock->tcph = NULL;             \
    sock->tcpl = 0;                \
    sock->iph = NULL;              \
    sock->ipl = NULL;              \
    sock->app = NULL;              \
    sock->tx_type = TX_TYPE_NONE;  \
    sock->applen = 0
#endif
