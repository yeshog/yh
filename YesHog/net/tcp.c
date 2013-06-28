/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/

#include <ip.h>
#include "tcp.h"

/* We are a single user system
   so we lock the precious 'conn'
   and leave it on err or finished
   transaction
   Also a tcp needs to send its ack
   independently of when app is ready
   to send. Now this is very desirable
   for bigger systems. For us, we simply
   cannot proceed w/o app app processing
   data
*/

yh_socket conn;
static SHORT conn_id;
static WORD  seq;

/* declared in rtl driver and test */
extern RESULT snd_packet( BYTE*, SHORT );

/* declared in yhmemory.c */
extern SHORT yh_mem( void );

/* somehow if i declare
 * yh_app tls_rx;
 *  i get a SIGSEGV, thus I still don't know about C
 */
extern RESULT tls_rx ( yh_socket* );
extern RESULT tls_free_sec_data( yh_socket* );

SHORT get_id()
{
    return conn_id++ & 0xFFFF;
}

/*!
  \brief : resize the packet to be transmitted to len bytes
  \param 1: socket, socket->pkt is resized
  \param 2: requested l4 len needed
  \note  : So sock->app can mean different pointers
          based on the direction. When a packet comes
          in, we save what we need, and muck the same
          packet to send the reply. Now the sending header
          len is usually lesser since we strip tcp header
          options.
  \warning : make sure we have everything we need from
             the incoming packet before calling resize.
*/
RESULT resize_tx( yh_socket* s, SHORT len )
{
    /* at this point we assume that packet 'read'
       has finished properly and we have processed
       what we need. Now remove extra tcp options
       and set app pointer correctly, so we can
       write to the correct offset
    */
    tcp_handle_opts( s );
    /* We dont need to resize */
    //if( len <= s->pkt_len )
    //{
    //    return OK;
    //}
    //void* tmp = yh_realloc( *s->pktp, s->pkt_len, len );
    //if( !tmp )
    //{
    //    /* restore original */
    //    return TCP_APP_RESIZE_FAILED;
    //}
    //*s->pktp = tmp;
    sock_set_offsets( s, len );
    return OK;
}

/*!
 \brief Does a given packet check out
 \param 1 tcp packet
 \param 2 len length
 \param 3 ip header (we need it for a bunch of things)
*/

RESULT tcp_check_hdr( yh_socket* sock )
{
    if( sock->pkt_len < MIN_TCP_HEADER_LEN )
        return TCP_HEADER_PKT_TOO_SMALL;

    if( sock->tcpl > MAX_TCP_HEADER_LEN )
        return TCP_HEADER_LEN_TOO_BIG;

    if(  R_STRUCT_VAR_TYPE( SHORT, sock->tcph->dst_port ) !=
         __MYPORT )
    {
        return TCP_HEADER_DST_PORT_NOT_ME;
    }
    if( sock->tcpl > sock->pkt_len )
    {
        return TCP_HEADER_LEN_BIGGER_THAN_PKT;
    }
    if( sock->tcph->flags == TCP_SYN )
    {
        if( sock->applen > 0 )
        {
            return TCP_HEADER_SYN_WITH_DATA;
        }
    }
    /* TODO: this needs to be move out of here. I SUCK */
    if( sock->state == TCP_INITIAL && __MYPORT == 443 )
    {
        if( !seq ) {
            set_initial_seq(0x11111111);
        }
    }
    /* keep last */
    if( R_STRUCT_VAR_TYPE( SHORT, sock->tcph->csum ) !=
       tcp_checksum( sock ) )
    {
        return TCP_HEADER_CHECKSUM_VERIFY_FAILED;
    }
    return OK;
}

void tcp_print_sock( yh_socket* sock )
{
    printf("\r\n");
    printf( "sock->src       [%u.%u.%u.%u:%u] ",
            ip_word_addr_to_str_fmt(sock->src),
            sock->src_port);
    printf( "sock->dst       [%u.%u.%u.%u:%u]\r\n",
            ip_word_addr_to_str_fmt(sock->dst),
            sock->dst_port);
    printf( "sock->iph->dst  [%u.%u.%u.%u:%u] ",
            ip_hdr_addr_to_str_fmt(sock->iph->dst),
            REVS( sock->tcph->dst_port ) );
    printf( "sock->iph->src  [%u.%u.%u.%u:%u]\r\n",
            ip_hdr_addr_to_str_fmt(sock->iph->src),
            REVS( sock->tcph->src_port ) );

    printf( "sock->seq       [%X] ",                sock->seq );
    printf( "sock->ack       [%X]\r\n",             sock->ack );
    printf( "sock->tcph->ack [%X] ",    REVW(sock->tcph->ack) );
    printf( "sock->tcph->seq [%X]\r\n", REVW(sock->tcph->seq) );
    printf( "sock->nxt       [%X] ",                sock->nxt );
    printf( "sock->state     [%X]\r\n",           sock->state );
    printf( "sock->pkt_len   [%u] ",             sock->pkt_len);
    printf( "sock->rxlen     [%u]\r\n",            sock->rxlen);
    printf( "sock->ipl:tcpl  [%u:%u] ", sock->ipl, sock->tcpl );
    printf( "sock->applen    [%u]\r\n",           sock->applen);
    printf( "sock->txlen     [%u] ",               sock->txlen);
    printf( "sock->tx_type   [%u]\r\n",          sock->tx_type);
}

RESULT tcp_check_flow( yh_socket* sock )
{
    WORD tack    = R_STRUCT_VAR_TYPE( WORD, sock->tcph->ack );

    if ( sock->state == TCP_INITIAL )
    {
        return TCP_CONN_FLOW_ST_MISMATCH;
    }
    /* ack overflowed past 0xFFFFFFFF */
    if( ( tack < sock->seq ) && 
        ( ( (MAX_WORD - sock->seq ) + tack )
                               > yh_mem()) )
        return TCP_CONN_ACK_NUM_OVERFLOW;

    /* make sure src and destination are same */
    if( ( REVW(sock->iph->dst) != sock->src )
     || ( REVW(sock->iph->src) != sock->dst )
     || ( REVS(sock->tcph->dst_port) != sock->src_port )
     || ( REVS(sock->tcph->src_port) != sock->dst_port ) )
    {
        return TCP_CON_IP_SRC_DST_TUPLE_MISMATCH;
    }

    if(  (sock->seq == R_STRUCT_VAR_TYPE( WORD, sock->tcph->ack ))
      && (sock->ack == R_STRUCT_VAR_TYPE( WORD, sock->tcph->seq ))
      && ( sock->applen == 0 ) )
    {
        return TCP_CONN_DUP_PKT;
    }
    if( sock->nxt != R_STRUCT_VAR_TYPE( WORD, sock->tcph->ack ) )
    {
        return TCP_CONN_ACK_NUM_MISMATCH;
    }
    return OK;
}
/*!
  \brief Build tcp and ip header for tx
  \param [IN] yh_socket* sock
  \note sock->txlen MUST be set correctly before call
*/
void tcp_mk_header( yh_socket* sock )
{
    /* Now the packet has been received,
       the state saved. We are free to
       muck with it and send it back (hopefully)
    */
    sock->iph->id               =   sock->txid & 0xFFFF;
    sock->iph->ttl              =    sock->iph->ttl - 1;
    sock->tcph->ack             =       REVW(sock->ack);
    sock->tcph->seq             =       REVW(sock->seq);
    sock->tcph->src_port        =  REVS(sock->src_port);
    sock->tcph->dst_port        =  REVS(sock->dst_port);
    sock->iph->src              =       REVW(sock->src);
    sock->iph->dst              =       REVW(sock->dst);
    /* not setting iph csum to 0 causes lots of unhappiness
       in the form of wasted time */
    sock->iph->csum             =                     0;
    /* TODO: Use _mem_avail_ here? */
    sock->tcph->window_sz       =                0x0004;
    sock->tcph->csum            =  tcp_checksum( sock );
    W_STRUCT_VAR_TYPE( SHORT, sock->iph->data_len,
                                    sock->txlen );
    sock->iph->csum =  ~( pchksum( 0, (void*) sock->iph,
                                          sock->ipl ) );
    sock->txid++;
}

void set_initial_seq( WORD mseq )
{
    seq = mseq;
}

WORD get_initial_seq( void )
{
    return seq;
}

RESULT tcp_handle_opts( yh_socket* sock )
{
    SSHORT n_l = 0;
    WORD   t_s = 0;
    BYTE*  s_o = sock_tcp_opts_offset( sock );
    SHORT  s_l = sock_tcp_opts_len( sock->tcph );
    /* remove 3 bytes starting with window scaling
       option \x3\x3\shft.cnt if present */

    n_l = mem_replace_starting_with( s_o, s_l, s_l,
                    (BYTE*) TCP_WINDOW_SCALING_OPT,
                                   2, 3, NULL, 0 );
    if( n_l < 0 )
    {
        n_l = s_l;
    }
    /* remove the sack option if any */
    n_l = mem_replace( s_o, n_l, n_l, (BYTE*) TCP_SACK,
                                 2, NULL, 0, NULL, 0 );
    if( n_l > 0 )
    {
        n_l          = n_l + ( 4 - (n_l & 3 ) );
        sock->tcpl   = n_l + sizeof( tcp_header );
        sock->tcph->data_offset_ns =
                     ( ( sock->tcpl >> 2 ) << 4 );
    }
    n_l = memfind( s_o, s_l, (BYTE*) "\x08\x0A", 2 );
    if( n_l > 0 )
    {
        /* TODO: Check lengths */
        memcpy( s_o + n_l + 2 + 4,
                s_o + n_l + 2,
                4 );
        t_s = R_WORD( s_o + n_l + 2, 0 );
        /* Bogus TS */
        t_s += 100;
        W_WORD( s_o + n_l + 2, 0, t_s );
    }
    /* TODO: why are we returning anything */
    return OK;
}

/*!
 \brief send ack to received tcp syn
 \param 1 [INOUT] sock conn structure
 \param 2 [INOUT] pkt tcp packet
 \param 3 [IN] len of incoming tcp packet
 \param 4 [INOUT] ip header to send ack to
 \note we whack window scaling option and sack
       options that are commonly present.
      TODO: Whack other possible options except
            timestamp
*/

RESULT tcp_syn_ack( yh_socket* sock )
{
    /* update src and dst */
    sock->id       =                                        get_id();
    sock->dst      =       R_STRUCT_VAR_TYPE( WORD, sock->iph->src );
    sock->src      =                                R_WORD(__IP, 0 );
    sock->src_port =                                        __MYPORT;
    sock->dst_port = R_STRUCT_VAR_TYPE( SHORT, sock->tcph->src_port);

    sock->ack      =  R_STRUCT_VAR_TYPE( WORD, sock->tcph->seq ) + 1;
    sock->seq      =                               get_initial_seq();
    sock->nxt      =                                   sock->seq + 1;
    sock->tcph->flags    =                               TCP_SYN_ACK;
    sock->state   |=                                    TCP_CON_BUSY;
    tcp_handle_opts( sock );
    sock->txlen = sock->ipl + sock->tcpl;
    printf( " sock new ip len [%u], new tcpl [%u] state [%X] \r\n",
                              sock->ipl, sock->tcpl, sock->state );
    return OK;
}

/*!
  \brief pass things to the app layer
  \param [INOUT] sock connection
  \param [INOUT] tcp packet
  \param [IN] length of packet in param 2
  \param [IN] IP header pointer
  \note wrapper to app
*/

RESULT tcp_app_process( yh_socket* sock )
{
    /* if this is only tcp packet */
    if( !(sock->app) || !(sock->applen) )
    {
        return OK;
        sock->txlen = 0;
    }
    printf( "Processing application data\r\n ");
    RESULT _res_             =                       OK;
    BYTE j                   =                        0;
    sock->txlen              =                        0;
    /* send data to app and process */
    for( ; j < MAX_APPS; j++ )
    {
        if( sock->apps[j] == NULL )
        {
            register_app( sock, tls_rx, 0 );
        }
        _res_ = sock->apps[j]( sock );
    }
    /* app layer has no response */
    if ( sock->txlen == 0 )
        return _res_;
    /* sock->txlen = application layer data */
    sock->nxt         =        sock->seq + sock->txlen;
    /* we are done with rx part and reading applen reuse
     * it for checksumming later in snd_packet
     */
    sock->applen      =                    sock->txlen;
    /* add app + tcp + ip */
    sock->txlen      +=         sock->ipl + sock->tcpl;
    sock->tx_type     =                    TX_TYPE_APP;
    return _res_;
}
RESULT tcp_app_cleanup( yh_socket* sock )
{
    return tls_free_sec_data( sock );
}
/*!
  \brief register an application above tcp stack
  \param [INOUT] sock whose app is set
  \param [IN] function to executed
  \param [IN] ordinal of registered function
  \note sock->apps[ num ] = func;
*/
RESULT register_app( yh_socket* sock, yh_app func, BYTE num )
{
    sock->apps[ num ] = func;
    return OK;
}

/*!
  \brief return a new connection
  \arg1 [IN] new or previously initialized yh_socket
  \return pointer to new yh_socket connection
  \note currently a single connection
*/
yh_socket* tcp_get_sock( ip_header_p iph )
{
    /*! \TODO: we *really* need some serious logic here
       For now we are in demo mode */
    return &conn;
}
/*!
 * \brief free packet reset socket fields (only ones relevant)
 * \param [IN] sock to be cleaned
 * \param [IN] result from tcp processing
 */
RESULT tcp_err_cleanup( yh_socket* sock, RESULT r )
{
    RESULT _res_ = r;
    switch( r )
    {
        case OK:
            _res_ = OK;
            break;
        case TCP_CONN_DUP_PKT:
        case TCP_CONN_SYN_RECD_BUT_BUSY:
        case TCP_CONN_ACK_NUM_MISMATCH:
            /* if this is a app layer retransmission
             * set txlen to 0 so that packet is dropped
             */
            sock->txlen = 0;
            _res_ = OK;
            break;
        default:
            /* you lame bastard */
            printf( "Socket Full Reset on error [%X]\r\n", r );
            _res_ = r;
            sock_zero(sock);
            break;
    }
    return _res_;
}

/*!
  \brief entry point for tcp stack
  \param [IN] tcp packet
  \param [IN] len of param 1
  \param [IN] ip header for checksum and callbacks
  \param [IN] ethernet frame in case we need it
               for callbacks
  \note 
*/
RESULT tcp_process( yh_socket* sock )
{
    RESULT _res_ =                         tcp_check_hdr ( sock );
    SHORT     st = (sock->state | sock->tcph->flags) & TCP_FLMASK;

    if( _res_ != OK )
    {   /* don't worry abt tcp checksum too much */
        if( _res_ !=
               TCP_HEADER_CHECKSUM_VERIFY_FAILED )
            return _res_;
    }
    /* debug */
    printf( "tcp process st [%X] fl [%X] sst [%X]\r\n",
            sock->state, sock->tcph->flags,
           (sock->state | sock->tcph->flags) & TCP_FLMASK );
    /* end debug */
    switch( st )
    {
        case TCP_SYN:
          /* We received a SYN */
          return tcp_syn_ack( sock );

        case TCP_SYN|TCP_CON_BUSY:
          return TCP_CONN_SYN_RECD_BUT_BUSY;

        case TCP_ACK|TCP_CON_BUSY:
            printf( "Connection established \r\n");
            sock->state   = TCP_CON_EST;

        case TCP_CON_EST:
            _res_ = tcp_check_flow( sock );
            if( _res_ != OK )
            {
                printf( "Flow cntl err [%X]\r\n", _res_ );
                tcp_print_sock(sock);
                /* flow control */
                return _res_;
            }
           sock->seq     =   sock->nxt;
           /* we received an ack we are done */
           if( !sock->applen )
           {
               sock->txlen = 0;
               return OK;
           }
           /* we are only acking received data
              we add tcp+ip len here, eth adds eth len */
           sock->txlen = sock->tcpl + sock->ipl;
           sock->ack  +=           sock->applen;
           tcp_handle_opts( sock );
           sock->tx_type = TX_TYPE_ACK;
           if( _res_ != OK )
               return _res_;
           break;
       default:
           return TCP_UNKNOWN_ST;
    }
    return OK;
}

/*!
 \brief do checksum of pkt of length len with ipheader iph
 TODO: i assume data is also in pkt so we are good but check
*/
SHORT tcp_checksum( yh_socket* sock )
{
    SHORT              v  =                         0;
    WORD             sum  =                         0;
    tcp_header_p    tcph  =                sock->tcph;
    ip_header_p      iph  =                 sock->iph;
    tcp_header       tcp;
    pseudo_hdr       psh;
    /* Pseudo header
         +-----------------------------------------+
         |                    |                    |
         |                 src  ip                 |
         |                 dst  ip                 |
         | zeros   | proto    |      tcp len       |
         +-----------------------------------------+
    */
    if( sock->tx_type == TX_TYPE_ACK )
    {
        v = sock->tcpl;
    } else
    {
        v = sock->tcpl + sock->applen;
    }
    psh.ph_src_addr  =         iph->src;
    psh.ph_dest_addr =         iph->dst;
    psh.ph_zero      =                0;
    psh.ph_protocol  =    iph->protocol;
    psh.ph_len       = R_SHORT( &v, 0 );
    memcpy( &tcp, tcph, sizeof( tcp ) );
    tcp.csum = 0;
    sum = pchksum( 0  , (void*) &psh, sizeof(psh) );
    sum = pchksum( sum, (void*) &tcp, sizeof(tcp) );
    sum = pchksum( sum,
                  (void*) sock->tcph + sizeof(tcp),
                  v - sizeof(tcp) );
    v   = ~sum;
    return v;
}

/*!
   \brief RFC 1071 checksum code straight up copy paste
   better mortals than me convert this stuff into assembly
   for speed
   \note Do not forget to set iph/tcph csum fields to 0
    before doing this
*/
SHORT pchksum(WORD partial_csum, void *buf, SHORT count)
{
    WORD sum = partial_csum;
    SHORT *d2 = (SHORT*) buf;
    while (count > 1)
    {
        sum   += *d2++;
        count -=     2;
    }
    if (count > 0)
        sum += *(BYTE*) d2++;

    while (sum>>16)
        sum = (sum & 0xFFFF) + (sum >>16);
    partial_csum = sum;
    return (SHORT) (partial_csum & 0xFFFF);
}
