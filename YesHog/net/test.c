/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
   A protocol stack test utility.
*/
#include "test.h"

static yh_pcap_p dmp;
static WORD found_ip_dst = 0;
static WORD found_ip_src = 0;
static BYTE found_eth_src[6];
static BYTE found_eth_dst[6];
static WORD found_seq_srv = 0;
static BYTE eth_set = 0;

#define PCAP_PKTS_TO_TEST 20

/*!
  \brief : Given a packet, save the ip and tcp pointers
           and their lengths
  \param 1: [IN] pkt, captured packet
  \param 2: [IN] length of packet
*/
void make_tcp_pkt( BYTE* pkt, SHORT len,
                                  test_pkt_p t)
{
    t->iph =   (ip_header_p) ( pkt +
                       sizeof( eth_frame ) );
    t->ipl =    get_ip_data_len( t->iph );
    t->tcph = (tcp_header_p) ( pkt +
                       sizeof( eth_frame )  +
               get_ip_header_len( t->iph ) );
    t->tcpl = len - sizeof( eth_frame )
               - get_ip_header_len( t->iph );
}

/*!
  \brief : Core tx function, its clone resides in
           the rtl ethernet driver
  \param 1: [IN] pkt, packet to send on ethernet
  \param 2: [IN] length of packet
*/
extern yh_socket* tcp_get_sock(ip_header_p);
extern void tcp_mk_header( yh_socket* sock );
RESULT snd_packet( BYTE* pkt, SHORT len )
{
    /* really bad but we have to test checksumming */
    yh_socket* sock = tcp_get_sock(NULL);
    tcp_mk_header(sock);
    int app_len = 0;
    if( !dmp )
        return PCAP_DUMP_NOT_INITIALIZED;
    printf( "\nTest sending packet of len [%d]\n", len );
    yh_pcap_append_pkt( dmp, pkt, len );
    test_pkt tp, *t;
    t = &tp;
    make_tcp_pkt( pkt, len, t );
    app_len = l5_len_from_l4( t->tcph, t->tcpl );
    if( app_len > 0 )
    {
        dmp->cli_tcp_ack += app_len;
    }
    return hexdump( pkt, len );
}

/*!
  \brief : Our ethernet destination is different from
           the pcap, hence we pass the packet up the
           stack, see its value, expect and error and
           pass it off to this function which fixes the
           destination eth.
  \param 1: [IN] pkt, captured packet with different eth
                 destination
  \param 2: [IN] length of packet
*/
void fix_eth( BYTE* pkt, SHORT len )
{
    eth_frame_p e = (eth_frame_p) pkt;
    if( ! eth_set ) {
        memcpy( found_eth_src, e->src, 6 );
        memcpy( found_eth_dst, e->dst, 6 );
        eth_set = 1;
    }
    if( eth_set ) {
        if( memcmp( e->dst, found_eth_dst, 6 ) == 0 )
            memcpy( e->dst, __MAC, 6 );
        if( memcmp( e->src, found_eth_dst, 6 ) == 0 )
            memcpy( e->dst, __MAC, 6 );
    }
}
/*!
  \brief : Our ip destination is different from
           the pcap, hence we pass the packet up the
           stack, see its value, expect and error and
           pass it off to this function which fixes the
           destination ip address.
  \param 1: [IN] pkt, captured packet with different ip
  \param 2: [IN] length of packet
*/
void fix_ip( BYTE* pkt, SHORT len )
{
    /* save the dst in the SYN */
    ip_header_p i = (ip_header_p) pkt;
    if( found_ip_src == 0 ) {
        found_ip_src = REVW(i->src);
        found_ip_dst = REVW(i->dst);
    }
    if( REVW( i->dst ) == found_ip_dst )
    {
        i->dst = REVW(R_WORD( __IP, 0 ));
    }
    if( REVW( i->src ) == found_ip_dst )
    {
        i->src = REVW(R_WORD( __IP, 0 ));
    }
    i->csum = 0;
    i->csum =  ~( pchksum( 0,   i,
         get_ip_header_len( i ) ) );
}

RESULT test_handle_seq( tcp_header_p tcph )
{
    WORD seq = R_STRUCT_VAR_TYPE( WORD, tcph->seq );
    WORD ack = R_STRUCT_VAR_TYPE( WORD, tcph->ack );
    if( ( seq > 0 && ack > 0 ) && found_seq_srv == 0 ) 
    {
        set_initial_seq( seq );
        found_seq_srv = seq;
        return OK;
    }
    return ERR_STATE;
}

/*!
  \brief : process_rx is essentially our entry point
           after ethernet frame is received and makes
           the core rx function.
           We test our proto stacks on x86 and when
           things look fine, (memory constraints are met)
           it becomes emdeddable.
  \param 1: [IN] pkt, captured packet
  \param 2: [IN] length of packet in param 1
  \param 3: [IN] callloced copy of pkt_1_copy (param 1)
                 so we can get tcp flow control in order
*/
RESULT test_process_rx( BYTE* pkt_1_copy, SHORT len,
                                 BYTE* pkt_2_copy )
{
    RESULT _res_ = 0;
    WORD inseq = get_initial_seq();
    test_pkt tpkt;
    make_tcp_pkt( pkt_1_copy, len, &tpkt );
    /* expected failure cuz dst eth is not ours */
    fix_eth( pkt_1_copy, len );
    /* expected failure cuz dst ip aint ours */
    fix_ip( pkt_1_copy    + sizeof( eth_frame ),
                            len -
                          sizeof( eth_frame ) );

    ip_header_p iph =           ( (ip_header_p)
                                  (pkt_1_copy +
                        sizeof( eth_frame ) ) );

    BYTE ipl = get_ip_data_len( iph );

    printf( "ip pkt len [%d]\n", ipl );
    printf( "ip dst [%u.%u.%u.%u]\n",
          ip_hdr_addr_to_str_fmt( iph->dst ) );
    printf( "ip header len [%u]\n",
                    get_ip_header_len( iph ) );

    /* expected failure cuz dst port aint ours */
    tcp_header_p tcph =          (tcp_header_p)
                                  (pkt_1_copy +
                          sizeof( eth_frame ) +
                   + get_ip_header_len( iph ));

    SHORT tcpl =                          len -
                            sizeof( eth_frame )
                    - get_ip_header_len( iph );

    SHORT tcphl = get_tcp_hdr_data_len( tcph );
    printf( "tcp len [%u] tcp header len [%u]",
                                 tcpl, tcphl );

    if( ( iph->src != REVW( R_WORD( __IP, 0 ) ) )
          &&
        ( tcph->ack > 1 )
          &&
        ( dmp->cli_tcp_ack > (get_initial_seq() -
                                   inseq + 1) ) )
    {
        tcph->ack = REVW((dmp->cli_tcp_ack + inseq));
    }
    /* make a copy since we change pkt_1_copy
       in place and capture it just before
       sending it to our tcp stack */
    memcpy( pkt_2_copy, pkt_1_copy, len );
    if( iph->src != REVW( R_WORD( __IP, 0 ) ) )
    {
        yh_pcap_append_pkt( dmp, pkt_2_copy, len );
    }
    BYTE **pktp = &pkt_1_copy;
    _res_ = process_rx( pktp, len );
    printf(   "process_rx [%X] dst port[%u] "
                             "my port[%u]\n",
                                      _res_ ,
                    R_STRUCT_VAR_TYPE( SHORT,
                            tcph->dst_port ),
                                  __MYPORT );
    return _res_;
}

/*!
  \brief: register app handler
*/
void regapp(void)
{
    switch( __MYPORT )
    {
        case 80:
            /* register http */
            register_app( &conn, http_rx, 0 );
            break;
        case 443:
            register_app( &conn, tls_rx, 0 );
            break;
        default:
            break;
    }
}

RESULT text_extract_seq( int argc, char** argv )
{
    yh_pcap_p xdmp = yh_pcap_init( argv[1], NULL );
    if( !xdmp || xdmp->err )
    {
        yh_pcap_close( xdmp );
        return xdmp->err;
    }
    struct pcap_pkthdr *header;
    unsigned char *data;
    int len, indx;
    len = indx = 0;
    do
    {
        /* now start iterating packets */
        if( pcap_next_ex (xdmp->pcap_in, &header,
                     (const u_char**) &data) <=0 )
        {
            break;
        }
        if( !header || !data )
        {
            break;
        }
        len = header->caplen;
        test_pkt tpkt;
        make_tcp_pkt( data, len, &tpkt );
        if( test_handle_seq( tpkt.tcph ) == OK )
        {
            break;
        }
       indx++;
    } while( indx < PCAP_PKTS_TO_TEST );
    yh_pcap_close( xdmp );
    return OK;
}

int test_pcap_file( int argc, char** argv )
{
    if( argc < 3 )
    {
        printf( "Usage: pcap_test <infile> <outfile>\n" );
        return 1;
    }
    if( access( argv[1], F_OK ) == -1 )
    {
        printf( "File Not Found [%s]", argv[1] );
    }

    /* initialize pcap and other stuff */
    RESULT _res_;
    dmp = yh_pcap_init( argv[1], argv[2] );
    if( !dmp || dmp->err )
    {
        yh_pcap_close( dmp );
        return 1;
    }
    text_extract_seq( argc, argv );
    struct pcap_pkthdr *header;
    unsigned char *data, *pkt_1, *pkt_2;
    size_t len;
    int indx;
    _res_ = indx = 0;
    data = pkt_1 = pkt_2 = NULL;
    do
    {
        /* now start iterating packets */
        if( pcap_next_ex (dmp->pcap_in, &header,
                     (const u_char**) &data) <=0 )
            break;
        if( header == NULL ) break;
        len = header->caplen;
        if( data == NULL ) break;
        pkt_1 = (BYTE*) yh_calloc( len, 1 );
        if( !pkt_1 ) break;
        pkt_2 = (BYTE*) calloc( len, 1 );
        if( !pkt_2 )
        {
            free( pkt_1 );
            free( pkt_2 );
            break;
        }
        memcpy( pkt_1, data, len );
        printf( "=== Captured Packet ===\n" );
        hexdump( data, (short)len );
        _res_ = test_process_rx( pkt_1, len, pkt_2 );
        printf( "YH Stack result [%X]\n", _res_ );
        /* The below corrupts the stack, no clue why,
           ask pcap developers */
        /* free( data ); */

        /* pkt1 is freed by process_ip_pkt */
        indx++;
    } while( indx < PCAP_PKTS_TO_TEST );
    yh_pcap_close( dmp );
    return 0;
}

/*!
  \brief: ./test ./http.pcap ./http-out.pcap
          reads each packet from arg[1] pcap,
          adjusts ethernet, ip, tcp to match ours
          and finally passes it to our stack
  \param 1: [IN] input packet capture filename
  \param 2: [IN] output packet capture filename
  \note: The only way to QA my 0xBADC0DE
*/
int main(int argc, char** argv)
{
    if( argc == 1 )
    {
        return test_live();
    }
    return test_pcap_file( argc, argv );
}
