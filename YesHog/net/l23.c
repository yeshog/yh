/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/

#include "l23.h"

/* yh config eth */
BYTE __MAC[ 6 ] = { 0, 0,'Y','O','G','I' };
/* end yh config eth */
/* yh config ip */
BYTE __IP [ 4 ] = { 192, 168, 1, 28 };
/* end yh config ip */
/* yh config peer ip */
BYTE __PEER_IP[ 4 ];
/* end yh config peer ip */
/* yh config peer mac */
BYTE __PEER_MAC[ 6 ];
/* end yh config peer mac */
/* yh config port */
SHORT __MYPORT = 443;
/* end yh config port */
BYTE  __MBUF[MAX_MBUF_SZ];
/*!
    \brief check if the etherhnet destination is me
    \arg1 [IN] packet
    \arg2 [IN] packet len
*/
RESULT check_eth( BYTE* pkt, SHORT len )
{
    eth_frame_p e = (eth_frame_p) pkt;
    if( memcmp( e->dst, __MAC, 6 ) == 0 )
    {
        return OK;
    }
    if( memcmp( (const void*) e->dst,
                (const void*) ETH_PKT_BROADCAST,
                6 ) == 0 )
    {
        return OK;
    }
    return ETH_DST_ETH_NOT_ME;
}

/*!
    \brief process an arp packet
    \arg1 [IN] arp packet
    \arg2 [IN] packet len
*/
RESULT process_arp_pkt( BYTE* pkt, SHORT len )
{
    RESULT _res_ = ERR_STATE;
    _res_ = arp_process( pkt + sizeof( eth_frame ), len );
    if( _res_ == ARP_PKT_SEND_RESPONSE )
    {
        /* Switch dest with src eth */
        memcpy( pkt, pkt + 6, 6 );
        memcpy( pkt + 6, __MAC, 6 );
        _res_ = snd_packet( pkt, len );
    }
    //yh_free( pkt, len );
    return _res_;
}

/*!
    \brief process an incoming ip packet
           Send a TCP ack for recd data and
           if there is app data, send it
    \arg1 [IN] pkt
    \arg2 [IN] tx len
    \arg3 [IN] sock struct having data
    \arg4 [IN] Type either ETH_TYPE_TCPIP or
                           ETH_TYPE_APP_DATA
    \note this function also gets the yh_socket
          and tx data len is len of data in sock
*/
RESULT send_packet( yh_socket* sock, BYTE type )
{
    eth_frame_p eth = (eth_frame_p) (*sock->pktp);
    RESULT _res_ = ERR_STATE;
    tcp_mk_header( sock );
    if( sock->txlen == 0 )
    {
        return ETH_PKT_LEN_ZERO;
    }
    if( type != ETH_TYPE_APP_DATA )
    {
        /* reverse eth src, dst */
        eth_plug_mac( eth, __MAC );
    }
    _res_ = snd_packet( *sock->pktp, sizeof( eth_frame ) +
                                            sock->txlen );
    /*tcp may be done sending ack but app isnt done.
    In that case don't free the packet just yet */
    sock->txlen = 0;
    return _res_;
}

/*!
    \brief: process an incoming ip packet
           Send a TCP ack for recd data and
           if there is app data, send it
    \arg: 1 [INOUT] pkt
    \arg: 2 [IN] rx len
    \note this function also gets the yh_socket
          and tx data len is len of data in sock
    \todo: should this live in eth
*/
RESULT process_ip_pkt( BYTE** pktp, SHORT len )
{
    RESULT _res_ =  ERR_STATE;
    ip_header_p ip_hdr = NULL;
    /* todo: add hash alg to make sure we get the same
              sock */
    yh_socket* sock = tcp_get_sock( NULL );
    if( sock == NULL )
    {
        printf( "Failed to get socket \r\n" );
        _res_ = TCP_CONN_FAILED_TO_SET_SOCKET;
        goto done;
    }
    sock->pktp    = pktp;
    sock->rxlen   = len;
    sock->txlen   = 0;
    sock_set_offsets( sock, len );
    _res_ = ip_process( sock->iph, sock->ipl );
    printf( "Processing IP result [%X]\r\n", _res_ );
    if( _res_ != OK )
    {
        if( _res_ == IP_HEADER_AND_ACTUAL_LEN_MISMATCH )
        {
            /* Ignore for now since there might be an eth
               trailer */
            _res_ = OK;
        } else
        {
            goto done;
        }
    }
    printf( "Processing tcp \r\n" );
    /* process tcp <-> tcp */
    _res_ = tcp_process( sock );
    /* something went wrong or if it was only an ack */
    if( _res_ != OK )
    {
        /*
         * And god gave us re-transmissions
         */
        _res_ = tcp_err_cleanup( sock, _res_ );
        goto done;
    }
    if( sock->txlen <= 0 )
    {
        goto done;
    }
    /* We have data to send i.e. sock->txlen > 0.
      Well, first send an ack */
    _res_ = send_packet( sock, ETH_TYPE_TCPIP );
    if( _res_ != OK )
    {
        goto done;
    }
    if( sock->pkt_len <= MIN_PKT_LEN )
    {
        goto done;
    }
    /* Process the app here */
    _res_ = tcp_app_process( sock );
    if( _res_ != OK )
    {
        /* debug */
        printf("Application error [%X]", _res_ );
        /* end debug */
        tcp_app_cleanup(sock);
        goto done;
    }
    if( sock->txlen > 0 )
    {
        _res_ = send_packet( sock, ETH_TYPE_APP_DATA );
    }
done:
    //yh_free( *sock->pktp, sock->pkt_len );
    tx_reset( sock );
    return _res_;
}

/*!
    \brief process an incoming packet
    \arg1 [INOUT] pkt
    \arg2 [IN] rx len
    \note This is the core TCP handler from
          driver's perspective i.e. every packet
          is handled by this function.
*/
RESULT process_rx( BYTE** pktp, SHORT len )
{
    RESULT _res_  =                           ERR_STATE;
    BYTE  *pkt    =                               *pktp;
    SHORT p_type  = R_SHORT( pkt, ETH_PKT_TYPE_OFFSET );
    if( pkt == NULL )
    {
        return ETH_PROCESS_RX_NULL_PKT;
    }
    _res_ = check_eth( pkt, len );
    if ( _res_ != OK )
    {
        goto done;
    }
    switch (p_type)
    {
        case ETH_PKT_TYPE_ARP:
            _res_ = process_arp_pkt( pkt, len );
            break;
        case ETH_PKT_TYPE_IP:
            printf( "Processing IP packet\r\n ");
            _res_ = process_ip_pkt( pktp,  len );
            break;
        default:
          printf( "IP/ARP Uknown payload [%X]", _res_ );
          //yh_free( pkt, len );
          *pktp = NULL;
          _res_ = ETH_UNKNOWN_PAYLOAD;
          break;
    }
    done:
    return _res_;
}
