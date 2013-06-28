#ifdef TEST
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <pcap.h>
#define PCAP_NO_ERR 0
#define PCAP_OOM_ERR -1
#define PCAP_OPEN_OFFLINE_ERR -2
#define PCAP_OPEN_DEAD_ERR -3
#define PCAP_DUMP_OPEN_ERR -4
#define PCAP_INDX_NT_FOUND_ERR -5
#define PCAP_READ_PKT_PRIOR_ERRS -50
#define MAX_LEN 65535
typedef struct yh_pcap {
    pcap_t *pcap_in;
    pcap_t *pcap_out;
    pcap_dumper_t *pcap_dumper;
    int err;
} yh_pcap, *yh_pcap_p;

yh_pcap_p yh_pcap_init( char*, char* );
unsigned char* yh_pcap_read_pkt( yh_pcap_p, int, size_t* );
void yh_pcap_append_pkt( yh_pcap_p, u_char*, int );
void yh_pcap_close( yh_pcap_p );

#else

#include "pcaptest.h"

#endif

/*!
    \brief: Initialize a packet capture playback
    \arg1:  [IN] input pcap file
    \arg2:  [IN] output pcap file
    \return: raw data packet
*/
yh_pcap_p yh_pcap_init( char* infile, char* outfile )
{
    char buf[1024];
    yh_pcap_p p = calloc( 1, sizeof( yh_pcap ) );
    if( !p )
    {
        p->err = PCAP_OOM_ERR;
        return p;
    }
    /* set pcap_t pointer */
    p->pcap_in = pcap_open_offline(infile, buf);
    if( !p )
    {
        p->err = PCAP_OPEN_OFFLINE_ERR;
        return p;
    }
    p->pcap_out = pcap_open_dead(DLT_EN10MB, MAX_LEN);
    if( !p->pcap_out )
    {
        p->err = PCAP_OPEN_DEAD_ERR;
        return p;
    }
    if( outfile )
    {
        p->pcap_dumper =
               pcap_dump_open( p->pcap_out, outfile );
        if( !p->pcap_dumper )
        {
            p->err = PCAP_DUMP_OPEN_ERR;
            return p;
        }
    }
    p->cli_tcp_ack = get_initial_seq() + 1;
    p->err = PCAP_NO_ERR;
    return p;
}

/*!
    \brief: Append packet output file
    \arg1:  [IN] struct yh_pcap_p
    \arg2:  [IN] raw data packet
    \arg3:  [IN] len of arg2
*/
void yh_pcap_append_pkt( yh_pcap_p pcap,
                  u_char* pkt, int len )
{
    if( pcap->err != PCAP_NO_ERR )
    {
        pcap->err = PCAP_READ_PKT_PRIOR_ERRS;
        return;
    }
    struct pcap_pkthdr p;
    gettimeofday(&(p.ts), NULL);
    p.len = len;
    p.caplen = len;
    pcap_dump( (u_char*) pcap->pcap_dumper,
                                 &p, pkt );
}

/*!
    \brief: close all pcap objects
    \arg1:  [IN] struct yh_pcap_p
*/
void yh_pcap_close( yh_pcap_p pcap )
{
    pcap_close( pcap->pcap_in );
    pcap_close( pcap->pcap_out );
    if( pcap->pcap_dumper )
    {
        pcap_dump_close( pcap->pcap_dumper );
    }
    free( pcap );
}

#ifdef TEST
int main(int argc, char** argv)
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

    /* initialize pcap */
    dmp = yh_pcap_init( argv[1], argv[2] );
    /* data and len will be read from pcap file */
    unsigned char* data;
    size_t len;
    int indx = 0;
    struct pcap_pkthdr *header;
    do
    {
        /* now start iterating packets */
        if( pcap_next_ex (dmp->pcap_in, &header,
                     (const u_char**) &data) <=0 )
            break;

        if( data == NULL ) break;
        len = header->caplen;
        /*
        hexdump( data, (short)len );
        */
        /* append packet to pcap outfile */
        yh_pcap_append_pkt( dmp, data, len );
        /*
            hexdump( data, (short)len );
        */
        indx++;
    } while( indx < 20 );
    yh_pcap_close( dmp );
    return 0;
}
#endif
