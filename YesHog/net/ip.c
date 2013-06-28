#include "ip.h"

static BYTE supported_ip_protocols[] = { 0x06 };

RESULT ip_process( ip_header_p iph, SHORT len )
{
    DECLARE( SHORT, data_len,    0 );
    DECLARE( BYTE,  j,           0 );
    DECLARE( WORD,  dst,         0 );
    if( len < sizeof( ip_header ) )
    {
        return IP_HEADER_LEN_TOO_SMALL;
    }
    dst = R_STRUCT_VAR_TYPE( WORD, iph->dst );
    if( dst != R_WORD( __IP, 0 ) )
    {
        return IP_HEADER_DST_NOT_ME;
    }
    data_len = get_ip_data_len( iph );
    if( data_len == 0 )
    {
        return IP_HEADER_DATA_LEN_ZERO;
    }
    if( data_len > MAX_IP_DATA_LEN )
    {
        return IP_HEADER_DATA_LEN_TOO_BIG;
    }
    if( data_len != len )
    {
        return IP_HEADER_AND_ACTUAL_LEN_MISMATCH;
    }

    j = get_ip_header_len( iph );
    if( j > data_len )
    {
        return IP_HEADER_LEN_BIGGER_THAN_PKT;
    }

    for ( j = 0; j < sizeof( supported_ip_protocols );
            j++ )
    {
        if( supported_ip_protocols[ j ]
                     == iph->protocol )
            break;
    }
    if( j == sizeof( supported_ip_protocols ) )
    {
        return IP_HEADER_PROTO_NOT_SUPPORTED;
    }
    return OK;
}
