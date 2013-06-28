/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/

#include "common.h"

/*!
    \brief print hexdump of a buffer as chars
    \param 1: [IN]  buffer, buffer to be hexdumped, observed
    \param 2: [IN]  len, length of buffer to be hexdumped
    \return: Error if len too big to handle, or param 1 null
             or len = 0
*/
SHORT hexdump_(BYTE* p, SHORT len)
{
    if ( (p == NULL) || (len <= 0) || (len > 2048) )
    {
       /* debug */
       //printf( "p == NULL ? [%s], len <= 0 ? [%s], len >= 2048 ? [%s]",
       //         (p == NULL)? "Yes":"No", (len <= 0)? "Yes":"No",
       //         (len > 2048) ? "Yes":"No" );
       /* end debug */
       return HEXDUMP_ERR;
    }
    SSHORT offset, i, l;
    l = len;
    offset = 0;
    while( l > 0 )
    {
        i = len - l;
        printf( "%04X ", offset);
        do {
            printf( "%02X ", p[i] );
            i++;
            l--;
        } while( (i < len) && (l > 0 ) &&
                 ((i & 15) != 0) );

        l += ((i & 15)? (i & 15):16);
        if( !(i & 15) ) printf( " " );
        while ( (i & 15 )!= 0 )
        {
            printf( "   " );
            i++;
        }
        i = len - l;
        do {
            printf( "%c", ( p[i] >= 0x20 &&
                   p[i] < 0x7f )? p[i] : '.' );
            i++;
            l--;
        } while( (i > 0)   &&
                 (l > 0)   &&
                 (i < len) &&
                 ((i & 15) != 0) );

        offset += 16;
        printf( _NEWLINE_ );
    }
    return OK;
}

/*!
    \brief print hexdump of a buffer as chars
    \param 1: [IN]  buffer, buffer to be hexdumped, observed
    \param 2: [IN]  len, length of buffer to be hexdumped
    \note     Wrapper to hexdump_
*/
SHORT hexdump( BYTE *p, SHORT len )
{
    printf( _NEWLINE_ "== hex %u chars ==" _NEWLINE_, len);
    RESULT _res_ = hexdump_( p, len );
    printf("== end hex [Status %X] ==" _NEWLINE_, _res_);
    return _res_;
}
