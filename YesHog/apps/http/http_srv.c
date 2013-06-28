/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/

#include "http_srv.h"

RESULT http_rx( yh_socket* s )
{
    return OK;
}

RESULT http_process( BYTE** in, SHORT inlen, BYTE** out,
                       SHORT* outlen, SHORT* needbytes )
{
    BYTE* req = *in;
    /* debug */
    hexdump( req, inlen );
    *outlen = inlen;
    /* end debug */
    return OK;
}
