/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/

#include "sha1.h"

static BYTE sha1_pad[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

RESULT sha1_update(sha1_ctx_p ctx,
             BYTE* buf, SHORT len)
{
    if( len == 0 || len > MAX_SHORT || !buf )
    {
        return SHA1_BUF_ERR;
    }

    /* remaining bytes = ct[1] mod 64 */
    WORD last = ctx->ct[1] & 0x3F;
    WORD unused = 64 - last;

    ctx->ct[1] += len;
    if( ctx->ct[1] < len )
    {
        /* overflow */
        ctx->ct[0]++;
        if( ctx->ct[0] >= SHA1_DATA_SZ_LIMIT )
        {
            return SHA1_BUF_TOO_BIG;
        }
    }
    if( last && len >= unused )
    {
        memcpy( (void*) (ctx->W + last),
                (void*) buf, unused );
        sha1_transform( ctx );
        buf += unused;
        len -= unused;
        last = 0;
    }
    while ( len >= 64 )
    {
        memcpy( (void*) (ctx->W ),
                (void*) buf, 64 );
        sha1_transform(ctx);
        buf += 64;
        len -= 64;
    }
    if( len )
    {
        memcpy( (void*) (ctx->W + last),
                 (void*) buf, len );
    }
    return OK;
}

RESULT sha1_final( sha1_ctx_p ctx, BYTE* o )
{
    WORD last, padn;
    BYTE fin_ct[8];
    RESULT r;
    /* convert len to bits */
    WW( fin_ct, 0, (ctx->ct[0] << 3 ) |
                   (ctx->ct[1] >> 29) );
    WW( fin_ct, 1, ctx->ct[1] << 3 );

    /*
       if we have ct[1] mod 64 = (0..55) then
       we need at most (64 -8 - last) pad bytes
       if we have ct[1] mod 64 = (56..63) then
       we need at most (128 - 8 - last) pad bytes
    */
    last = ctx->ct[1] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ):
                          ( 120 - last );

    r = sha1_update( ctx, (BYTE*) sha1_pad, padn );
    if ( r != OK )
    {
        return SHA1_FINAL_PAD_ERR;
    }
    r = sha1_update( ctx, fin_ct, 8 );
    if( r != OK )
    {
        return SHA1_FINAL_COUNT_ERR;
    }
    finish(ctx, o);
    return OK;
}
