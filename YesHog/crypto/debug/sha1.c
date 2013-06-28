#include "sha1.h"

static BYTE sha1_pad[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void sha1_transform(sha1_ctx_p c)                    \
{
    F0_TO_15(c, 0,  0); F0_TO_15(c, 0,  1);     \
    F0_TO_15(c, 0,  2); F0_TO_15(c, 0,  3);     \
    F0_TO_15(c, 0,  4); F0_TO_15(c, 0,  5);     \
    F0_TO_15(c, 0,  6); F0_TO_15(c, 0,  7);     \
    F0_TO_15(c, 0,  8); F0_TO_15(c, 0,  9);     \
    F0_TO_15(c, 0, 10); F0_TO_15(c, 0, 11);     \
    F0_TO_15(c, 0, 12); F0_TO_15(c, 0, 13);     \
    F0_TO_15(c, 0, 14); F0_TO_15(c, 0, 15);     \
                                                \
    F16_TO_79(c, 0, 16 ); F16_TO_79(c, 0, 17 ); \
    F16_TO_79(c, 0, 18 ); F16_TO_79(c, 0, 19 ); \
    F16_TO_79(c, 1, 20 ); F16_TO_79(c, 1, 21 ); \
    F16_TO_79(c, 1, 22 ); F16_TO_79(c, 1, 23 ); \
    F16_TO_79(c, 1, 24 ); F16_TO_79(c, 1, 25 ); \
    F16_TO_79(c, 1, 26 ); F16_TO_79(c, 1, 27 ); \
    F16_TO_79(c, 1, 28 ); F16_TO_79(c, 1, 29 ); \
    F16_TO_79(c, 1, 30 ); F16_TO_79(c, 1, 31 ); \
    F16_TO_79(c, 1, 32 ); F16_TO_79(c, 1, 33 ); \
    F16_TO_79(c, 1, 34 ); F16_TO_79(c, 1, 35 ); \
    F16_TO_79(c, 1, 36 ); F16_TO_79(c, 1, 37 ); \
    F16_TO_79(c, 1, 38 ); F16_TO_79(c, 1, 39 ); \
    F16_TO_79(c, 2, 40 ); F16_TO_79(c, 2, 41 ); \
    F16_TO_79(c, 2, 42 ); F16_TO_79(c, 2, 43 ); \
    F16_TO_79(c, 2, 44 ); F16_TO_79(c, 2, 45 ); \
    F16_TO_79(c, 2, 46 ); F16_TO_79(c, 2, 47 ); \
    F16_TO_79(c, 2, 48 ); F16_TO_79(c, 2, 49 ); \
    F16_TO_79(c, 2, 50 ); F16_TO_79(c, 2, 51 ); \
    F16_TO_79(c, 2, 52 ); F16_TO_79(c, 2, 53 ); \
    F16_TO_79(c, 2, 54 ); F16_TO_79(c, 2, 55 ); \
    F16_TO_79(c, 2, 56 ); F16_TO_79(c, 2, 57 ); \
    F16_TO_79(c, 2, 58 ); F16_TO_79(c, 2, 59 ); \
    F16_TO_79(c, 3, 60 ); F16_TO_79(c, 3, 61 ); \
    F16_TO_79(c, 3, 62 ); F16_TO_79(c, 3, 63 ); \
    F16_TO_79(c, 3, 64 ); F16_TO_79(c, 3, 65 ); \
    F16_TO_79(c, 3, 66 ); F16_TO_79(c, 3, 67 ); \
    F16_TO_79(c, 3, 68 ); F16_TO_79(c, 3, 69 ); \
    F16_TO_79(c, 3, 70 ); F16_TO_79(c, 3, 71 ); \
    F16_TO_79(c, 3, 72 ); F16_TO_79(c, 3, 73 ); \
    F16_TO_79(c, 3, 74 ); F16_TO_79(c, 3, 75 ); \
    F16_TO_79(c, 3, 76 ); F16_TO_79(c, 3, 77 ); \
    F16_TO_79(c, 3, 78 ); F16_TO_79(c, 3, 79 ); \
    STEP_3(c);
}

RESULT sha1_update(sha1_ctx_p ctx, BYTE* buf, SHORT len)
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
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

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
