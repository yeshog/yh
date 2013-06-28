#include <common.h>

typedef struct
{
    WORD ct [2];
    BYTE W  [64];
    /* could have defined an array but
     * just so it reads like RFC 3174 */
    WORD A;
    WORD B;
    WORD C;
    WORD D;
    WORD E;
    WORD TEMP;
    WORD H[5];
} sha1_ctx, *sha1_ctx_p;

#ifndef SHA1_DATA_SZ_LIMIT
    #define SHA1_DATA_SZ_LIMIT 1
#endif

#define H0 0x67452301
#define H1 0xEFCDAB89
#define H2 0x98BADCFE
#define H3 0x10325476
#define H4 0xC3D2E1F0

#define init_H(ctx) ctx->A = ctx->H[0] = H0; \
                    ctx->B = ctx->H[1] = H1; \
                    ctx->C = ctx->H[2] = H2; \
                    ctx->D = ctx->H[3] = H3; \
                    ctx->E = ctx->H[4] = H4; \
                    ctx->ct[1] = \
                    ctx->ct[0] = \
                    ctx->TEMP  = \
                    0;           \
                    memset( ctx->W, 0, 64 );

#define H(ctx, x, y) ctx->H[x] = y

#define S( X, n ) ( ( (X) << n) | ( (X) >> (32-n) ) )

#define f0( B, C, D ) ( (B & C) | ( (~B) & D ) )
#define f1( B, C, D ) ( B ^ C ^ D )
#define f2( B, C, D ) ( (B & C) | (B & D) | (C & D) )
#define f3 f1

#define K0 0x5A827999
#define K1 0x6ED9EBA1
#define K2 0x8F1BBCDC
#define K3 0xCA62C1D6
#define MASK 0x0F
#define s(t) (t & MASK)

/* Read word */
#define WR( b, s ) R_WORD( b, s*4 )
/* Write word */
#define WW( b, s, v ) W_WORD( b, s*4, (v) )

#define STEP_1(ctx, t)                                     \
        WW( ctx->W, s(t),                                  \
              S( ( WR( ctx->W, ( (s(t) + 13) & MASK ) ) ^  \
                   WR( ctx->W, ( (s(t) +  8) & MASK ) ) ^  \
                   WR( ctx->W, ( (s(t) +  2) & MASK ) ) ^  \
                   WR( ctx->W, s(t) ) ), 1 ) )

#define STEP_2( ctx, N, t )                 \
        ctx->TEMP = S( ctx->A, 5 )       +  \
        f##N( ctx->B, ctx->C, ctx->D )   +  \
        ctx->E + WR( ctx->W, s(t) )      +  \
        K##N;                               \
        ctx->E = ctx->D;                    \
        ctx->D = ctx->C;                    \
        ctx->C = S( ctx->B, 30 );           \
        ctx->B = ctx->A;                    \
        ctx->A = ctx->TEMP

#define F0_TO_15 STEP_2

#define F16_TO_79( ctx, N, t )              \
        STEP_1( ctx, t);                    \
        STEP_2( ctx, N, t)

#define STEP_3(ctx)                                   \
        ctx->A =  ctx->H[0] = ( ctx->H[0] + ctx->A ); \
        ctx->B =  ctx->H[1] = ( ctx->H[1] + ctx->B ); \
        ctx->C =  ctx->H[2] = ( ctx->H[2] + ctx->C ); \
        ctx->D =  ctx->H[3] = ( ctx->H[3] + ctx->D ); \
        ctx->E =  ctx->H[4] = ( ctx->H[4] + ctx->E ); \
        printf( "%X %X %X %X %X\n", ctx->A, ctx->B,   \
                                    ctx->C, ctx->D,   \
                                    ctx->E)

#define finish(ctx, o)                      \
    WW( o, 0, ctx->A );                     \
    WW( o, 1, ctx->B );                     \
    WW( o, 2, ctx->C );                     \
    WW( o, 3, ctx->D );                     \
    WW( o, 4, ctx->E )

#define sha1_init(ctx) init_H((ctx))

#if 0
#define sha1_transform(c, b)                          \
    F0_TO_15(c, b, 0,  0); F0_TO_15(c, b, 0,  1);     \
    F0_TO_15(c, b, 0,  2); F0_TO_15(c, b, 0,  3);     \
    F0_TO_15(c, b, 0,  4); F0_TO_15(c, b, 0,  5);     \
    F0_TO_15(c, b, 0,  6); F0_TO_15(c, b, 0,  7);     \
    F0_TO_15(c, b, 0,  8); F0_TO_15(c, b, 0,  9);     \
    F0_TO_15(c, b, 0, 10); F0_TO_15(c, b, 0, 11);     \
    F0_TO_15(c, b, 0, 12); F0_TO_15(c, b, 0, 13);     \
    F0_TO_15(c, b, 0, 14); F0_TO_15(c, b, 0, 15);     \
                                                      \
    F16_TO_79(c, b, 0, 16 ); F16_TO_79(c, b, 0, 17 ); \
    F16_TO_79(c, b, 0, 18 ); F16_TO_79(c, b, 0, 19 ); \
    F16_TO_79(c, b, 1, 20 ); F16_TO_79(c, b, 1, 21 ); \
    F16_TO_79(c, b, 1, 22 ); F16_TO_79(c, b, 1, 23 ); \
    F16_TO_79(c, b, 1, 24 ); F16_TO_79(c, b, 1, 25 ); \
    F16_TO_79(c, b, 1, 26 ); F16_TO_79(c, b, 1, 27 ); \
    F16_TO_79(c, b, 1, 28 ); F16_TO_79(c, b, 1, 29 ); \
    F16_TO_79(c, b, 1, 30 ); F16_TO_79(c, b, 1, 31 ); \
    F16_TO_79(c, b, 1, 32 ); F16_TO_79(c, b, 1, 33 ); \
    F16_TO_79(c, b, 1, 34 ); F16_TO_79(c, b, 1, 35 ); \
    F16_TO_79(c, b, 1, 36 ); F16_TO_79(c, b, 1, 37 ); \
    F16_TO_79(c, b, 1, 38 ); F16_TO_79(c, b, 1, 39 ); \
    F16_TO_79(c, b, 2, 40 ); F16_TO_79(c, b, 2, 41 ); \
    F16_TO_79(c, b, 2, 42 ); F16_TO_79(c, b, 2, 43 ); \
    F16_TO_79(c, b, 2, 44 ); F16_TO_79(c, b, 2, 45 ); \
    F16_TO_79(c, b, 2, 46 ); F16_TO_79(c, b, 2, 47 ); \
    F16_TO_79(c, b, 2, 48 ); F16_TO_79(c, b, 2, 49 ); \
    F16_TO_79(c, b, 2, 50 ); F16_TO_79(c, b, 2, 51 ); \
    F16_TO_79(c, b, 2, 52 ); F16_TO_79(c, b, 2, 53 ); \
    F16_TO_79(c, b, 2, 54 ); F16_TO_79(c, b, 2, 55 ); \
    F16_TO_79(c, b, 2, 56 ); F16_TO_79(c, b, 2, 57 ); \
    F16_TO_79(c, b, 2, 58 ); F16_TO_79(c, b, 2, 59 ); \
    F16_TO_79(c, b, 3, 60 ); F16_TO_79(c, b, 3, 61 ); \
    F16_TO_79(c, b, 3, 62 ); F16_TO_79(c, b, 3, 63 ); \
    F16_TO_79(c, b, 3, 64 ); F16_TO_79(c, b, 3, 65 ); \
    F16_TO_79(c, b, 3, 66 ); F16_TO_79(c, b, 3, 67 ); \
    F16_TO_79(c, b, 3, 68 ); F16_TO_79(c, b, 3, 69 ); \
    F16_TO_79(c, b, 3, 70 ); F16_TO_79(c, b, 3, 71 ); \
    F16_TO_79(c, b, 3, 72 ); F16_TO_79(c, b, 3, 73 ); \
    F16_TO_79(c, b, 3, 74 ); F16_TO_79(c, b, 3, 75 ); \
    F16_TO_79(c, b, 3, 76 ); F16_TO_79(c, b, 3, 77 ); \
    F16_TO_79(c, b, 3, 78 ); F16_TO_79(c, b, 3, 79 ); \
    STEP_3(c)
#endif

RESULT sha1_update(sha1_ctx_p, BYTE*, SHORT);
RESULT sha1_final( sha1_ctx_p, BYTE* );
void sha1_transform(sha1_ctx_p c)  ;