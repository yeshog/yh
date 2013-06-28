#include "tls_handshake.h"
/*!
  \brief   : tls p_hash key expansion function
  \param 3 : [IN] secret for hmac
  \param 5 : [IN] secret length
  \param 6 : [IN] label for P_hash (S2, label + seed)
  \param 7 : [IN] label len
  \param 8 : [IN] seed
  \param 9 : [IN] seed len
  \param 15: [OUT] output
  \param 16: [IN]  output len
*/
void tls_prf( BYTE* s, SHORT s_l, BYTE* l, SHORT l_l,
              BYTE* d, SHORT d_l, BYTE* o, SHORT o_l )
{
    BYTE A  [MD5_LEN];
    BYTE AN [MD5_LEN];
    BYTE B [SHA1_LEN];
    BYTE BN[SHA1_LEN];
    BYTE r = 0;
    SHORT h_l = ( s_l >> 1 ) + ( s_l & 1 );
    BYTE* s_t = s;
    BYTE* s_b = (s_l & 1)? (s + h_l - 1):(s + h_l);
    BYTE* text[3];
    SHORT text_len[3];
    /* A(0) = seed
     * A(i) = HMAC_hash(secret, A(i-1))
     * Where seed = (label + seed), + denoting concat
     * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) + ...
     */
    text[1] = l;
    text_len[1] = l_l;
    text[2] = d;
    text_len[2] = d_l;
    hmac_md5 ( &text[1], &text_len[1], 2, s_t, h_l, A );   /* A(0) md5  */
    hmac_sha1( &text[1], &text_len[1], 2, s_b, h_l, B );   /* A(0) sha1 */
    do
    {
        if( (r % MD5_LEN) == 0 )
        {
            text[0] = A; text_len[0] = MD5_LEN;
            /* HMAC_hash(secret, A(1) + seed)
             * = HMAC_hash(secret, HMAC(secret, A(0)) + seed)
             */
            hmac_md5( text, text_len, 3, s, h_l, AN );
            /* A(2) = HMAC(secret, A(1)) */
            hmac_md5( text, text_len, 1, s, h_l, A );
        }
        if( (r % SHA1_LEN) == 0 )
        {
            text[0] = B; text_len[0] = SHA1_LEN;
            /* HMAC_hash(secret, A(1) + seed) */
            hmac_sha1( text, text_len, 3, s + h_l, h_l, BN );
            /* A(2) = HMAC(secret, A(1)) */
            hmac_sha1( text, text_len, 1, s + h_l, h_l, B );
        }
        /* PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
         * P_SHA-1(S2, label + seed);
         */
        o[r] = AN[ r % MD5_LEN ] ^ BN[ r % SHA1_LEN ];
        r++;
    } while( r < o_l );
}
/*!
  \brief :  hmac_md5, straight up copy
            from RFC 2104
  \param 1: [IN] text, list containing data/text to hmac
  \param 2: [IN] text_len, list containing lengths of data
            specified in parameter 1
  \param 3: [IN] text_ct, number of items in list specified
            in param 1 (and 2)
  \param 4: [IN] hmac secret
  \param 5: [IN] hmac secret len
  \param 6: [OUT] digest, caller allocated 16 bytes
  \note   :
          "abcde"   text[0] text_len[0] = 5
          "efghijk" text[1] text_len[1] = 7
          "lm"      text[2] text_len[2] = 2
          text_ct = 3
*/
void
hmac_md5( BYTE** text, SHORT* text_len, BYTE text_ct,
          BYTE* key,   SHORT key_len,   BYTE* digest )
{
    md5_ctx context;
    BYTE k_ipad[64];    /* inner padding -
                         * key XORd with ipad
                         */
    BYTE k_opad[64];    /* outer padding -
                         * key XORd with opad
                         */
    BYTE tk[16];
    SHORT i;
    /* if key is longer than 64 bytes reset it to key=MD5(key) */
    if (key_len > 64)
    {
        md5_ctx tctx;
        md5_init( &tctx );
        md5_update( &tctx, key, key_len);
        md5_final( &tctx, tk );
        key = tk;
        key_len = 16;
    }
    /*
     * the HMAC_MD5 transform looks like:
     *
     * MD5(K XOR opad, MD5(K XOR ipad, text))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times
     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected
     */
     /* start out by storing key in pads */
     memset( k_ipad, 0, sizeof k_ipad);
     memset( k_opad, 0, sizeof k_opad);
     memcpy( k_ipad, key, key_len );
     memcpy( k_opad, key, key_len );
    /* XOR key with ipad and opad values */
    for (i=0; i<64; i++)
    {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    /*
     * perform inner MD5
     */
    md5_init( &context );                   /* init context for 1st
                                             * pass */
    /* start with inner pad */
    md5_update( &context, k_ipad, 64 );
    for( i=0; i < text_ct; i++ )
    {
        /* then text of datagram */
        md5_update( &context, text[i], text_len[i] );
    }
    md5_final( &context, digest );          /* finish up 1st pass */
    /*
     * perform outer MD5
     */
    md5_init( &context );                   /* init context for 2nd
                                              * pass */
    md5_update( &context, k_opad, 64 );     /* start with outer pad */
    md5_update( &context, digest, 16 );     /* then results of 1st
                                              * hash */
    md5_final( &context, digest );          /* finish up 2nd pass */
}
/*!
  \brief :hmac_sha1
  \param 1: [IN] text, list containing data/text to hmac
  \param 2: [IN] text_len, list containing lengths of data
            specified in parameter 1
  \param 3: [IN] text_ct, number of items in list specified
            in param 1 (and 2)
  \param 4: [IN] hmac secret
  \param 5: [IN] hmac secret len
  \param 6: [OUT] digest, caller allocated 20 bytes
  \note   :
          "abcde"   text[0] text_len[0] = 5
          "efghijk" text[1] text_len[1] = 7
          "lm"      text[2] text_len[2] = 2
          text_ct = 3
*/
void
hmac_sha1( BYTE** text, SHORT* text_len, BYTE text_ct,
           BYTE* key, SHORT key_len, BYTE* digest )
{
    /* TODO: sha1 actually returns result use it? */
    sha1_ctx context;
    BYTE k_ipad[64];    /* inner padding -
                         * key XORd with ipad
                         */
    BYTE k_opad[64];    /* outer padding -
                         * key XORd with opad
                         */
    BYTE tk[20];
    SHORT i;
    /* if key is longer than 64 bytes reset it to key=SHA1(key) */
    if (key_len > 64)
    {
        sha1_ctx tctx;
        sha1_init( &tctx );
        sha1_update( &tctx, key, key_len);
        sha1_final( &tctx, tk );
        key = tk;
        key_len = 20;
    }
    /*
     * the HMAC_SHA1 transform looks like:
     *
     * SHA1(K XOR opad, SHA1(K XOR ipad, text))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times
     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected
     */
     /* start out by storing key in pads */
     memset( k_ipad, 0, sizeof k_ipad);
     memset( k_opad, 0, sizeof k_opad);
     memcpy( k_ipad, key, key_len );
     memcpy( k_opad, key, key_len );
    /* XOR key with ipad and opad values */
    for (i=0; i<64; i++)
    {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    /*
     * perform inner SHA1
     */
    sha1_init( &context );                   /* init context for 1st
                                             * pass */
    sha1_update( &context, k_ipad, 64 );
    for( i = 0; i < text_ct; i++ )
    {
        sha1_update( &context, text[i], text_len[i] );
    }
    sha1_final( &context, digest );          /* finish up 1st pass */
    /*
     * perform outer SHA1
     */
    sha1_init( &context );                   /* init context for 2nd
                                              * pass */
    sha1_update( &context, k_opad, 64 );     /* start with outer pad */
    sha1_update( &context, digest, 20 );     /* then results of 1st
                                              * hash */
    sha1_final( &context, digest );          /* finish up 2nd pass */
}
