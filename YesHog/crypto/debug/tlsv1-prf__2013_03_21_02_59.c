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
/* debug */
/**
 * md5_vector - MD5 hash for data vector
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash
 * Returns: 0 on success, -1 of failure
 */
int md5_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	md5_ctx ctx;
	size_t i;

	md5_init(&ctx);
	for (i = 0; i < num_elem; i++)
		md5_update(&ctx, addr[i], len[i]);
	md5_final(&ctx, mac);
	return 0;
}
/**
 * hmac_md5_vector - HMAC-MD5 over data vector (RFC 2104)
 * @key: Key for HMAC operations
 * @key_len: Length of the key in bytes
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash (16 bytes)
 * Returns: 0 on success, -1 on failure
 */
int hmac_md5_vector(const u8 *key, size_t key_len, size_t num_elem,
		    const u8 *addr[], const size_t *len, u8 *mac)
{
	u8 k_pad[64]; /* padding - key XORd with ipad/opad */
	u8 tk[16];
	const u8 *_addr[6];
	size_t i, _len[6];

	if (num_elem > 5) {
		/*
		 * Fixed limit on the number of fragments to avoid having to
		 * allocate memory (which could fail).
		 */
		return -1;
	}

        /* if key is longer than 64 bytes reset it to key = MD5(key) */
        if (key_len > 64) {
		if (md5_vector(1, &key, &key_len, tk))
			return -1;
		key = tk;
		key_len = 16;
        }

	/* the HMAC_MD5 transform looks like:
	 *
	 * MD5(K XOR opad, MD5(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected */

	/* start out by storing key in ipad */
	os_memset(k_pad, 0, sizeof(k_pad));
	os_memcpy(k_pad, key, key_len);

	/* XOR key with ipad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x36;

	/* perform inner MD5 */
	_addr[0] = k_pad;
	_len[0] = 64;
	for (i = 0; i < num_elem; i++) {
		_addr[i + 1] = addr[i];
		_len[i + 1] = len[i];
	}
	if (md5_vector(1 + num_elem, _addr, _len, mac))
		return -1;

	os_memset(k_pad, 0, sizeof(k_pad));
	os_memcpy(k_pad, key, key_len);
	/* XOR key with opad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x5c;

	/* perform outer MD5 */
	_addr[0] = k_pad;
	_len[0] = 64;
	_addr[1] = mac;
	_len[1] = MD5_MAC_LEN;
	return md5_vector(2, _addr, _len, mac);
}


/**
 * hmac_md5 - HMAC-MD5 over data buffer (RFC 2104)
 * @key: Key for HMAC operations
 * @key_len: Length of the key in bytes
 * @data: Pointers to the data area
 * @data_len: Length of the data area
 * @mac: Buffer for the hash (16 bytes)
 * Returns: 0 on success, -1 on failure
 */
int hmac_md5_w(const u8 *key, size_t key_len, const u8 *data, size_t data_len,
	      u8 *mac)
{
	return hmac_md5_vector(key, key_len, 1, &data, &data_len, mac);
}

/**
 * sha1_vector - SHA-1 hash for data vector
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash
 * Returns: 0 on success, -1 of failure
 */     
int sha1_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{       
        sha1_ctx ctx;
        size_t i; 
        
        sha1_init(&ctx);
        for (i = 0; i < num_elem; i++)
                sha1_update(&ctx, addr[i], len[i]);
        sha1_final(&ctx, mac);
        return 0;
}

/**
 * hmac_sha1_vector - HMAC-SHA1 over data vector (RFC 2104)
 * @key: Key for HMAC operations
 * @key_len: Length of the key in bytes
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash (20 bytes)
 * Returns: 0 on success, -1 on failure
 */
int hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem,
		     const u8 *addr[], const size_t *len, u8 *mac)
{
	unsigned char k_pad[64]; /* padding - key XORd with ipad/opad */
	unsigned char tk[20];
	const u8 *_addr[6];
	size_t _len[6], i;

	if (num_elem > 5) {
		/*
		 * Fixed limit on the number of fragments to avoid having to
		 * allocate memory (which could fail).
		 */
		return -1;
	}

        /* if key is longer than 64 bytes reset it to key = SHA1(key) */
        if (key_len > 64) {
		if (sha1_vector(1, &key, &key_len, tk))
			return -1;
		key = tk;
		key_len = 20;
        }

	/* the HMAC_SHA1 transform looks like:
	 *
	 * SHA1(K XOR opad, SHA1(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected */

	/* start out by storing key in ipad */
	os_memset(k_pad, 0, sizeof(k_pad));
	os_memcpy(k_pad, key, key_len);
	/* XOR key with ipad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x36;

	/* perform inner SHA1 */
	_addr[0] = k_pad;
	_len[0] = 64;
	for (i = 0; i < num_elem; i++) {
		_addr[i + 1] = addr[i];
		_len[i + 1] = len[i];
	}
	if (sha1_vector(1 + num_elem, _addr, _len, mac))
		return -1;

	os_memset(k_pad, 0, sizeof(k_pad));
	os_memcpy(k_pad, key, key_len);
	/* XOR key with opad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x5c;

	/* perform outer SHA1 */
	_addr[0] = k_pad;
	_len[0] = 64;
	_addr[1] = mac;
	_len[1] = SHA1_MAC_LEN;
	return sha1_vector(2, _addr, _len, mac);
}


/**
 * hmac_sha1 - HMAC-SHA1 over data buffer (RFC 2104)
 * @key: Key for HMAC operations
 * @key_len: Length of the key in bytes
 * @data: Pointers to the data area
 * @data_len: Length of the data area
 * @mac: Buffer for the hash (20 bytes)
 * Returns: 0 on success, -1 of failure
 */
int hmac_sha1_w(const u8 *key, size_t key_len, const u8 *data, size_t data_len,
	       u8 *mac)
{
	return hmac_sha1_vector(key, key_len, 1, &data, &data_len, mac);
}

/**
 * tls_prf_sha1_md5 - Pseudo-Random Function for TLS (TLS-PRF, RFC 2246)
 * @secret: Key for PRF
 * @secret_len: Length of the key in bytes
 * @label: A unique label for each purpose of the PRF
 * @seed: Seed value to bind into the key
 * @seed_len: Length of the seed
 * @out: Buffer for the generated pseudo-random key
 * @outlen: Number of bytes of key to generate
 * Returns: 0 on success, -1 on failure.
 *
 * This function is used to derive new, cryptographically separate keys from a
 * given key in TLS. This PRF is defined in RFC 2246, Chapter 5.
 */
int tls_prf_sha1_md5(const u8 *secret, size_t secret_len, const char *label,
		     const u8 *seed, size_t seed_len, u8 *out, size_t outlen)
{
	size_t L_S1, L_S2, i;
	const u8 *S1, *S2;
	u8 A_MD5[MD5_MAC_LEN], A_SHA1[SHA1_MAC_LEN];
	u8 P_MD5[MD5_MAC_LEN], P_SHA1[SHA1_MAC_LEN];
	int MD5_pos, SHA1_pos;
	const u8 *MD5_addr[3];
	size_t MD5_len[3];
	const unsigned char *SHA1_addr[3];
	size_t SHA1_len[3];

	if (secret_len & 1)
		return -1;

	MD5_addr[0] = A_MD5;
	MD5_len[0] = MD5_MAC_LEN;
	MD5_addr[1] = (unsigned char *) label;
	MD5_len[1] = os_strlen(label);
	MD5_addr[2] = seed;
	MD5_len[2] = seed_len;

	SHA1_addr[0] = A_SHA1;
	SHA1_len[0] = SHA1_MAC_LEN;
	SHA1_addr[1] = (unsigned char *) label;
	SHA1_len[1] = os_strlen(label);
	SHA1_addr[2] = seed;
	SHA1_len[2] = seed_len;

	/* RFC 2246, Chapter 5
	 * A(0) = seed, A(i) = HMAC(secret, A(i-1))
	 * P_hash = HMAC(secret, A(1) + seed) + HMAC(secret, A(2) + seed) + ..
	 * PRF = P_MD5(S1, label + seed) XOR P_SHA-1(S2, label + seed)
	 */

	L_S1 = L_S2 = (secret_len + 1) / 2;
	S1 = secret;
	S2 = secret + L_S1;
	if (secret_len & 1) {
		/* The last byte of S1 will be shared with S2 */
		S2--;
	}

	hmac_md5_vector(S1, L_S1, 2, &MD5_addr[1], &MD5_len[1], A_MD5);
	hmac_sha1_vector(S2, L_S2, 2, &SHA1_addr[1], &SHA1_len[1], A_SHA1);

	MD5_pos = MD5_MAC_LEN;
	SHA1_pos = SHA1_MAC_LEN;
	for (i = 0; i < outlen; i++) {
		if (MD5_pos == MD5_MAC_LEN) {
			hmac_md5_vector(S1, L_S1, 3, MD5_addr, MD5_len, P_MD5);
			MD5_pos = 0;
			hmac_md5_w(S1, L_S1, A_MD5, MD5_MAC_LEN, A_MD5);
		}
		if (SHA1_pos == SHA1_MAC_LEN) {
			hmac_sha1_vector(S2, L_S2, 3, SHA1_addr, SHA1_len,
					 P_SHA1);
			SHA1_pos = 0;
			hmac_sha1_w(S2, L_S2, A_SHA1, SHA1_MAC_LEN, A_SHA1);
		}

		out[i] = P_MD5[MD5_pos] ^ P_SHA1[SHA1_pos];

		MD5_pos++;
		SHA1_pos++;
	}

	return 0;
}

/* end debug */

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
