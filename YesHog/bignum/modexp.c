/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)

*/

#include "bignum.h"

/*!
    \brief calculate (1/N0) mod 2^16
           used before mont_mul aka P.Montgomery reduction
           aka calculation of ( A * B / 2 ^ w mod N )
    \example
          Variable     Hex value
           A=         10 00 07
           B=   3F 01 11 00 07
           N=         C0 00 11

          n0=            00 11
          A0=            00 07
          B0 =           00 07

         1. mul 7*7 = 49
            ********************************
            * The problem in question is now to
            * Find multiple of  0011 (=17) when added
            * to 49 is divisible by 2^16
            * i.e. (17*x + 49) mod 2^16 = 0 mod 2^16
            **********************************
         2. 17*x = -49 mod 2^16
               x = 49 ( -1/17) mod 2^16
               since (-1/17) mod 2^16 = 61681
                    (save one time .. and use in every step of mont_mul)
               x = -49*61681 mod 2^16
                    ( calculate every time outer loop of mont_mul )
               x = 57823
                   57823*17 + 49
               final number is divisible by 2^16 Hooray!!
*/
SHORT montGetInv( SHORT n0 )
{
    SHORT n0inv = 1;
    WORD t = 0;
    SHORT i=0;
    for ( i=2; i<=SZ_SHORT ; i++ )
    {
        t = (n0*n0inv) % ( RADIX << (i-1) );
        if( t != 1 )
        {
            n0inv += ( RADIX << (i-2) );
        }
    }
    return n0inv;
}


/*!
    \brief calculate R = (A*B)/(2^w) mod N
           Implementation of P.Montgomery reduction
    \param 1:  [in] Integer A
    \param 2:  [in] Integer B
    \param 3:  [in] Integer N
    \param 4:  [in] Integer R
    \param 5: [in] mod inverse of N [ 0 ]
    \return RESULT OK if successful
     Warning! no boundary checks
*/
RESULT mont_mul_fios(Integer A, Integer B,
                     Integer N, Integer R,
                     SHORT n0inv)
{
    SHORT  a, b, c, t, n_f, a_f, b_f;
    WORD p, q, k;
    RESULT r;
    SWORD j = B->size - SZ_W_BY_S;
    SWORD i = A->size - SZ_W_BY_S;
    SWORD n = N->size - SZ_W_BY_S;
    SWORD o = R->size - SZ_W_BY_S;
    SWORD z;
    a_f = fByte( A );
    b_f = fByte( B );
    n_f = fByte( N );
    
    a = b = c = t = z =
    p = q = k = r = 0;

    /* len(R) = len(N) + 4 */
    if( R->size < (N->size - fByte(N)
                       + SZ_WORD_B) )
    {
        r = WRN_MUL_NOT_ENOUGH_SPACE;
    }
    reset(R);
    while( n >= n_f && j >= b_f )
    {
        i = A->size - SZ_W_BY_S;
        o = R->size - SZ_W_BY_S;
        z = N->size - SZ_W_BY_S;
        b = IR_SHORT( B, j );

        /* unroll the first iter */
        a = IR_SHORT( A, i );

        /* p(c,t) = a[i]*b[i] */
        p = a * b + IR_SHORT( R, o );

        /* calculate t to be multiplied to N */
        t = R_SHORT_LSBS_FROM_WORD( p );
        t =  (SHORT) ( ( 
               ( (SWORD) t * -1 )
             * ( (SWORD) n0inv ) )
             % MONT_MOD );

        /*
            A =          00 AA AA| AA AA     AA AA
            B =          00 BB BB| BB BB     BB BB
            N =          00 FF FF| FF FF     FF FF
            t =                              AA AB
            t*N          AA AA FF| FF FF     55 55
                                 |        k        |
                                 |  k1    |  k0    |
            A*B =     7D 27 55 55| 55 54     D8 2E
                                 |        p        |
                                 |   p1   |   p0   |
                                 |   q1   |q0=k0+p0|
         */

        /* k = t * N[0] */
        k = t * IR_SHORT( N, z );
        q = R_SHORT_LSBS_FROM_WORD( k )+
            R_SHORT_LSBS_FROM_WORD( p );

        i -= SZ_W_BY_S;
        z -= SZ_W_BY_S;
        
        while( z >= n_f && i >= a_f )
        {

            a = IR_SHORT( A, i );

            p = (a * b)                      +
                IR_SHORT( R, o - SZ_W_BY_S ) +
                R_SHORT_MSBS_FROM_WORD( p );

            k = t * IR_SHORT( N, z ) +
                R_SHORT_MSBS_FROM_WORD( k );

            q = R_SHORT_MSBS_FROM_WORD( q ) +
                R_SHORT_LSBS_FROM_WORD( p ) +
                R_SHORT_LSBS_FROM_WORD( k );

            IW_SHORT( R, o, R_SHORT_LSBS_FROM_WORD( q ) );

            i -= SZ_W_BY_S;
            z -= SZ_W_BY_S;
            o -= SZ_W_BY_S;
        }

        q = IR_SHORT( R, (o-SZ_W_BY_S) ) +
            R_SHORT_MSBS_FROM_WORD( q )  +
            R_SHORT_MSBS_FROM_WORD( p )  +
            R_SHORT_MSBS_FROM_WORD( k );

        IW_SHORT( R, o,
            R_SHORT_LSBS_FROM_WORD( q ) );
        o -= SZ_W_BY_S;
        IW_SHORT( R, o,
            R_SHORT_MSBS_FROM_WORD( q ) );

        setOffset( R );

        j -= SZ_W_BY_S;
        n -= SZ_W_BY_S;
    } /* while j >= 0 && n >= 0 */
    if( cmp( R, N ) == L_GT_R )
    {
        sub( R, N, R );
    }
    setOffset( R );

    return r;
}

/*!
    \brief calculate c = a^e mod n
           Implementation of P.Montgomery reduction
    \param 1:  [in]   Integer A
    \param 2:  [in]   Integer E
    \param 3:  [in]   Integer N
    \param 5:  [out]  Integer C

    \return RESULT OK if successful
    \warning no boundary checks caller allocates all mem
*/
RESULT mont_modexp_n( Integer A,
                      Integer E,
                      Integer N,
                      Integer C )
{
    RESULT r = 0;
    Integer AR_MOD_N, R_MOD_N;

    /* Step1: AR_MOD_N = A*R mod N */
    r = mont_mul_ar_mod_n( A, N, &AR_MOD_N );
    if( r != OK )
    {
        return MODEXP_ARMODN_FAILED;
    }

    /* Step2: R_MOD_N = A*R mod N */
    r = mont_mul_r_mod_n( N, &R_MOD_N );
    if( r != OK )
    {
        return MODEXP_ARMODN_FAILED;
    }

    /* Step3: Exponentiation */
    r = mont_modexp_loop( A, E, N, C, &AR_MOD_N,
                                      &R_MOD_N);
    return r;
}

RESULT mont_mul_ar_mod_n( Integer A,
                          Integer N,
                          Integers P )
{
    RESULT r      = 0;
    SHORT R_t, R_s, AR_s, Q_s, M_s;
    R_t = R_s = AR_s = Q_s = M_s =0;

    R_t     = N->top + 1;
    /*
      Size Matters: Max RSA modulus 512  bytes
                     A*R is 512+512+1 or rather
                     1024+2 bytes when rounded.
                     Now lets allocate the right
                     size for A*R mod N.
                     Thus: R > 2^k >= N
                     where k is the number of
                     bits in N. R_t = R->top.
      Therefore memory upperbound of this func
      is AR(1026) + Q(514) + M( 514 ) = 2052 bytes,
      not considering variables and parameters on
      stack.
    */
    R_s     = ( R_t +
              ( SIZEOF_BYTE - (R_t & 0x7) ) )
              >> 3;
    /* 16 bit align since we multiply
       shorts */
    R_s = (R_s & 1)? (R_s + 1) : R_s;

    AR_s    = R_s + A->size;
    size_even( AR_s );

    /* 
       If anything more is thrown our way we throw
       up here instead of allowing funny guys access
       to sacred memory
    */

    if( AR_s > MAX_MODULUS_BUF_SZ )
    {
        r = MODEXP_ARMODN_SZ_TOO_BIG;
    }
    /* Quotient of A*R mod N is len(A)+len(R)-
       len(N), */
    Q_s = AR_s - N->size;
    size_even( Q_s );

    /* 
       Temp/Remainder M is NOT really the sz
       remainder but rather a buffer to hold
       the foll where N is the divisor:
       N*WORD << (A->size - (N*WORD)->size) 
    */

    M_s = AR_s + SZ_WORD_B;
    size_even( M_s );
    mint( AR, AR_s );
    mint( Q,   Q_s );
    mint( M,   M_s );
    copy( AR, A );
    lshift( AR, (R_t - 1) );

    /* AR = AR mod N */
    
    if( ( r = divide( AR, N, Q, M ) ) != OK )
    {
        r = MODEXP_ARMODN_FAILED;
        goto done;
    }

    /* 
       Now we dont need the full buffer
       len(AR) = len(A)+len(R), since it
       has been reduced. M has just the
       right size, so use it
    */
    mint( V, ( AR->size - fByte(AR) ) );
    copy( V, AR );
    /* P = AR mod N */
    *P = V;
    goto done;

no_mem_:
    r = NO_MEM;
done:
    flint( M );
    flint( Q );
    flint( AR );
    return r;
}

RESULT mont_mul_r_mod_n( Integer N,
                         Integers T )
{
    RESULT r      = 0;
    SHORT R_t, R_s, I_s, M_s;
    R_t = R_s = M_s = I_s = 0;

    R_t     = N->top + 1;
    /* 
       R(514) + I(2) + M( 514) =  1030 bytes,
      not considering variables and parameters on
      stack.
    */
    R_s     = ( R_t +
              ( SIZEOF_BYTE - (R_t & 0x7) ) )
              >> 3;

    /* Dividend len:R_s is just a
      byte more than N->top */
    R_s = (R_s & 1)? (R_s + 1) : R_s;

    /* Quotient len:I_s could be 1 or perhaps 
      2 but not too large a number */
    I_s = MAX(R_s - N->size, 2);

    /* 
       Temp/Remainder M is NOT really the sz
       remainder but rather a buffer to hold
       the foll where N is the divisor:
       N*WORD << (A->size - (N*WORD)->size)
    */
    M_s = R_s;

    mint( Q, R_s );
    mint( I, I_s );
    mint( M, M_s );

    /* Q = R mod N */
    placeTopBitFromLeft( Q, R_t );
    /* Reuse AR for remainder */
    if( (r = divide( Q, N, I, M ) ) != OK )
    {
      r = MODEXP_DIV_FAILED;
      goto done;
    }

    /* Trim to needed sz */
    mint( V, ( Q->size - fByte(Q) ));
    copy( V, Q );
    *T = V;
    goto done;

no_mem_:
    r = NO_MEM;
done:
    flint( M );
    flint( I );
    flint( Q );
    return r;
}

RESULT mont_modexp_loop( Integer A, Integer E,
                         Integer N, Integer C,
                         Integers     AR_MOD_N,
                         Integers     R_MOD_N )
{
    RESULT r = OK;
    /* One time modinv from N[] */
    SHORT n0inv = montGetInv( R_SHORT( N->buf,
                  N->size - SZ_W_BY_S ) );
    SWORD j     = E->top - 1;

    /*
       We need len(AR_MOD_N)+4 since reduction
       takes place at evey loop.
       Fortunately the right size was allocated
       in mont_mul_ar_mod_n
    */
    SHORT Q_s   = MAX( (*AR_MOD_N)->size,
                       (*R_MOD_N)->size ) + SZ_WORD_B;
    /* Integer to hold result */
    mint( Q, Q_s );

    /* We need all sizes same since we exchange
       ARMODN with Result and viceversa later in
       loop */

    mint( ARMODN, Q_s );
    copy( ARMODN, (*AR_MOD_N) );
    flint( (*AR_MOD_N) );

    mint( RMODN, Q_s );
    copy( RMODN, (*R_MOD_N) );
    flint( (*R_MOD_N) );

    /* Exponentiation loop */
    for( ; j >= 0; j-- )
    {
        mont_mul_fios( RMODN, RMODN,
                      N, Q, n0inv );

        i_xchg( RMODN, Q );
        if( bitAtPosition( E, j ) )
        {
            mont_mul_fios( RMODN, ARMODN,
                           N, Q, n0inv );
            i_xchg( RMODN, Q );
        }
    }
    /* 
     * AR has the result
     * Finally Residue = mont_mul( 1, AR )
     */
    mint( I, Q_s );
    placeTopBitFromLeft( I, 1 );

    /* cheat */
    I->topByte = RMODN->topByte;
    mont_mul_fios( RMODN, I, N, Q, n0inv );

    /* Q contains the result */
    copy( C, Q );
    goto done;

no_mem_:
    r = NO_MEM;
done:
    flint( ARMODN );
    flint( RMODN );
    flint( Q );
    flint( I );
    return r;
}
