/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)

*/

#include "bignum.h"

/*!
  \brief: Free variables U, V, X1, X2 used for modinv A^1 mod P
*/
#define modinv_cleanup( a, b, c, d) \
    flint( a );                     \
    flint( b );                     \
    flint( c );                     \
    flint( d )

/*!
  \brief: cauculate A^-1 mod P
          placing temp variables on heap
  \param1: [IN] Integer A of which we want to calculate inverse
           mod P
  \param2: [IN] Integer P
  \param3: [INOUT] Result R
  \note: Guide to Elliptic curve cryptography page 60
         when using in a loop, more often that not we dont
         want to resize. Ex when using ECC once we have the
         size of prime P used in Fp, and size of ECPoint(Xp, Yp)
         are known, we need not calloc, free on every iteration.
         Thats the idea behind creating init, cleanup routines
  \return: R = A^-1 mod P on success, RESULT on failure.
*/
RESULT modinv_heap( Integer A, Integer P, Integer R )
{
    result_init( _res_ );
    Integer U, V, X1, X2;
    _res_ = modinv_init( A, P, R, &U, &V, &X1, &X2 );
    if( _res_ != OK )
        goto done;
    modinv_( A, P, R, U, V, X1, X2 );
done:
    modinv_cleanup( U, V, X1, X2 );
    return _res_;
}

/*!
  \brief: cauculate A^-1 mod P
          placing temp variables on stack
  \param1: [IN] Integer A of which we want to calculate inverse
           mod P
  \param2: [IN] Integer P
  \param3: [INOUT] Result R
  \note: This is the same as modinv except tmp variables are
         allocated on the stack.
  \return: R = A^-1 mod P on success, RESULT on failure.
*/
RESULT modinv_stack( Integer A, Integer P, Integer R )
{
    RESULT _res_ = 0;
    BYTE u_[MAX_MODINV_TMP_VAR_LEN];
    BYTE v_[MAX_MODINV_TMP_VAR_LEN];
    BYTE x1[MAX_MODINV_TMP_VAR_LEN];
    BYTE x2[MAX_MODINV_TMP_VAR_LEN];
    lint( U, u_ );
    lint( V, v_ );
    lint( X1, x1 );
    lint( X2, x2 );
    _res_ = modinv_( A, P, R, U, V, X1, X2 );
    if( _res_ != OK )
        return _res_;
    return OK;
}

/*!
  \brief: Initialize variables for A^1 mod P
  \param1: [IN] Integer A
  \param2: [IN] Integer P
  \param3  [INOUT] variables calloced after size calculation
  \return: mvars if success, RESULT if failure
*/
RESULT modinv_init( Integer A, Integer P, Integer R,
                    Integers u, Integers v, Integers x1,
                    Integers x2 )
{
    SHORT j;
    result_init(_res_);
    j = MAX( A->size, P->size) + SZ_WORD_B;
    if( R->size < j )
    {
        return MODINV_RESULT_SZ_TOO_SMALL;
    }
    mint( U , A->size );
    mint( V , P->size );
    mint( X1, j );
    mint( X2, j );
    *u = U;
    *v = V;
    *x1 = X1;
    *x2 = X2;
    return OK;

no_mem_:
    _res_ = MODINV_NOMEM;
    flint( U );
    flint( V );
    flint( X1 );
    flint( X2 );
    *u = *v = *x1 = *x2 = NULL;
    return _res_;
}

/*!
 * \brief: calculate X1 or X2 in the modular inverse algorithm
 *         counting the trailing zeros.
 * \param [INOUT] X, that we want to calculate after a ctz operation
 * \param [IN]    P, modulus i.e. calculations are mod(P)
 * \param [INOUT] T, temporary Integer to hold X*m where m is determined
 *                based on X+P 's last byte.
 * \param [IN]    r, the number of places U or V was shifted
 */
RESULT modinv_ctz_calc_x( Integer X, Integer P, Integer T, BYTE r )
{
    /*
     * 0xFF << 8 + 0xFF produces a carry
     * So the length needed is actually 3 bytes
     * or 2*r+1 bytes where r (in our case) is 8
     * at most
     */
    SHORT a, m;
    SWORD x;
    SSHORT i, j, c;
    SBYTE xneg, pneg;
    i = j = a = m = c = x = 0;
    xneg = (X->flags & NEGATIVE)? -1:1;
    pneg = 1;
    if( byte_ctz( X->buf[X->size -1] ) >= r )
    {
        rshift_n( X, r );
        return OK;
    }
    i = r;
    x = X->buf[ X->size -1] * xneg;
    while( i > 0 )
    {
        /* m = shifts */
        if( x & (1 << m) )
        {
            /*
             * R[i] = X[i] + P[i]
             * P is never negative, X can be
             * Carry is -1 or whatever is from two unsigned
             * bytes whose carry upon add cannot exceed or
             *  equal SBYTE = -1
             *  BUT if |X| > P and X < 0 we make P negative
             *  ^^ is also the reason we don't write x yet.
             */
            x += ( ( SSHORT )( P->buf[P->size - 1] << m ) );
            /* Save the number that we will multiply with in c */
            c |= (1 << m);
        }
        m++;
        i--;
    }
    /* we save the multiplier in m */
    m = c;
    /* debug */
    printf( "\ncalc x = [%04x]  c = [%02X] m = [%02X] "
            "X->buf[%d]=[%02X] " HEXCALC_OPEN "(", x, c, m,
            X->size - 1, X->buf[ X->size - 1 ]);
    printInteger(P);
    printf( "*" );
    printf( "%02X)" HEXCALC_CLOSE " = ", m );
    /* end debug */
    i = T->size;
    c = 0;
    /* T = P * m */
    for( j = P->size -1; j >= 0; j-- )
    {
        a = P->buf[j] * m + c;
        T->buf[--i] = (BYTE) a;
        c = (BYTE) (a >> 8);
    }
    T->buf[--i] = c;
    setOffset( T );
    /* debug */
    printInteger(T);
    printf( "\n add n shft " HEXCALC_OPEN "((" );
    printInteger( T );
    printf( ")+(");
    printInteger( X );
    printf( "))/" );
    printf( "%02X" HEXCALC_CLOSE " = ", (1 << r ) );
    /* end debug */
    x = cmp_(X, T, x);
    if( ( xneg < 0 ) && ( x == L_GT_R ) )
    {
        xneg = 1;
        pneg = -1;
        T->flags |= NEGATIVE;
    }
    i = X->size - 1;
    j = T->bytelen - 1;
    if( i < j )
    {
        return MINV_CTZ_CALC_X_BUF_TOO_SMALL;
    }
    c = 0;
    j = T->size - 1;
    m = T->size - T->bytelen;
    while( j >= m )
    {
        x  = ( T->buf[j] * pneg );
        x += ( X->buf[i] * xneg );
        x += c;
        a = ( (BYTE) x ) << (SZ_BYTE - r);
        X->buf[i + 1] = ( X->buf[i + 1] | (BYTE) a );
        c  = ( x >> SZ_BYTE);
        x  = ( ( (BYTE) x ) >> r);
        X->buf[i] = (BYTE) x;
        /* keep resetting T since we no longer need it */
        T->buf[j] = 0;
        i--;
        j--;
    }
    /* j can be at most P->bytelen + 1, make sure X->size
     * is more or even == P->bytelen + 1 before calling
     * this function */
    while( i >= 0 )
    {
        x = (SSHORT) ( X->buf[i] * xneg ) + c;
        a = ( ( (BYTE) x ) << (SZ_BYTE - r) );
        X->buf[i + 1] = ( X->buf[i + 1] | (BYTE) a );
        c = ( x >> SZ_BYTE );
        x  = ( ( (BYTE) x ) >> r );
        X->buf[i] = (BYTE) x;
        i--;
    }
    /* debug */
    printInteger(X);
    printf( "\n" );
    /* end debug */
    X->flags = T->flags;
    T->flags = 0;
    setOffset( X );
    return OK;
}
/*!
  \brief: cauculate A^-1 mod P, main loop
  \param1: Integer A of which we want to calculate inverse
           mod P
  \param2: Integer P
  \param3: Result R
  \param4: Temp variable U
  \param5: Temp variable V
  \param6: Temp variable X1
  \param7: Temp variable X2
  \note:  Straight up implementation from
          Guide to Elliptic curve cryptography page 60
*/
RESULT modinv_( Integer A, Integer P, Integer  R,
                Integer U, Integer V, Integer X1,
                                     Integer X2 )
{
    /* debug */
    //#define cmp_(x, y, z) cmp(x, y)
    /* end debug */
    RESULT _res_;
    SWORD r;
    _res_ = r = 0;
    BYTE f = A->flags;
    A->flags = 0;
    SHORT i = 0;
    /* u<-a, v<-p, x1<-0, x2<-0 */
    reset( U );
    reset( V );
    reset( X1 );
    reset( X2 );
    setBit(X1, 1 );
    copy( U, A );
    copy( V, P );

    while( U->top != 1 &&
           V->top != 1 )
    {
        /* debug */
        printf( "\n%d] U = ", i );
        printInteger( U );
        printf( ", V = " );
        printInteger( V );
        printf( ", X1 = " );
        printInteger( X1 );
        printf( ", X2 = " );
        printInteger( X2 );
        printf( "\n" );
        /* end debug */
        do
        {
            /* r can be more than 8 bits */
            r = byte_ctz( (U->buf[ U->size - 1 ]) );
            if( r )
            {
                /* debug */
                printf( "\tU ctz [%d] " HEXCALC_OPEN, r );
                printInteger( U );
                printf( "/%d" HEXCALC_CLOSE  " = ", r );
                /* end debug */
                /*
                 * rshift and ctz calc can do at most 8 bits,
                 *  hence another loop
                 */
                rshift_n( U, r );
                _res_ = modinv_ctz_calc_x( X1, P, R, r );
            }
        } while( r );
        do
        {
            r = byte_ctz( (V->buf[ V->size - 1 ]) );
            if( r )
            {
                /* debug */
                printf( "\tV ctz [%d] " HEXCALC_OPEN, r );
                printInteger( V );
                printf( "/2" HEXCALC_CLOSE " = " );
                /* end debug */
                /*
                 * rshift and ctz calc can do at most 8 bits,
                 *  hence another loop
                 */
                rshift_n( V, r );
                _res_ = modinv_ctz_calc_x( X2, P, R, r );
            }
        } while( r );
        r = cmp_( U, V, r );
        if( r == L_GT_R ||
            r == L_EQ_R )
        {
            /* debug */
            printf( "U >= V, U - V = " HEXCALC_OPEN "(");
            printInteger( U );
            printf( "-(" );
            printInteger( V );
            printf( "))" HEXCALC_CLOSE " = " );
            /* end debug */

            /* if u >= v
               u <- u - v
               x1 = x1 - x2 */
            _res_ = sub( U, V, U );
            if( _res_ != OK )
            {
                A->flags = f;
                return MINV_SUB_U_V_FAILED;
            }
            /* debug */
            printInteger( U );
            printf(", X1-X2 = " HEXCALC_OPEN "(");
            printInteger( X1 );
            printf( "-(" );
            printInteger( X2 );
            printf( "))" HEXCALC_CLOSE " = " );
            /* end debug */

            _res_ = sub( X1, X2, X1 );
            if( _res_ != OK )
            {
                A->flags = f;
                return MINV_SUB_X1_X2_FAILED;
            }
            /* debug */
            printInteger( X1 );
            printf( "\n" );
            /* end debug */

        } else
        {
            /* debug */
            printf( "U < V, V - U = " HEXCALC_OPEN "(");
            printInteger( V );
            printf( "-(" );
            printInteger( U );
            printf( "))" HEXCALC_CLOSE " = " );
            /* end debug */

            /* else v > u
               v <- v - u
               x2 = x2 - x1 */
            _res_ = sub( V, U, V );
            if( _res_ != OK )
            {
                A->flags = f;
                return MINV_SUB_V_U_FAILED;
            }
            /* debug */
            printInteger( V );
            printf("\nX2-X1 = " HEXCALC_OPEN "(");
            printInteger( X2 );
            printf( "-(" );
            printInteger( X1 );
            printf( "))" HEXCALC_CLOSE " = " );
            /* end debug */

            _res_ = sub( X2, X1, X2 );
            if( _res_ != OK )
            {
                A->flags = f;
                return MINV_SUB_X2_X1_FAILED;
            }
            /* debug */
            printInteger( X2 );
            printf( "\n" );
            /* end debug */
        }
        if( U->top == 0 || V->top == 0 )
        {
            return MINV_DOES_NOT_EXIST;
        }
        /* debug */
        i++;
        /* end debug */
    }

    /* Actually these should be mod P
       but this number will work too */

    if( U->top == 1 )
    {
        copy( R, X1 );
    } else
    {
        copy( R, X2 );
    }
    i = 0;
    while( cmp_( R , P, r ) == L_GT_R )
    {
        _res_ = sub( R, P, R );
        if( _res_ != OK )
        {
            return MINV_SUB_R_P_FAILED;
        }
        i++;
        if( i > 2 )
        {
            return MINV_SUB_R_P_ITERS;
        }
    }
    /* if A is -ve and if X = 1/A mod P
     *                 then -1/A mod P = P - X
     * Example modinv( 5, 7 ) = 3
     * (7 - 3) = 4 should be equal to -1/5 mod 7
     * since (5*4 mod 7) = 6 mod 7 = -1 mod 7
     * 4 = -1/5 mod 7
     */
    if( f & NEGATIVE )
    {
        if( R->flags & NEGATIVE )
        {
            R->flags &= ~NEGATIVE;
        }
        else
        {
            _res_ = sub( P, R, R );
        }
    }
    if( R->flags & NEGATIVE )
    {
        _res_ = add( R, P, R );
    }
    A->flags = f;
    return OK;
}
