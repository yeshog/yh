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
    RESULT _res_, r;
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

        while( isEven( U ) )
        {
            /* debug */
            printf( "\tU is even " HEXCALC_OPEN );
            printInteger( U );
            printf( "/2" HEXCALC_CLOSE  " = " );
            /* end debug */

            /* u <- u/2 */
            rshift( U, 1 );

            /* debug */
            printInteger( U );
            printf( "\n" );
            /* end debug */

            if( isEven( X1 ) )
            {
                /* debug */
                printf( "\t\t X1 is even " HEXCALC_OPEN );
                printInteger( X1 );
                printf( "/2" HEXCALC_CLOSE " = " );
                /* end debug */

                /* x1 <- x1/2 */
                rshift( X1, 1 );

                /* debug */
                printInteger( X1 );
                printf( "\n" );
                /* end debug */
            } else
            {
                /* debug */
                printf( "\t\tX1 is odd (X1 + P)/2 "
                        HEXCALC_OPEN "(" );
                printInteger( X1 );
                printf( "+" );
                printInteger( P );
                printf( ")/2" HEXCALC_CLOSE " = " );
                /* end debug */

                /* x1 = ( x1 + p )/2 */
                _res_ = add( X1, P, X1 );
                if( _res_ != OK )
                {
                    A->flags = f;
                    return MINV_X1_ODD_ADD_FAILED;
                }
                rshift( X1, 1 );

                /* debug */
                printInteger( X1 );
                printf( "\n" );
                /* end debug */
            }
        }
        while( isEven( V ) )
        {
            /* debug */
            printf( "\tV is even " HEXCALC_OPEN );
            printInteger( V );
            printf( "/2" HEXCALC_CLOSE " = " );
            /* end debug */

            /* v <- v/2 */
            rshift( V, 1 );

            /* debug */
            printInteger( V );
            printf( "\n" );
            /* end debug */

            if( isEven( X2 ) )
            {
                /* debug */
                printf( "\t\tX2 is even " HEXCALC_OPEN );
                printInteger( X2 );
                printf( "/2" HEXCALC_CLOSE " = " );
                /* end debug */

                /* x2 <- x2/2 */
                rshift( X2, 1 );

                /* debug */
                printInteger( X2 );
                printf( "\n" );
                /* end debug */

            } else
            {
                /* debug */
                printf( "\t\tX2 is odd (X2 + P)/2 "
                        HEXCALC_OPEN "(" );
                printInteger( X2 );
                printf( "+" );
                printInteger( P );
                /* end debug */

                /* x2 = ( x2 + p )/2 */
                _res_ = add( X2, P, X2 );
                if( _res_ != OK )
                {
                    A->flags = f;
                    return MINV_X2_ODD_ADD_FAILED;
                }
                rshift( X2, 1 );

                /* debug */
                printf( ")/2" HEXCALC_CLOSE " = " );
                printInteger( X2 );
                printf( "\n" );
               /* end debug */
            }
        }
        r = cmp( U, V );
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
    while( cmp( R , P ) == L_GT_R )
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

