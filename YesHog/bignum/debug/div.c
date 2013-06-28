/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/
#include "bignum.h"

/*!
    \brief divide two big integers Q = A/B + R
    \param 1: [in] Integer A
    \param 2: [in] Integer B
    \param 3: [inout] Integer quotient Q
    \param 4: [inout] Integer remainder R
    \return RESULT OK TODO: check errors
    \note R is not actually used rather A is
          reduced and carries remainder.
          R is a tmp buf that *should* be allocated
          2*A->size for multiplications.
    \warning no boundary checks
*/

RESULT divide ( Integer A, Integer B,
               Integer Q, Integer R )
{
    /* division by 0 */
    if ( B->top == 0 )
    {
        return DIVISOR_ZERO;
    }
    /* A < B leave all untouched */
    if ( A->top < B->top )
    {
       return OK;
    }
    /* A / 1 */
    if( B->top == 1 )
    {
        copy( Q, A );
        reset( A );
        return OK;
    }
    if( R-> size < A->size )
    {
        return DIV_TMP_BUF_TOO_SMALL;
    }
    BYTE x[2];
    WORD a, m, n;
    SWORD r;
    SHORT i, shl, she, c;
    a = m = n = i = r = shl = she = c = 0;

    WORD q = div_q_top( A, B, Q );

    /* debug */
    printf("Q size [%u] q = sz [%u] A sz [%u] B sz [%u]\n",
            Q->size, q, (A->size - A->topByte),
            (B->size - B->topByte) );
    /* end debug */

    reset ( Q );
    reset ( R );

    /* debug */
    printf("\n" HEXCALC_OPEN);
    printInteger( A );
    printf("/");
    printInteger( B );
    printf(HEXCALC_CLOSE "\n");
    /* end debug */

    m = getTopWordSafe( B, 3 );
    n = getTopWordSafe( B, 4 );

    while ( A->top >= B->top )
    {
        if ( A->top == B->top )
        {
            if( cmp( A, B ) == L_LT_R )
            {
                break;
            }
        }
        /* leading digits of dividend*/
        a = getTopWordSafe( A, 4 );
        r = (SHORT) (a/m);
        /* When the topByte is same we are within
           a digit */
        if( A->bytelen == B->bytelen )
        {
            r = (BYTE) (a/n);
        }
        /*
           790000 / 791 (decimal). Now we take 2 leading
           digits of A = 79 and 1 of B = 7 and get q = 11
           Then we multiply B*11 to get 8701 and then cmp
           7900 to 8701 finally subtracting 8701 - 791-791
           to get 7119 and q = 9 which is the right answer
        */
        W_SHORT( x, 0, r );

        /* debug */
        printf( "\n" HEXCALC_OPEN );
        printInteger( B );
        printf("*");
        printf( "%04X", r );
        printf( HEXCALC_CLOSE " = " );
        /* end debug */

        if( mul_( B->buf + B->topByte, B->bytelen, x, 2,
                               R->buf, R->size ) != OK )
        {
            return DIV_MUL_FAILED;
        }
        setOffset( R );

        /* debug */
        printInteger( R );
        printf( "\n" );
        /* end debug */

        do {
            if( A->buf[ A->topByte ] == 1 &&
                R->buf[ R->topByte ] != 1 )
            {   /* We handle this special case later */
                break;
            }
            a = compare( A->buf + A->topByte,
                         R->buf + R->topByte,
                         R->bytelen );
            if( a == L_LT_R )
            {
                /* debug */
                printf( "B > A, R = R - B, " HEXCALC_OPEN );
                printInteger( R );
                printf( "-" );
                printInteger( B );
                printf( " = " );
                /* end debug */

                sub( R, B, R );
                /* debug */
                printInteger( R );
                printf( "\n" );
                /* end debug */
                c = w_len( r );
                r--;
                if( (w_len( r )) < c )
                    q++;
            }
        } while( a == L_LT_R );

        /* use R as a temp var */
        she = R->bytelen;
        if( A->buf[A->topByte] == 1 && R->buf[R->topByte] != 1 )
        {   /* For the case of 0x01000000/0xFF
               or say 10000/99 we shift less 1
               10000
              - 9900
               then q also shifts + 1
               This never happens */
            she = R->bytelen + 1;
        }
        shl = ( A->bytelen - she ) * SIZEOF_BYTE;
        lshift( R, shl );

        /* debug */
        printf("Sub Iteration [%u] Shifts [%u] \n", i, shl);
        printf( "A = A - R " HEXCALC_OPEN );
        printInteger( A );
        printf("-");
        printInteger( R );
        printf( HEXCALC_CLOSE " = " );
        /* end debug */

        sub( A, R, A );

        /* debug */
        printInteger( A );
        printf( "\n" );
        /* end debug */

        if( A->flags & NEGATIVE )
        {
            /* We expect the remainder to be
               positive. A negative remainder
               means a wtf moment */
            A->flags ^= NEGATIVE;
            return UNEXPECTED_NEG_REMAINDER; 
        }
        if( q >= Q->size )
        {
            return QUOTIENT_OVERFLOW;
        }
        if( r <= 0 )
        {
            return UNEXPECTED_MULTIPLIER;
        }
        /* a/m yielded w_len bytes of quotient
           ex. FFFFFFFF/010000.
        */
        switch( (w_len(r)) ) {
            case 1:
                Q->buf[q] = (BYTE) r;
                break;
            case 2:
                W_SHORT( Q->buf, q, (SHORT) r );
                break;
            /* case 3, 4 for future use when we do
               WORD/BYTE if we ever do so */
        }
        setOffset( Q );
        /* Start over again */
        q = div_q_top( A, B, Q );
        /* debug */
        printf( " = " );
        printInteger( A );
        printf( "\n" );
        /* end debug */

        reset( R );
        /* debug */
        printf("\n Quotient Iteration [%u] offset [%u]\n", i, q );
        printInteger( Q );
        printf( "\n" );
        /* end debug */
        i++;
    }
    /* debug */
    printf("RESULT Iteration [%u] offset [%u] Quotient ", i, q );
    printInteger( Q );
    printf( " Remainder " );
    printInteger( A );
    printf( "\n" );
    /* end debug */
    return OK;
}

/*!
    \brief R = A % B
    \param 1: [in] Integer A
    \param 2: [in] Integer B
    \param 3: [out] Integer R
    \return RESULT OK or error
    \note Size Matters: allocates/deallocates 2A + (A-B)
          R is allocated by caller.
    \warning .
*/
RESULT mod( Integer A, Integer B, Integer R )
{
    RESULT _res_ = OK;
    BYTE neg = A->flags;
    mint( Q, div_q_sz( A, B ) );
    cint( A1, A );
    A1->flags = 0;
    _res_ = divide( A1, B, Q, R );
    if( _res_ != OK )
        goto done;
    if( neg & NEGATIVE )
    {
        _res_ = sub( B, A1, A1 );
    }
    copy( R, A1 );
    goto done;
no_mem_:
    _res_ = DIV_MOD_NO_MEM;
done:
    flint( Q );
    flint( A1 );
    return _res_;
}

/*!
    \brief Q = A/B
    \param 1: [in] Integer A
    \param 2: [in] Integer B
    \param 3: [out] Integer Q
    \return RESULT OK or error
    \note Size Matters: allocates/deallocates 2*A + 4 bytes
    \warning Caller please use div_q_sz to calculate Q->size
*/
RESULT div_quotient( Integer A, Integer B, Integer Q )
{
    RESULT _res_ = OK;
    cint( A1, A );
    mint( R, A1->size + SZ_WORD_B );
    _res_ = divide( A1, B, Q, R );
    goto done;
no_mem_:
    _res_ = DIV_MOD_NO_MEM;
done:
    flint( R );
    flint( A1 );
    return _res_;
}

/*!
  \brief: barrett modular reduction, get _mu_
  \param1: [IN] B modulus
  \param2: [OUT] Integer** R. 2 or 3 variables are allocated
                 If R[2] is not null, it is assumed that the _mu_
                 value is pre-allocated and pre-calculated and not
                 allocated by this function.
                 R[0] = Output variable for mod_barrett_reduce
                 R[1] = Temp variable used for mod_barrett_reduce
                 R[2] = _mu_ value used in mod_barrett_reduce
  \note:
        1. For calculating A mod B, we:
           Qo = A >> len(B)-1 = A/radix^(k-1)
           Q = Qo * _mu_ = Qo * (radix^2k/B)
           Q = Q >> len(B) = Q/(radix^(k+1))
           Qo = A - Q
        2. Allocates B->size*2+1 bytes and deallocates on exit in case
           we are asked to calculate _mu_
*/
RESULT mod_barrett_init( Integer B, Integer R[3] )
{
    RESULT _res_ = ERR_STATE;
    R[0] = R[1] = NULL;

    /* Q = _mu_*A (Max Size) */
    mint( Qo, 2*B->bytelen + 4 );
    mint( Q,  Qo->size );
    R[0] = Qo;
    R[1] = Q;
    /* _mu_ may be preclculated, in that case
      don't allocate */
    if( !R[2] )
    {
        /* M->size = 40 */
        mint( T, B->bytelen * 2 + 1 );
        T->buf[0] = 1;
        setOffset( T );
        mint( M, div_q_sz( T, B ) );
        _res_ = div_quotient( T, B, M );
        R[2] = M;
        flint( T );
    }
    /* debug */
    printf( "MU = " );
    printInteger( R[2] );
    printf( "\n" );
    /* end debug */
    _res_ = OK;
    goto done;
no_mem_:
    _res_ = MOD_BARRETT_INIT_NO_MEM;
done:
    return _res_;
}

/*!
  \brief: barrett modular reduction, Q = A mod B
  \param1: [INOUT] A integer to be reduced (can be negative)
            If negative, sign of A is changed to positive
  \param2: [IN] B modulus
  \param3: [IN] M _mu_ precalculated for calculations.
           For ECC, we have all the data we need for
           calculating _mu_ for known curves
  \param4: [TMP] Temp scratch variable allocated by
                 caller to store intermediate values
  \param5: [OUT] Result returned in Qo
  \note: Size Matters (160 bit e)
         Does not allocate or deallocate
         Calculations for ECC
         B = modulus bits   = 20 bytes secp160R1
         A = 2*B            = 40 bytes
         M = _mu_ = B->size = 20 bytes
             since radix^sz >= B^2
         Qo = A              = 40
         Q  = Qo->size + M->size = 60 bytes
         Total: A + B + M + Qo + Q
            =  20 + 20 + 20 + 80 + 60
            = 200 bytes
*/
RESULT mod_barrett_reduce( Integer A, Integer B,
                           Integer M, Integer Q,
                           Integer Qo )
{
    if( !A || !B || !M || !Q || !Qo )
        return MOD_BARRETT_NULL_PARAMS;

    if( Qo->size < (B->bytelen + M->bytelen + 2) )
        return MOD_BARRETT_Q0_SZ_UNSUFFICIENT;

    if( A->bytelen > (2 * B->bytelen) )
        return MOD_BARRETT_A_GT_B_SQ;

    BYTE neg = A->flags;
    BYTE i = 0;
    reset( Qo );
    reset( Q );
    RESULT _res_ = OK;
    copy( Qo, A );
    Qo->flags = 0;

    /* A < B return immediately */
    if( cmp( Qo, B ) == L_LT_R )
    {
        if( neg & NEGATIVE )
            _res_ = add( A, B, Qo );
        return _res_;
    }
    A->flags  = 0;
    /* debug */
    printf( "\nQ = " HEXCALC_OPEN );
    printInteger( Qo );
    printf( "/(2^%X)", (B->bytelen-1) * 8);
    printf( HEXCALC_CLOSE " = " );
    /* end debug */

    rshift_x( Qo, (B->bytelen-1) );
    /* _mu_ = M = radix^l_B/B is precalculated */

    /* debug */
    printInteger( Qo );
    printf( "\nQ = Qo * Mu " HEXCALC_OPEN );
    printInteger( Qo );
    printf( "*" );
    printInteger( M );
    printf( HEXCALC_CLOSE " = " );
    /* end debug */

    _res_ = mul( Qo, M, Q );

    /* debug */
    printInteger( Q );
    printf( "\n" );
    /* end debug */

    if( _res_ != OK )
    {
        A->flags = neg;
        return MOD_BARRETT_MUL_Q0_MU_FAILED;
    }
    /* debug */
    printf( "Q/16^%d %s", (B->bytelen + 1), HEXCALC_OPEN );
    printInteger( Q );
    printf( "/(100^%X)", (B->bytelen +1) );
    printf( HEXCALC_CLOSE "=" );
    /* end debug */
    rshift_x( Q, (B->bytelen + 1) );
    /* debug */
    printInteger( Q );
    printf( "\n" );
    /* end debug */

    /* debug */
    printf( "Qo = Q*B " HEXCALC_OPEN );
    printInteger( Q );
    printf( "*" );
    printInteger( B );
    printf( HEXCALC_CLOSE " = " );
    /* end debug */

    /* After this Q should be short enough that
       we can put the multiplication result in Qo */
    _res_ = mul( Q, B, Qo );

    /* debug */
    printInteger( Qo );
    printf( "\nA-Qo " HEXCALC_OPEN );
    printInteger( A );
    printf( "-" );
    printInteger( Qo );
    /* end debug */

    if( _res_ != OK )
    {
        A->flags = neg;
        return MOD_BARRETT_MUL_Q_B_FAILED;
    }
    _res_ = sub( A, Qo, Qo );
    /* debug */
    printf( HEXCALC_CLOSE "=" );
    printInteger( Qo );
    printf( "\n" );
    /* end debug */
    if( _res_ != OK )
    {
        A->flags = neg;
        return MOD_BARRETT_SUB_A_Qo_FAILED;
    }

    /* We expect at most 1 to 2 iterations here */
    while( cmp( Qo, B ) == L_GT_R )
    {
        /* debug */
        printf( "\nQo > B, Qo = Qo -B, " HEXCALC_OPEN );
        printInteger( Qo );
        printf( "-" );
        printInteger( B );
        printf( HEXCALC_CLOSE "=" );
        /* end debug */
        _res_ = sub( Qo, B, Qo );
        /* debug */
        printInteger( Qo );
        printf( "\n" );
        /*end debug */
        if( _res_ != OK )
        {
            A->flags = neg;
            return MOD_BARRETT_SUB_Qo_B_FAILED;
        }
        i++;
        if( i > 2 )
        {
            A->flags = neg;
            return MOD_BARRETT_SUB_Qo_B_ITERS;
        }
    }
    /* We were asked to do -A mod B
     * if x = -A mod B, then B - x = A mod B
     * we calculated A mod B now send back B-x
     */
    if( neg & NEGATIVE )
    {
        _res_ = sub( B, Qo, Qo );
    }
    if( Qo->flags & NEGATIVE )
    {
        _res_ = add( B, Qo, Qo );
    }
    A->flags = neg;
    return _res_;
}

/*!
  \brief: barrett modular reduction, Q = A mod B
  \param1: [IN] A integer to be reduced
  \param2: [IN] B modulus
  \param3: [OUT] Result returned
  \note: Size Matters
        If A->size > 2*B->size + 1 then mod barrett is pretty
        useless
        1. Allocates Qo = 2*A->size bytes where l_A ~= 2*l_B + 1
           Caller IS responsible for deallocating Qo
        2. Allocates Q =  2*A->size bytes and deallocates on exit
        3. Calls mod_barrett_mu which allocates B->size these are
           deallocated on function exit.
        4. Overall mem cost is approx 5*l_B
        This function is seldom used when calculating mudular reductions
        in a loop.
*/
RESULT mod_barrett( Integer A, Integer B, Integers X )
{
    Integer M, Qo, Q;
    M = Qo = Q = NULL;
    RESULT _res_ = ERR_STATE;

    Integer R[3];
    R[0] = R[1] = R[2] = NULL;
    _res_ = mod_barrett_init( B, R );
    if( _res_ != OK )
        goto done;

    /* debug */
    printf( "A mod B = " HEXCALC_OPEN " mod(" );
    printInteger( A );
    printf( "," );
    printInteger( B );
    printf(") " HEXCALC_CLOSE "= " );
    /* end debug */

    Qo = R[0];
    Q  = R[1];
    M  = R[2];
    _res_ = mod_barrett_reduce( A, B, M, Q, Qo );

    /* debug */
    printInteger( Qo );
    printf( "\n" );
    /* end debug */
    *X = Qo;
    goto done;

done:
    if( _res_ != OK )
    {   /* free as much as you can */
        mod_barrett_free( R, YES );
    } else 
    {   /* preserve the result */
        mod_barrett_free( R, NO );
    }
    return _res_;
}

/*!
  \brief: free M (_mu_) Qo and Q used in barrett computation
*/
void mod_barrett_free( Integer R[3], BYTE free_result )
{
    if( free_result )
        flint( R[0] );
    flint( R[1] );
    flint( R[2] );
}
