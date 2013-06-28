/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)

*/
#include "bignum.h"
/* debug */
/*!
    \brief multiply two big integers
    \param 1: [in] buffer representing integer A
    \param 2: [in] length of A
    \param 3: [in] buffer representing integer B
    \param 4: [in] length of B
    \param 5: [out] output buffer containing product AxB
    \return RESULT OK if successful
     Warning! no boundary checks 
*/

RESULT mul16_(BYTE* A, SHORT lA,
            BYTE* B, SHORT lB,
            BYTE* R, SHORT lR )
{
    SWORD i  = lA;
    SWORD j  = lB;
    /* For odd boundaries we set lower limit to -1
       There is lost performance to to an added if */
    SWORD l_j = (j & 1)? -1:0;
    SWORD l_i = (i & 1)? -1:0;
    SHORT r, wa, wb, ps, carry;
    SWORD of = lR - ( lA + lB ), off;
    WORD p;
    p = r = off = wa = ps = 0;
    /* make sure there is space for R */
    if ( of < 0 )
    {
        r = WRN_MUL_NOT_ENOUGH_SPACE;
        return r;
    }
    j = lB - SZ_W_BY_S;

    while( j >= l_j )
    {
       wb = (j >= 0)? R_SHORT( B, j ): B[0];
       carry = 0;
       i = lA - SZ_W_BY_S;

       while( i >= l_i )
       {
           off = ( of+ i + j + SZ_W_BY_S );
           /* Odd boundaries we add an if here
              perhaps asm optimize later */
           wa = (i >= 0) ? R_SHORT( A, i ): A[0];
           ps = R_SHORT( R, off );

            /* read previous value at R [ i + j ] */
           p =  ps + (wb * wa) + carry;
           W_SHORT( R, off, R_SHORT_LSBS_FROM_WORD( p ) );
           carry = R_SHORT_MSBS_FROM_WORD( p );
           i-=SZ_W_BY_S;
       } /* while i > 0 */
       off = ( of + i + j + SZ_W_BY_S );
      /* push the carry */
       W_SHORT( R, off, ((R_SHORT(R, off)) + carry) );
       j-=SZ_W_BY_S;

    } /* while j>=0 */
    return OK;
}
/* end debug */

RESULT mul_(BYTE* A, SHORT lA,
             BYTE* B, SHORT lB,
             BYTE* R, SHORT lR )
{
    SSHORT j  = lB - 1, i;
    /* For odd boundaries we set lower limit to -1
       There is lost performance to to an added if */
    BYTE r, wa, wb, ps, carry;
    SSHORT of = lR - ( lA + lB ), off;
    SHORT p;
    p = r = off = wa = ps = 0;
    /* make sure there is space for R */
    if( of < 0 )
    {
        r = WRN_MUL_NOT_ENOUGH_SPACE;
        return r;
    }
    while( j >= 0 )
    {
       wb = B[ j ];
       carry = 0;
       i = lA - 1;

       while( i >= 0 )
       {
           off = ( of + i + j + 1 );
           wa = A[ i ];
            /* read previous value at R [ i + j ] */
           p =  R[ off ] + (wb * wa) + carry;
           R[ off ] = (BYTE) p;
           carry = p >> 8;
           i--;
       } /* while i > 0 */
       off = ( of + i + j + 1 );
      /* push the carry */
       R[ off ] = R[ off ] + carry;
       j--;
    } /* while j>=0 */
    return OK;
}

/*!
    \brief    multiply two Integers (Wrapper)
              see bignum.h
    \param 1: [in] Integer A
    \param 3: [in] Integer B
    \param 5: [out] output Integer containing Integer
                    product AxB
    \return RESULT OK if successful
     Warning! no boundary checks
*/
RESULT mul( Integer A, Integer B, Integer R )
{
    /* copy may overwrite flags
       save them */
    BYTE flags = (A->flags & NEGATIVE)
                  ^
                 (B->flags & NEGATIVE);
    /* simple cases */
    if( A->top == 0 || B->top == 0 )
    {
        reset( R );
        return OK;
    }
    if( B->top == 1 )
    {
        copy( R, A );
        R->flags = flags;
        R->flags   = ( SZ_WORD > R->top )?
               R->flags|IS_WORD : R->flags;
        return OK;
    }
    if( A->top == 1 )
    {
        copy( R, B );
        R->flags = flags;
        R->flags   = ( SZ_WORD > R->top )?
               R->flags|IS_WORD : R->flags;
        return OK;
    }
    reset( R );
    /* TODO: optimize send fBytes */
    RESULT r = mul_( A->buf + A->topByte, A->size - A->topByte,
                     B->buf + B->topByte, B->size - B->topByte,
                     R->buf, R->size );
    R->flags = flags;
    setOffset( R );
    return r;
}
