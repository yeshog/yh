/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/
#include "bignum.h"
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
    RESULT r = mul_( A->buf + A->topByte, A->bytelen,
                     B->buf + B->topByte, B->bytelen,
                     R->buf, R->size );
    R->flags = flags;
    setOffset( R );
    return r;
}
