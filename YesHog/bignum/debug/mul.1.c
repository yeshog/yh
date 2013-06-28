/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)

*/
#include "bignum.h"

/*!
    \brief multiply two big integers
    \param 1: [in] buffer representing integer A
    \param 2: [in] length of A
    \param 3: [in] buffer representing integer B
    \param 4: [in] length of B
    \param 5: [out] output buffer containing product AxB
    \return pointer to buffer product AB
     Warning! no boundary checks 
*/

BYTE* mul_(BYTE* A, SHORT lA,
           BYTE* B, SHORT lB,
           BYTE* productAB, SHORT lpAB )
{

    memset(productAB, 0, sizeof(productAB));
    int i  = lA;
    int j  = lB;
    int k  = 0;

    j = lB - SZ_W_BY_S;

    while(j>=0)
    {

       SHORT wordAtB = R_SHORT( B, j );
       SHORT carry = 0;
       i = lA - SZ_W_BY_S;

       while(i>=0)
       {

           SHORT wordAtA = R_SHORT( A, i );
           SHORT pShort = R_SHORT( productAB,
                                   i + j + SZ_W_BY_S );

            /* read previous value at productAB [ i + j ] */
           WORD product =  pShort + (wordAtB * wordAtA) + carry;
           W_SHORT( productAB, i + j + SZ_W_BY_S,
                    R_SHORT_LSBS_FROM_WORD( product ) );

           //readType(pRptr, 0, SZ_W_BY_S, (void*) &carry);
           carry = R_SHORT_MSBS_FROM_WORD( product );

           i-=SZ_W_BY_S;

       } /* while i > 0 */

      /* push the carry */
       W_SHORT( productAB, i + j + SZ_W_BY_S, carry );

       j-=SZ_W_BY_S;
    } /* while j>=0 */

    for(k=0; k< 16; k++) printf("%X ", productAB[k]);
    printf("\n");

    return productAB;
}
/*!
    \brief    multiply two Integers (Wrapper)
              see bignum.h
    \param 1: [in] Integer A
    \param 3: [in] Integer B
    \param 5: [out] output Integer containing Integer
                    product AxB
    \return Integer
     Warning! no boundary checks
*/
Integer mul( Integer A, Integer B, Integer R )
{
    mul_( A->buf, A->size,
          B->buf, B->size,
          R->buf, R->size );
    setOffset( R );
    return R;
}

