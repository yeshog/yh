/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/
#include "bignum.h"
/*!
    \brief square two big integers
    \param 1: [in] buffer representing integer A
    \param 2: [in] length of A
    \param 3: [out] buffer representing result R=A*A
    \param 4: [in] length of R
    \return RESULT OK if successful
    \warning no boundary checks caller allocs/frees
              all memory
*/
/* alas this has to be byte based
because we are calculating columns */
RESULT sqr( BYTE* A, SHORT lA,
            BYTE* R, SHORT lR)
{
    SSHORT i, j, k, of, r;
    SHORT p ;
    WORD s, c;
    /* ^^ do NOT mess with that width */
    BYTE flag;
    i = j = k = s = c =
    of = flag = p = 0;
    r = OK;
    /* insufficient space */
    of = lR - 2*lA;
    if( of < 0 )
    {
        /* set r */
        r = WRN_SQR_NOT_ENOUGH_SPACE;
    }
    /*
       last and first numbers are
       exceptions so as to hopefully
       speed up squarings
    */
    k = lA - 1;
    i = j = k;
    /* calculate first square */
    p = A [ i ] * A [ j ];
    c = ( p & SHORT_B0_MASK ) >> SIZEOF_BYTE;
    of = lR - 1;
    R [ of ] = ( BYTE ) p;
    /*
      start from column 2
      (assuming first column is 1)
     */
    j = k;
    k--;
    i = k;
    of--;
    s = 0;
    while( k >= 0 )
    {
        while ( i < j )
        {
            p = A[ i ] * A[ j ];
            s += p;
            i++;
            j--;
        }
        s *= 2;
        s += ( c + ( A[ i ] * A[ j ] * flag ) );
        c = (s & 0xFFFFFF00) >> SIZEOF_BYTE;
        /* we are done with the column */
        R[ of ] = (s & WORD_B3_MASK);
        k --;
        i = k;
        j = lA - 1;
        s = 0;
        flag ^= 1;
        of--;
    }
    /* we are only a little over half done */
    j = 0;
    k = lA - 2;
    i = k;
    s = 0;
    while( k >= 0 )
    {
        while( i > j )
        {
            p = A[ i ] * A[ j ];
            s += p;
            i--;
            j++;
        }
        s *= 2;
        s += ( c + ( flag * A[ i ] * A[ j ] ) );
        c = (s & 0xFFFFFF00) >> SIZEOF_BYTE;
        /* we are done with the column */
        R[ of ] = (s & WORD_B3_MASK);
        k --;
        i = k;
        j = 0;
        s = 0;
        flag ^= 1;
        of--;
    }
    R[of] = c;
    memset( R, 0, of - 1 );
    return r;
}

RESULT sq( Integer A, Integer R )
{
    SHORT r = sqr( A->buf + A->topByte, A->bytelen,
                                 R->buf, R->size );
    R->flags &= ~NEGATIVE;
    setOffset( R );
    return r;
}
