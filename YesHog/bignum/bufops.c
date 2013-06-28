/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/
#include "bignum.h"

/*!
    \brief determine position of '1' bit in buffer
    \param 1: [in] BYTE* A
    \param 2: [in] len of buf A
    \return the offset of  leftmost '1' bit from the
            LSB in buf A. Ex A = { 0, 0, 3, 0 } then
            bufBitOffset(...) = 10
    \return position of '1' bit in buf if found
            ONE_BIT_NOT_FOUND otherwise
*/
SHORT bufBitOffset( BYTE* A, SHORT lA )
{
    SHORT j = 0;
    BYTE  t = 0;
    for ( ; j < lA; j++ )
    {
        t = bitOffset( A [ j ] );
        if ( t != ONE_BIT_NOT_FOUND )
        {
            break;
        }
    }
    if ( j == lA )
    {
        return MAX_SHORT;
    }
    j = ( ( lA - j ) * SIZEOF_BYTE ) - t;
    return  j;
}

/*!
    \brief shift buffer right
    \param 1: [in out] BYTE* buf
    \param 2: [in] length of buf
    \param 3: [in] number of shifts
    \param 3: [out] oB overflow buffer. 
                    if NULL overflow ignored
    \param 4: [in] oL length of overflow buffer
    \return BYTE* overflow buffer
    \warning  no boundary checks allocate enough space
            for buf and oB
*/

BYTE* rshiftBuf( BYTE* buf, SHORT lBuf, SHORT nS,
             BYTE* oB , SHORT oL )
{
    if ( nS <= 0 )
    {
        return NULL;
    }
    /* byte shifts */
    SHORT bSh  = (nS  /  SIZEOF_BYTE);
    BYTE biSh = (nS  %  SIZEOF_BYTE);

    /*TODO add check to see oL > bSh return null if so */

    SSHORT k = bSh;

    /* if overflow buffer is not provided never mind */
    if( oB && oL > 0 )
    {
        for( ; k >= 0; k-- )
        {
            /* save bytes into overflow
              ex for nS = 19, lBuf = 8
            oB [ 2 ] = buf [ (8 - 1) - ( 2 - 2) ]
            oB [ 2 ] = buf [ 7 ]  */

            oB [ k ] = buf [ (lBuf -1) - (bSh - k)  ];
        }
    }

    /*
       now we are ready to rshift the buf
       shift the big quantities first
    */
    k = lBuf - 1;
    for ( ; (bSh) && (k >= bSh) ; k--)
    {
        buf [ k ] = buf [ k - bSh ];
        buf [ k - bSh ] = 0;
    }
    /* now do the final shift */
    BYTE ov  = 0;
    BYTE ovc = 0;
    for( k = bSh; k < lBuf ; k++ )
    {
        ovc = rshiftByte( &buf[ k ],  biSh );
        buf[ k ] |= ( ov << ( SIZEOF_BYTE - biSh ) );
        ov = ovc;
    }
    /* modify first byte of overflow buffer */
    if( oB && oL > 0 )
    {
        oB [ 0 ] = ov;
    }
    return oB;
}

/*!
    \brief shift byte right
    \param 1: [in out] BYTE* pointer to byte to be shifted
    \param 2: [in] number of right shifts
    \return BYTE overflow byte
    \note in place rshift of passed byte
*/
BYTE rshiftByte( BYTE* bP, BYTE nS )
{
    SSHORT sH = nS - 1;

    /* x is the overflow mask
       y is ~x
       r is return value */
    BYTE x = 0;
    BYTE y = 0;
    BYTE r = 0;

    for( ; sH >=0; sH -- )
    {
        x |= (1 << sH);
    }
    y = ~(x);

    /* ready to finally shift */
    r     = (*(bP) & x);
    *(bP) = (*(bP) & y) >> nS;

    return r;
}

/*!
    \brief shift buffer left
    \param 1: [in out] BYTE* buf
    \param 2: [in] length of buf
    \param 3: [in] number of shifts
    \param 3: [out] oB overflow buffer. 
                    if NULL overflow ignored
    \param 4: [in] oL length of overflow buffer
    \return BYTE* overflow buffer
    \warning  no boundary checks allocate enough space
              for buf and oB
*/

BYTE* lshiftBuf( BYTE* buf, SHORT lBuf, SHORT nS,
             BYTE* oB , SHORT oL)
{
    if ( nS <= 0 )
    {
        return NULL;
    }
    /* byte shifts */
    SHORT bSh  = (nS  /  SIZEOF_BYTE);
    SHORT biSh = (nS  %  SIZEOF_BYTE);

    /*TODO add check to see oL > bSh return null if so */

    SSHORT k = 0;

    /* if overflow buffer is not provided never mind */
    if( oB && oL > 0 )
    {
        for( ; k <= bSh; k++ )
        {
            /* save bytes into overflow
              ex for nS = 19, lBuf = 8
            oB [ 0 ] = buf [ 0 ]  */

            oB [ k ] = buf [ k ];
        }
    }

    /*
       now we are ready to rshift the buf
       shift the big quantities first
    */
    for ( ; (bSh) && ( k < lBuf - bSh ); k++ )
    {
        buf [ k ] = buf [ k + bSh ];
        buf [ k + bSh ] = 0;
    }
    /* now do the final shift */
    BYTE ov  = 0;
    BYTE ovc = 0;
    for( k = lBuf - bSh - 1; k >= 0; k-- )
    {
        ovc = lshiftByte( &buf[ k ],  biSh );
        buf[ k ] |= ( ov >> ( SIZEOF_BYTE - biSh ) );
        ov = ovc;
    }
    /* modify first byte of overflow buffer */
    if( oB && oL >= bSh )
    {
        oB [ bSh ] = ov;
    }
    return oB;
}

/*!
    \brief 
    \param 1: [in Integer to be left shifted
    \param 3: [in] number of shifts
    \return void
*/

void lshift( Integer A, SHORT nS )
{
    lshiftBuf ( A->buf, A->size, nS, NULL, 0 );
    setTop( A, A->top + nS );
}

/*!
    \brief 
    \param 1: [in Integer to be right shifted
    \param 3: [in] number of shifts
    \return void
*/

void rshift( Integer A, SHORT nS )
{
    rshiftBuf ( A->buf, A->size, nS, NULL, 0 );
    setTop ( A, A->top - nS );
}

/*!
    \brief shift byte left
    \param 1: [in out] BYTE* pointer to byte to be shifted
    \param 2: [in] number of left shifts
    \return BYTE overflow byte
    \note in place lshift of passed byte
*/
BYTE lshiftByte( BYTE* bP, BYTE nS )
{
    SHORT sH = 0;

    /* x is the overflow mask
       y is ~x
       r is return value */
    BYTE x = 0;
    BYTE y = 0;
    BYTE r = 0;

    for( sH = 0; sH <=  nS - 1; sH ++ )
    {
        x |= (1 << (SIZEOF_BYTE - sH - 1) );
    }
    y = ~(x);

    /* ready to finally shift */
    r     = (*(bP) & x);
    *(bP) = (*(bP) & y) << nS;

    return r;
}

/*!
    \brief add 2 big numbers A + B
    \param 1: [in] Integer* pointer A
    \param 2: [in] Integer* pointer B
    \param 3: [out] Integer* R result
    \return : RESULT OK if successful
    \warning A,B are correctly initialized
*/
RESULT add( Integer A, Integer B, Integer R )
{
    RESULT _res_ = ERR_STATE;
    BYTE f, c;
    /* A  + (-B) */
    if( (B->flags & NEGATIVE) &&
      ( !(A->flags & NEGATIVE) ) )
    {
        /* Save flags and restore later */
        f = B->flags;
        B->flags ^= NEGATIVE;
        c = cmp( A, B );

        /* The other cases are handled ok
           by sub */
        switch( c )
        {
            case L_LT_R:
                /* A - B < 0 */
                _res_ = sub(B, A, R);
                R->flags |= NEGATIVE;
                break;
            default:
                /* A - B >= 0 */
                _res_ = sub(A, B, R);
                R->flags &= ~NEGATIVE;
                break;
        }
        B->flags = f;
        return _res_;
    }
    /* -A  + B */
    if( (A->flags & NEGATIVE) &&
      ( !(B->flags & NEGATIVE) ) )
    {
        f = A->flags;
        A->flags ^= NEGATIVE;
        c = cmp( A, B );

        /* The other cases are handled ok
           by sub */
        switch( c )
        {
            case L_GT_R:
                 /* -A + B < 0 */
                _res_ = sub(A, B, R);
                R->flags |= NEGATIVE;
                break;
            default:
                /* -A + B >= 0 */
                _res_ = sub(B, A, R);
                R->flags &= ~NEGATIVE;
                break;
        }
        if( R != A )
        {
            A->flags = f;
        }
        return _res_;
    }

    RESULT r = add_( A->buf + A->topByte, A->bytelen,
                     B->buf + B->topByte, B->bytelen,
                     R->buf, R->size );

    setOffset ( R );
    return r;
}


/*!
    \brief add 2 big numbers A + B
    \param 1: [in] BYTE* pointer A
    \param 2: [in] SHORT length A
    \param 3: [in] BYTE* pointer B
    \param 4: [in] SHORT length B
    \param 5: [out] BYTE* R result
    \return RESULT OK if successful
    \warning No boundary checks on param 5 allocate
             sufficient space
*/


RESULT add_(BYTE* A,  SHORT lA,
            BYTE* B,  SHORT lB,
            BYTE* R, SSHORT lR)
{
    SHORT t = 0;
    BYTE  C = 0;
    SSHORT j = ( lA > lB ) ?
               ( lA - lB -1 ):( lB -lA -1 );
    if( lR < ( MAX(lA, lB) + 1 ) )
    {
        return ERR_ADD_NOT_ENOUGH_SPACE;
    }
    BYTE* M = ( lA > lB ) ? A : B;

    do
    {
        t = (SHORT) A [ --lA ] + (SHORT) B [ --lB ]
            + (SHORT) C;
        R [ --lR ] = (BYTE) t;

        C = (BYTE) ( t >> SIZEOF_BYTE );

    }
    while ( lA > 0 && lB > 0 );
    /* now handle the remainder of the stuff */
    while ( j >= 0 && lR > 0 )
    {
        t = (SHORT) M [ j ] + (SHORT) C;
        R [ --lR ] = (BYTE) t;
        C = (BYTE) ( t >> SIZEOF_BYTE);
        j--;
    }
    if( (--lR) >= 0 && C > 0 )
    {
        R[ lR ] = C;
    }
    return OK;
}


/*!
    \brief subtract 2 big numbers A - B
    \param 1: [in] BYTE* pointer A
    \param 2: [in] SHORT length A
    \param 3: [in] BYTE* pointer B
    \param 4: [in] SHORT length B
    \param 5: [out] BYTE* R result
    \param 6: [in] R length of R
    \return   RESULT OK if successful
    \note     B MUST be less than A
    \warning No boundary checks allocate sufficient space
*/

RESULT sub_(BYTE* A,  SHORT lA,
            BYTE* B,  SHORT lB,
            BYTE* R, SSHORT lR)
{
    SSHORT j = ( lA > lB ) ?
               ( lA - lB - 1 ) : ( lB -lA -1 );
    if( lR < MAX( lA, lB ) )
    {
        return ERR_SUB_NOT_ENOUGH_SPACE;
    }
    BYTE* M = ( lA > lB ) ? A : B;
    BYTE C  = 0;
    do
    {
        /* Carry is -1 or 0 */
        SSHORT T =  ( (SSHORT) A [ --lA ] )
                    + (SBYTE) C
                  - ( (SSHORT) B [ --lB ] );
        R [ --lR ] = (BYTE) (T);
        C = (SHORT) T >> SIZEOF_BYTE;
    }
    while( lA > 0 && lB > 0 );
    /* handle the rest */
    while ( j >= 0 && lR > 0 )
    {
        SSHORT T =  ( (SSHORT) M [ j ] )
                   + (SBYTE) C;
        R [ --lR ] = (BYTE) T;
        C = (SHORT) T >> SIZEOF_BYTE;
        j--;
    }
    /* Zero out remaining bytes or R */
    while( --lR > 0 )
    {
        R[ lR ] = 0;
    }
    return OK;
}

/*!
    \brief subtract 2 big Integers R = A - B
    \param 1: [in] Int* A
    \param 2: [in] Int* B
    \param 3: [inout] Int* R
    \return RESULT OK if successful
    \warning No boundary checks allocate sufficient space
*/

RESULT sub( Integer A, Integer B, Integer R )
{
    RESULT _res_ = ERR_STATE;
    BYTE flags;

    /* 0 - (-B) */
    if( A->top == 0 && ( B->flags & NEGATIVE ) )
    {
        copy( R, B );
        R->flags ^= NEGATIVE;
        return OK;
    }
    /* A - 0 */
    if( B->top == 0 )
    {
        if ( R != A )
        {
            copy( R, A );
        }
        return OK;
    }
    /* 0 - B */
    if( A->top == 0 )
    {
        copy( R, B );
        R->flags |= NEGATIVE;
        return OK;
    }
    /* A  - (-B) */
    if( (B->flags & NEGATIVE) &&
      ( !(A->flags & NEGATIVE) ) )
    {
        flags = B->flags;
        B->flags ^= NEGATIVE;
        _res_ = add(A, B, R);
        B->flags = flags;
        R->flags &= ~NEGATIVE;
        return _res_;
    }
    /* -A  - B */
    if( (A->flags & NEGATIVE) &&
      ( !(B->flags & NEGATIVE) ) )
    {
        flags = A->flags;
        A->flags ^= NEGATIVE;
        _res_ = add(A, B, R);
        R->flags |= NEGATIVE;
        A->flags = flags;
        return _res_;
    }
    /* -A - (-B) | +ve if A > B, -ve if A < B, 0
       A - B     | same as above
    */
    Integer T;
    switch( cmp( A, B ) )
    {
        case L_LT_R:
            T = A;
            A = B;
            B = T;
            R->flags |= NEGATIVE;
            break;
        case L_EQ_R:
            reset ( A );
            return OK;
        default:
            break;
    }

    RESULT r = sub_( A->buf + A->topByte, A->bytelen,
                     B->buf + B->topByte, B->bytelen,
                     R->buf, R->size );

    setOffset ( R );
    return r;
}

/*!
    \brief negative of a number
    \param 1: [in] BYTE* pointer B
    \param 2: [in] SHORT length B
    \note in place negation of number
          (2's compliment of buffer B) + 1
*/
BYTE neg( BYTE* B, SHORT lB )
{
    SSHORT j = lB - 1;
    BYTE  c = 1;
    SHORT t = 0;

    for( ; j >= 0 ; j-- )
    {
        t = (SHORT)
           (((~ ( (SHORT) B [ j ] )) & SHORT_HIGH_LSB)
           +
           (SHORT) c);
        B [ j ] = (BYTE) t;
        c = (t > MAX_BYTE_VAL)? 1 : 0;
    }
    /* was B [ 0 ] = 0 and 
       thereby appropriate space provided */
    if( B [ 0 ] == BYTE_FF )
        return 0;

    /* there was an overflow */
    return c;
}

/*!
    \brief compare 2 unsigned ints
    \param 1: [in] BYTE* pointer A
    \param 2: [in] BYTE* pointer B
    \see compare
    \return BYTE return code see doc for compare
*/
BYTE cmp( Integer A, Integer B )
{
    if( A->top > B->top )
    {
        return L_GT_R;
    }
    if( A->top < B->top )
    {
        return L_LT_R;
    }
    return compare ( A->buf + A->topByte,
                     B->buf + B->topByte,
                     A->size - A->topByte );
}

/*!
    \brief compare 2 Ints (or memories within Ints)
    \param 1: [in] Byte buffer A
    \param 2: [in] Byte buffer B
    \param 3: [in] Length of bytes to compare
    \return L_GT_R if left (A) is > right (B)
            L_LT_R if (A) <(B), L_EQ_R if equal
*/
BYTE compare( BYTE* A, BYTE* B, SHORT l )
{
    SWORD r = memcmp( (void*) A, (void*) B, l );
    if( r < 0 )
    {
        return L_LT_R;
    }
    if( r == 0 )
    {
        return L_EQ_R;
    }
    return L_GT_R;
}

/*!
    \brief fill b1 with b2 and fill rest with 0
    \param 1: [in] BYTE* pointer b1
    \param 2: [in] SHORT length l1
    \param 3: [in] BYTE* pointer b2
    \param 4: [in] SHORT length l2
    \param 5: [in] SHORT max
    \note ex. A = [ FF FF FF ] B = [ AB CD ]
              then A after fill(...) is [ 00 AB CD ]
              if l2 > l1 then (l2 - l1) initial bytes
              are truncated
    \warning for _AVR_ b2 is assumed to live in PROGMEM
             aka flash memory
*/

BYTE* fill ( BYTE* b1, SHORT l1, const BYTE* b2, SHORT l2 )
{
    SSHORT r = MAX( l1 - l2, 0 );
    if( l2 > l1 )
    {
        /* foobar */
        l2 = l1;
    }
    yh_memcpy( b1 + r, b2, l2 );
    if( r )
    {
        memset( b1, 0, r );
    }
    return b1;
}

/*!
    \brief: construct an Integer from a buffer
    \param 1: [inout] Integer ptr
    \param 2: [in] buffer = value of integer
    \param 3: [in] size of buffer in arg 2
    \return: Integer ptr with top initialized
*/
Integer makeInt( Integer A, BYTE* buf, SHORT sz, BYTE isZero )
{
    A->buf  = buf;
    A->size = sz;
    A->flags = 0;
    if ( isZero )
    {
        reset( A );
        return A;
    }
    setOffset( A );
    return A;
}

/*!
    \brief: print binary version of Integer
    \param 1: [in] Integer ptr
    \return void
*/
void printIntegerBits( Integer K )
{
    SHORT j = K->topByte;
    for ( ; j < K->size; j++ )
    {
        printf( "%d", (K->buf[ j ] & 0x80)? 1 : 0 );
        printf( "%d", (K->buf[ j ] & 0x40)? 1 : 0 );
        printf( "%d", (K->buf[ j ] & 0x20)? 1 : 0 );
        printf( "%d", (K->buf[ j ] & 0x10)? 1 : 0 );
        printf( "%d", (K->buf[ j ] & 0x08)? 1 : 0 );
        printf( "%d", (K->buf[ j ] & 0x04)? 1 : 0 );
        printf( "%d", (K->buf[ j ] & 0x02)? 1 : 0 );
        printf( "%d", (K->buf[ j ] & 0x01)? 1 : 0 );
        printf( " " );
    }
}

/*!
    \brief: print the value of an integer
    \param 1: [in] Integer ptr
    \return void
*/
void printInteger( Integer A )
{
    if( A->flags & NEGATIVE )
    {
        printf("-");
    }
    printBuf( A->buf + A->topByte, A->size - A->topByte );
}

/*!
    \brief: print a hex buffer (Integer)
    \param 1: [in] Buffer to be printed
    \param 2: [in] size of Buffer in arg 1
    \return void
*/
void printBuf( BYTE* A, SHORT sz )
{
    SHORT j = 0;
    for ( ; j < sz; j++ )
    {
        printf( "%02X", A [ j ] );
    }
}

