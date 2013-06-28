/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/

#ifndef YH_BIGNUM_H_
#define YH_BIGNUM_H_

#include<yhmemory.h>

/* used for comparing 2 bignums */
#define          L_EQ_R                   0
#define          L_GT_R                   1
#define          L_LT_R                   2
#define          L_ERR                    0xFF
#define          L_LBUF_BOUNDARY_ERR      3
#define          L_RBUF_BOUNDARY_ERR      4
#define          L_LEN_NEQ_ERR            5

/* define left or right number is negative */
#define           F_ZERO             0
#define           F_L_NEG            2
#define           F_R_NEG            4
#define           RADIX              2
#define           MAX_BYTES          64
#define           ERROR_FILL         0xFF
#define           ERROR_OFFSET       0xFE
#define           EQUAL              0
#define           NEGATIVE           1
#define           POSITIVE           2
#define           IS_WORD            4
#define           ONE_BIT_NOT_FOUND  0xFF
#define           MAX_SHORT          0xFFFF
#define           MONT_MOD           0x10000
#define           MAX_MODULUS_BUF_SZ 1026
#define           HEXCALC_OPEN       "hexcalc \""
#define           HEXCALC_CLOSE      "\""

/* Max len in bytes of a buf */
#define MAX_LEN 2048

#define topByteFromLeft(x) \
    x->size - 1 - ( ( x->top - 1 ) / SIZEOF_BYTE )

#define topBitFromLeft(x) \
    ( ( x->size ) * SIZEOF_BYTE ) - x->top


#define setTop( x, a ) \
        x->top     = (a >= MAX_SHORT)? 0:a; \
        x->topByte = topByteFromLeft( x );  \
        x->bytelen = x->size - x->topByte

#define placeTopBitFromLeft(x, a)                                       \
    x->buf [  ( ( ( x->size * SIZEOF_BYTE ) - (a) ) / SIZEOF_BYTE ) ] = \
    1 << ( ( SIZEOF_BYTE - 1 ) - ( ( ( x->size * SIZEOF_BYTE ) -        \
         a ) & 7 ) );                                                   \
    setTop( x, a )

#define setBit placeTopBitFromLeft

#define setOffset( x ) \
        setTop( x, bufBitOffset( x->buf, x->size ) )

#define clearByte(x, a)                                                  \
    x->buf [ ( ( ( x->size * SIZEOF_BYTE ) - ( a ) ) / SIZEOF_BYTE ) ] = \
    0;  setOffset( x )                                                   \

#define isOdd( x ) ( x->buf[ x->size - 1 ] & 1 )
#define isEven( x ) ( !isOdd( x ) )

#define copy( x, y )                                             \
    fillmem( x->buf, x->size, y->buf + y->topByte, y->bytelen ); \
    x->flags = y->flags;                                         \
    setTop( x, y->top )

/* clone an int */
#define cint( x, y )                     \
    mint( x, y->size );                       \
    copy( x, y )
/*!
 \brief: Integer assignment x = y
*/
#define assign( x, y )                        \
    x->buf     =      y->buf;                 \
    x->size    =     y->size;                 \
    x->top     =      y->top;                 \
    x->topByte =  y->topByte;                 \
    x->bytelen =  y->bytelen;                 \
    x->flags   =    y->flags
/*!
 * \brief: get the bit 0 or 1 at position x of Integer b
 * \note: Positions start from 0 so leftmost bit is
 *        b->top - 1
 */
#define bitAtPosition( b, x )                      \
    1 & ( b->buf[ b->size -1 - (x/SIZEOF_BYTE) ]   \
    >> (x & 7) )

/* 'The good': clean integer with all zeros */
#define clint( x, y ) \
    Integer x = yh_calloc( 1, sizeof(Int) ) ;      \
    BYTE _##x##_[ y ];       \
    makeInt( x, _##x##_, y, YES )

/* 'The bad': create a preset integer from a buffer
   use with malloc since size is explicitly passed */
#define pint( x, y, z )                        \
    Integer x = yh_calloc( 1, sizeof(Int) ) ;  \
    memset( x, 0, sizeof( Int ) );             \
    makeInt( x, y, z, NO )

/* 'The ugly': create a local int only
   non malloc preallocated version */
#define lint( x, y )                \
    Int _##x##i_;                   \
    Integer x = &_##x##i_;          \
    x = makeInt( x, y, sizeof( y ), NO )

/** The leak: calloced integer with all zeros
    Always try to call mint and flint in the same
    function. Almost like alloca. If x is declared
    use oint
*/
#define mint( x, y )                                   \
    BYTE* _##x##_ = (BYTE*) yh_calloc(1, (y) );        \
    if( ! _##x##_ )                                    \
    {                                                  \
        goto no_mem_;                                  \
    }                                                  \
    pint( x, _##x##_, (y) )

/* Integer passed on stack */
#define oint( x, y )                                \
    x = yh_calloc( 1, sizeof(Int) ) ;               \
    memset( x, 0, sizeof( Int ) );                  \
    x->buf = (BYTE*) yh_calloc(1, (y) );            \
    if( ! x->buf )                                  \
    {                                               \
        goto no_mem_;                               \
    }                                               \
    x->size = y;                                    \
    reset( x )

#define foint( x )                               \
    if( x && (x->buf != NULL) )                  \
    {                                            \
        yh_free( x->buf, x->size );              \
        x->buf = NULL;                           \
        x = NULL;                                \
    }

/** \brief declare new integer (dint) x from 
           buffer 'a' of len y where y is the len
           of 'a'. y bytes are calloced and assigned
           to x
    \note call flint to free 
*/
#define dint( x, a, y )                             \
    BYTE* _##x##_ = (BYTE*) yh_calloc(1, (y) );     \
    if( ! _##x##_ )                                 \
    {                                               \
        goto no_mem_;                               \
    }                                               \
    memcpy( (void*) _##x##_, (void*) a, y );        \
    pint( x, _##x##_, (y) )

/** \brief declare int x of size y from buffer
           a of len b (bint = buffer to integer)
    \note call flint to free 
*/
#define bint( x, y, a, b )                         \
    Integer x = yh_calloc( 1, sizeof(Int) );       \
    x->buf = yh_calloc( 1, (y) );                  \
    x->size = (y);                                 \
    fillmem( x->buf, x->size, (a), (b) );          \
    setOffset( x )

#define flint( x )                               \
    if( x != NULL && x->buf != NULL )            \
    {                                            \
        yh_free( x->buf, x->size );              \
        x->buf = NULL;                           \
        yh_free( x, sizeof(Int) );               \
        x = NULL;                                \
    }


/*  TODO: mkWORD kinda stinks as it may go
    upto 8 comparisons on 64 bit */
#define topByteAddr( b ) ( (BYTE*) &(b->buf[b->topByte]) )

#define mkWORD( b ) \
    (( (b->bytelen & 3) == 3 )? \
                 mkWORD3( topByteAddr(b) ): \
    ( (b->bytelen & 3) == 2 )? \
                 mkWORD2( topByteAddr(b) ): \
    ( (b->bytelen & 3) == 1 )? \
                 mkWORD1( topByteAddr(b) ): \
    IR_WORD( b, (b->topByte) ))

#define getTopWord( x ) mkWORD( x )

#define getTopWordSafe( b, y ) \
    ((b->topByte + y + 1 > b->size)? \
        mkWORD( b ) : mkWORD##y( (b->buf + b->topByte) ))

#define reset( x ) \
    memset( x->buf, 0, x->size ); \
    x->top     = 0;               \
    x->topByte = 0;               \
    x->flags   = 0

#define i_xchg( x, y )                \
    {                                 \
        xchg( Integer, x, y )         \
    }
                          /* if 4      ? else */
#define w_len( x ) (x & WORD_B0_MASK)? 4 :       \
                          /* if 3      ? else */ \
                     (x & WORD_B1_MASK)? 3 :     \
                          /* if 2      ? else */ \
                       (x & WORD_B2_MASK)? 2 :   \
                          /* if 1      ? else */ \
                         (x & WORD_B3_MASK)? 1:0

/* TODO: ensure offset > 0 */
#define buf_align_16( A )                         \
    ((A->size - A->topByte - 1) & 1)?     \
    (A->buf + A->topByte):                        \
    (A->buf + (A->topByte - 1))

/* 
   Real size of an Integer.
   Align it to SHORT. Now this can go horribly
   wrong if buf sizes are not a multiple of
   SHORT
 */
#define size_align_16( A )                        \
    ((A->size - A->topByte - 1) & 1)?             \
    (A->size - A->topByte):                       \
    ((A->size - A->topByte) + 1)
    
/* firstByte
   BYTE[]   = 00 00 00 00 00 FF FF FF FF FF
   size     = 10
   topByte  = 10 - 5 -1 = 4
   size_align_16 = 6
   fByte = 4
*/
#define fByte( A )                                \
   (A->size - (size_align_16( A )))

/* Well this is for bytes */
#define size_align_64( x )                        \
    (x & 7)? ( x + (x & 7) ):x

#define from_offset( x )                          \
    buf_align_16( x ), size_align_16( x )

#define size_even( x ) x = ((x & 1)? (x + 1) : x)

/*!
  \brief get the Quotient size of x/y when y is inititated with
   zeros 
*/
#define div_q_sz_y_zero( x, y ) (x->bytelen - y->bytelen)

/*!
  \brief get quotient size of x/y when y > 0
*/
#define div_q_sz( x, y )                                        \
        ( ( w_len(((SHORT)((getTopWordSafe( x, 4 ))/            \
                          (getTopWordSafe( y, 3 ))))) ) > 1 )?  \
             /* if topByte is 1 */                              \
            (  (x->bytelen - y->bytelen) + 1 ):                 \
             /* else topbyte is not 1 */                        \
                (x->bytelen - y->bytelen)

/* If say we have 9899/99, the quotient length is always
   4-2 = 2. Int that case if Q->size > 2 (ex 5) the offset
   where Q bytes begin are 5 - (4-2) = 3 i.e. Quotient bytes
   are at offsets 3, 4. If bytelen(A) is the same as bytlen(B)
   ex. 9999/4447 then offset begins at 5 - (4-4) -1 = 4 which
   is correct since quotient is only a byte at most */
#define div_q_top( x, y, q )                                   \
      ( (x->bytelen == y->bytelen ) ||                         \
      ( ( w_len(((SHORT)((getTopWordSafe( x, 4 ))/             \
                        (getTopWordSafe( y, 3 ))))) ) > 1 ) )? \
      (Q->size - (x->bytelen - y->bytelen) -1 ):               \
      (Q->size - (x->bytelen - y->bytelen) )

#define byte_len( x ) ( x->size - x->topByte )
#define sub_noneg( X , Y, R )                                  \
        ( cmp( X, Y ) == L_GT_R )?                             \
            sub( X, Y, R ) : sub( Y, X, R )

/* Shift a buffer n bits to the right, where n <= 7 */
#define rshift_n( x , n )                                   \
    SHORT _i = x->topByte;                                  \
    BYTE _c = 0;                                            \
    BYTE _b = 0;                                            \
    while( _i  < x->size )                                  \
    {                                                       \
        _b = ( x->buf[ _i ] << (8 - n) );                   \
        x->buf[ _i ] = ( (x->buf[ _i ] >> n) | _c);         \
        _c = _b;                                            \
        _i++;                                               \
    };                                                      \
    setTop( x, x->top - n )

/* Shift a buffer one bit to the right */
#define rshift_1( x ) rshift_n( x , 1 )

/* shift a buffer n number of BYTEs to the right */
#define rshift_x( q, n ) memmove( q->buf + q->topByte + (n),     \
                                 q->buf + q->topByte,            \
                                 q->bytelen - (n) );             \
                         memset( q->buf + q->topByte, 0, (n) );  \
                         setTop( q, (q->top - (n*8)) )

/* cmp_ (disgustingly) assumes that x has been declared within the
 * function
 */
#define cmp_( A, B, x ) ( ( A->top > B->top )? L_GT_R :                    \
                        ( B->top > A->top )? L_LT_R :                      \
                           ( x =                                           \
                                memcmp( A->buf + A->topByte,               \
                                        B->buf + B->topByte,               \
                                        A->bytelen ) ) < 0  ?  L_LT_R :    \
                                      x ? L_GT_R : L_EQ_R )
/*!
    \brief determine position of '1' bit in byte with
           leftmost bit = 0
*/
#define bitOffset(x)                                            \
          ( ((x) == 0)? 0xFF: ( ((x) & 0xF0)?                   \
                                ( ((x) & 0x80)? 0 :             \
                                    ((x) & 0x40)? 1 :           \
                                      ((x) & 0x20)? 2 : 3 ) :   \
                                ( ((x) & 0x08)? 4 :             \
                                    ((x) & 0x04)? 5 :           \
                                      ((x) & 0x02)? 6 : 7 ) ) )
/*!
 * \brief count trailing zeros (ctz)
 */
#define byte_ctz(r)                                       \
          ( ( r & 1 )?   0 :    /* < mod(2)        */     \
            ( r & 3 )?   1 :    /* < mod(4)        */     \
            ( r & 7 )?   2 :    /* < mod(8)        */     \
            ( r & 15 )?  3 :    /* < mod(16)       */     \
            ( r & 31 )?  4 :    /* < mod(32)       */     \
            ( r & 63 )?  5 :    /* < mod(64)       */     \
            ( r & 127 )? 6 :    /* < mod(128)      */     \
            ( r & 255 )? 7 : 8  /* < mod(256)      */ )

/* includes from mul.c */

typedef struct _Int
{
    BYTE* buf;
    SHORT size;
    SHORT top;
    SHORT topByte;
    SHORT bytelen;
    BYTE  flags;
} Int, *Integer, **Integers;

/* bufOps.c */
RESULT add( Integer, Integer, Integer );
RESULT add_( BYTE*, SHORT,
             BYTE*, SHORT,
             BYTE*, SSHORT );

SHORT bufBitOffset( BYTE*, SHORT );

BYTE cmp( Integer, Integer );
BYTE compare( BYTE*, BYTE*, SHORT );

BYTE* fill ( BYTE*, SHORT, const BYTE*, SHORT );

BYTE* lshiftBuf( BYTE*, SHORT, SHORT,
                 BYTE* , SHORT );
BYTE lshiftByte( BYTE*, BYTE );
void lshift( Integer , SHORT );

Integer makeInt( Integer, BYTE*, SHORT, BYTE );
BYTE neg( BYTE*, SHORT );

void printInteger( Integer );
void printIntegerBits( Integer );

void printBuf( BYTE*, SHORT );

BYTE* rshiftBuf( BYTE*, SHORT, SHORT,
             BYTE*, SHORT);
BYTE rshiftByte( BYTE*, BYTE );
void rshift( Integer, SHORT );

RESULT sub_( BYTE*, SHORT,
            BYTE*,  SHORT,
            BYTE*, SSHORT );
RESULT sub( Integer, Integer, Integer );

/* mul.c */
RESULT mul_(BYTE*, SHORT,
            BYTE*, SHORT,
           BYTE*, SHORT);
RESULT mul16_(BYTE*, SHORT,
              BYTE*, SHORT,
             BYTE*, SHORT);

RESULT mul( Integer,
            Integer,
            Integer );

RESULT sqr( BYTE*, SHORT,
           BYTE*, SHORT );
RESULT sq( Integer, Integer );
/* includes from div.c */
RESULT divide(Integer, Integer,
              Integer, Integer);

/* Number theoritic */
SHORT montGetInv( SHORT );

#define modinv modinv_heap
RESULT modinv_heap( Integer, Integer, Integer );
RESULT modinv_stack( Integer, Integer, Integer );

SHORT montGetInv( SHORT );

RESULT mont_mul_fios( Integer, Integer, Integer, Integer, SHORT );

RESULT mont_modexp_n( Integer, Integer,
                      Integer, Integer);

RESULT mont_mul_ar_mod_n( Integer, Integer, Integers);

RESULT mont_mul_r_mod_n( Integer, Integers );

RESULT mont_modexp_loop( Integer, Integer, Integer, Integer,
                                          Integers, Integers );

RESULT modinv_init( Integer, Integer, Integer, Integers, Integers,
                    Integers, Integers );
RESULT modinv_1( Integer, Integer, Integer, Integer,
                      Integer, Integer, Integer );
RESULT modinv_( Integer, Integer, Integer ,
                Integer, Integer, Integer, Integer );
RESULT mod( Integer, Integer, Integer);


RESULT mod_barrett_init( Integer, Integer[3] );
RESULT mod_barrett( Integer, Integer, Integers );
void mod_barrett_free( Integer[3], BYTE );
RESULT mod_barrett_reduce( Integer, Integer, Integer, Integer, Integer );
RESULT div_quotient( Integer, Integer, Integer );
/* TODO: Test only #ifdef */
#endif
