/* types */

#define BYTE  uint8_t
#define SBYTE int8_t
#define MAX_BYTE_VAL 255
#define SIZEOF_BYTE 8
#define SIZEOF_SHORT 16
#define SZ_SHORT_PLUS_BYTE 24
#define BYTE_FF 0xFF
#define SZ_BYTE 8
#define SZ_SHORT 16
#define SZ_WORD  32
#define SZ_WORD_B 4
#define SZ_S_BY_B 1
#define SZ_W_BY_S 2
#define SZ_W_MAX_I 3
#define BYTE_FF 0xFF
#define SHORT_B0_MASK 0xFF00
#define SHORT_B1_MASK 0xFF
#define WORD_S0_MASK 0xFFFF0000
#define WORD_S1_MASK 0xFFFF
#define WORD_B0_MASK 0xFF000000
#define WORD_B1_MASK 0x00FF0000
#define WORD_B2_MASK 0x0000FF00
#define WORD_B3_MASK 0x000000FF
#define YES 1
#define NO  0

#define WORD   uint32_t
#define SWORD  int32_t
#define RESULT uint32_t

#define SHORT uint16_t
#define SSHORT int16_t
#define SHORT_HIGH_LSB 0x00FF
#define SHORT_HIGH_MSB 0xFF00
#define UCHAR unsigned char

/* Arch currently we test on gcc 386 */

#ifdef _ARCH_LE

#define REVS( v )  ( ( v & SHORT_B1_MASK ) << SZ_BYTE | \
                     ( v & SHORT_B0_MASK ) >> SZ_BYTE )

#define REVW( v ) ( ( v & WORD_B3_MASK ) << SZ_SHORT_PLUS_BYTE | \
                    ( v & WORD_B0_MASK ) >> SZ_SHORT_PLUS_BYTE | \
                    ( v & WORD_B2_MASK ) << SZ_BYTE | \
                    ( v & WORD_B1_MASK ) >> SZ_BYTE )

#define R_BYTE( b, o ) (* (BYTE*) ( b + o ) )

#define R_SHORT( b, o ) REVS( ( (SHORT) \
       ( *( (SHORT*) ( (BYTE*)b + o ) ) ) ) )

#define R_WORD( b, o ) REVW ( ( (WORD)  \
       ( *( (WORD*)  ( (BYTE*)b + o ) ) ) ) )

#define W_WORD( b, o, v )  ( *( (WORD*)  ( b + o ) ) \
                              = REVW ( (WORD)  v ) )
#define W_SHORT( b, o, v ) ( *( (SHORT*) ( b + o ) ) \
                              = REVS ( (SHORT) v ) )
#endif

#ifdef _ARCH_BE

#define R_BYTE( b, o )  ( *( b + o ) )
#define R_SHORT( b, o ) ( (SHORT) *( (SHORT*) \
                                 ( b + o ) ) )
#define R_WORD( b, o ) ( (WORD) *( (WORD*)    \
                                 ( b + o ) ) )

#define W_BYTE( b, o, v ) ( *( ( BYTE* )   \
                         ( b + o ) ) = v )
#define W_SHORT( b, o, v ) ( *( ( SHORT* ) \
                         ( b + o ) ) = (SHORT)v )
#define W_WORD( b, o, v ) ( *( ( WORD* )   \
                         ( b + o ) ) = (WORD)v )
#endif

/* Common Integer routines arch independent */
#define IR_BYTE(  i, o )  R_BYTE  ( i->buf, o )
#define IR_SHORT( i, o )  R_SHORT ( i->buf, o )
#define IR_WORD(  i, o )  R_WORD  ( i->buf, o )
#define IW_SHORT( i, o, v )  W_SHORT ( i->buf, o, v )
#define IW_WORD(  i, o, v )  W_WORD  ( i->buf, o, v )
#define R_SHORT_LSBS_FROM_WORD( a ) (a & WORD_S1_MASK)
#define R_SHORT_MSBS_FROM_WORD( a ) \
    ( (a & WORD_S0_MASK) >> SZ_SHORT )

/* TODO:64 bit mkWORD. This grossly assumess 32 bit */
#define mkWORD1( b ) \
    ( (WORD) ( *b ) )

#define mkWORD2( b ) \
    ( (WORD) ( ( (WORD)b[0]<<SZ_BYTE )| (WORD)b[1] ) )

#define mkWORD3( b ) \
    ( (WORD) ( (WORD)b[0]<<(2*SZ_BYTE) | \
      (WORD)b[1]<<SZ_BYTE | (WORD)b[2] ) )

#define mkWORD4( b ) R_WORD( b, 0 )

#define mkWORDL( b, l ) \
    ( l == 3 )? \
         mkWORD3( b ): \
    ( l == 2 )? \
         mkWORD2( b ): \
    ( l == 1 )? \
         mkWORD1( b ): \
    R_WORD( b, 0 )
