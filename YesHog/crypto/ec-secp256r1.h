#ifndef EC_SECP256R1_H_
#define EC_SECP256R1_H_
#include <bignum.h>
/*! \see: curve id ec_init_vars */
#define     SECP256R1_ID                                     0x0017

const      BYTE SECP256R1_OID[] ONFLASH =
{
            0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};
const      BYTE SECP256R1_n[] ONFLASH =
{
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD,
            0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
            0x25, 0x51
};
const      BYTE SECP256R1_G[] ONFLASH =
{
            0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8,
            0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D,
            0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8,
            0x98, 0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F,
            0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 0x2B,
            0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40,
            0x68, 0x37, 0xBF, 0x51, 0xF5
};
const      BYTE SECP256R1_h[] ONFLASH =
{
            0x01
};
const      BYTE SECP256R1_p[] ONFLASH =
{
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF
};
const      BYTE SECP256R1_a[] ONFLASH =
{
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFC
};
const      BYTE SECP256R1_m[] ONFLASH =
{
            /* This is _mu_ value used for barrett
               redutions mod n */
            0x01, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x43, 0x19, 0x05,
            0x52, 0xDF, 0x1A, 0x6C, 0x21, 0x01, 0x2F, 0xFD, 0x85, 0xEE,
            0xDF, 0x9B, 0xFE,
};
const      BYTE SECP256R1_u[] ONFLASH =
{
            /* This is _mu_ value used for barrett
               redutions mod p */
            0x01, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
            0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x03
};

#define     SECP256R1_DOMAIN_PARAMS_N_LEN     sizeof( SECP256R1_n )
#define     SECP256R1_DOMAIN_PARAMS_X_LEN          \
                     ( ( ( sizeof( SECP256R1_G ) - 1 ) >> 1 ) + 1 )
#define     SECP256R1_DOMAIN_PARAMS_G_LEN     sizeof( SECP256R1_G )
#define     SECP256R1_DOMAIN_PARAMS_H_LEN     sizeof( SECP256R1_h )
#define     SECP256R1_DOMAIN_PARAMS_P_LEN     sizeof( SECP256R1_p )
#define     SECP256R1_DOMAIN_PARAMS_A_LEN     sizeof( SECP256R1_a )
#define     SECP256R1_DOMAIN_PARAMS_MU_LEN    sizeof( SECP256R1_m )
#define     SECP256R1_DOMAIN_PARAMS_MU_N_LEN  sizeof( SECP256R1_u )
#define     SECP256R1_XLEN   ( ( sizeof( SECP256R1_G ) - 1 ) >> 1 )
#define     SECP256R1_OIDSZ                 sizeof( SECP256R1_OID )
/*!
 * \brief: If malloc/calloc and friends are not decided to be
 *         used, we can use static bufs.
 * This could be a linked list of say N number of structs
 * based on a system limit
 */
typedef struct SECP256R1_STATICMEM
{
    BYTE X_BUF[     SECP256R1_DOMAIN_PARAMS_X_LEN                       ];
    Int  X;
    BYTE Y_BUF[     SECP256R1_DOMAIN_PARAMS_X_LEN                       ];
    Int  Y;
    BYTE X1_BUF[    SECP256R1_DOMAIN_PARAMS_X_LEN                       ];
    Int  X1;
    BYTE Y1_BUF[    SECP256R1_DOMAIN_PARAMS_X_LEN                       ];
    Int  Y1;
    BYTE a_BUF[     SECP256R1_DOMAIN_PARAMS_A_LEN                       ];
    Int  a;
    BYTE n_BUF[     SECP256R1_DOMAIN_PARAMS_N_LEN                       ];
    Int  n;
    BYTE p_BUF[     SECP256R1_DOMAIN_PARAMS_P_LEN                       ];
    Int  p;
    BYTE s_BUF[     SECP256R1_DOMAIN_PARAMS_G_LEN + sizeof(SHORT)       ];
    Int  s;
    BYTE s_sq_BUF[ (SECP256R1_DOMAIN_PARAMS_G_LEN + sizeof(SHORT)) * 2  ];
    Int  s_sq;
    BYTE yInv_BUF[  SECP256R1_DOMAIN_PARAMS_P_LEN + SZ_WORD_B           ];
    Int  yInv;
    BYTE Mu_BUF[    SECP256R1_DOMAIN_PARAMS_MU_LEN                      ];
    Int  Mu;
    BYTE Qo_BUF[    2*SECP256R1_DOMAIN_PARAMS_P_LEN + SZ_WORD_B         ];
    Int  Qo;
    BYTE Q_BUF[     2*SECP256R1_DOMAIN_PARAMS_P_LEN + SZ_WORD_B         ];
    Int  Q;
    BYTE u_BUF[     SECP256R1_DOMAIN_PARAMS_X_LEN + 1                   ];
    Int  u;
    BYTE v_BUF[     SECP256R1_DOMAIN_PARAMS_X_LEN + 1                   ];
    Int  v;
    BYTE x1_BUF[    SECP256R1_DOMAIN_PARAMS_X_LEN + 1                   ];
    Int  x1;
    BYTE x2_BUF[    SECP256R1_DOMAIN_PARAMS_X_LEN + 1                   ];
    Int  x2;
} SECP256R1_STATICMEM;

#endif
