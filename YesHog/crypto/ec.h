#ifndef EC_H_
#define EC_H_
/* yh config ecCurveParams */
#include "ec-secp256r1.h"
/* end yh config ecCurveParams */

/* yh config ecCurve */
#define     CURVE(y)                           SECP256R1##_##y
/* end yh config ecCurve */

/* Octet to Point */
#define     OCT2PTX(x)           ( (x[0] == 0x04)? (x + 1):x )
#define     OCT2PTX_LEN(x, l) ( (l - (OCT2PTX(x) - x) ) >> 1 )
#define     OCT2PTY(x, l)   ( OCT2PTX(x) + OCT2PTX_LEN(x, l) )
#define     OCT2PTY_LEN                            OCT2PTX_LEN
/* Other parameters given a configured curve */
#define     CURVE_PARMSZ(x)               (sizeof( CURVE(x) ))
#define     CURVE_XLEN(x) OCT2PTX_LEN( CURVE(x), \
                                 CURVE_PARMSZ(x) )
#define     CURVE_YLEN CURVE_XLEN
#define     CURVE_X(x) OCT2PTX(CURVE(x))
#define     CURVE_Y(x) OCT2PTY( CURVE(x), CURVE_PARMSZ(x) )

#endif
