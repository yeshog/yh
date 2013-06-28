/*
 * ec-configured.h
 *
 *  Created on: Mar 24, 2013
 *      Author: yogesh
 */

#ifndef EC_CONFIGURED_H_
#define EC_CONFIGURED_H_
#include <bignum.h>

#define     ECPOINT_COMPRESSED_FORM            3
#define     ECPOINT_UNCOMPRESSED_FORM          4

/* initialize curve params with Q key or G */
#define     EC_INIT_MODE_G                     0
#define     EC_INIT_MODE_Q                     1

/*! \see: ec_set_mod_param */
#define     EC_MOD_MODE_P                      0
#define     EC_MOD_MODE_N                      1

/*!
  \brief: This holds memory/variables so that
          we dont have to allocate/reallocate
          for each iteration
  \note: Size matters:                                 secp160r1
         p = Fp is the prime number                      20
         G = Generator that has Xp, Yp for verification  40
         Q = Pubkey that has Xp, Yp for verification     40
         u1 = e/s mod p where e = hash (ex. SHA1) and    20+20+4*20
              s is part of Signature = (r,s)       |e|s^1mod p|modinv tmp vars|
         u2 = r/s mod p where (r,s) are part of Signature 20+20+4*20
                                                   |r|s^1mod p|modinv tmp vars|
         R = u1G + u2Q Point Addition              s = (Xp-Xq)/(Yp-Yq) mod p
                                           ............ 20  + 20 + 80
                                                   s^2  40
         Total:                             20 + 40 + 40 + 120 + 120 + 120 + 40
                                            Working space is 500 bytes or 1/2 kb
*/
typedef struct EC_vars
{
    Integer X;    /**< X coordinate                             */
    Integer Y;    /**< Y coordinate                             */
    Integer X1;   /**< X1 X-coordinate of point to be added     */
    Integer Y1;   /**< Y1 Y-coordinate of point to be added     */
    Integer s;    /**< s used in point dbl/add calculations     */
    Integer s_sq; /**< s^2 used in point dbl/add calculations   */
    Integer a;    /**< value of a in curve y^3 = x^2 + ax + b   */
    Integer p;    /**< Fp prime                                 */
    Integer yInv; /**< variable to store (Y-Y1)^-1 mod p        */
    Integer Q;    /**< variable used in barrett reduction       */
    Integer Qo;   /**< variable used in mod barrett reduction   */
    Integer Mu;   /**< _mu_ value used in mod barrett reduction */
    Integer u;    /**< variable used in modinv                  */
    Integer v;    /**< variable used in modinv                  */
    Integer x1;   /**< variable used in modinv                  */
    Integer x2;   /**< variable used in modinv                  */
    BYTE    inited;
} EC_vars, *EC_vars_p;

/*!
  \brief: Free ec variables initialized by ec_init_vars
*/
#define EC_vars_free( x )      \
    if( x )                    \
    {                          \
        flint( x->X    );      \
        flint( x->Y    );      \
        flint( x->X1   );      \
        flint( x->Y1   );      \
        flint( x->a    );      \
        flint( x->p    );      \
        flint( x->s    );      \
        flint( x->s_sq );      \
        flint( x->yInv );      \
        flint( x->Qo   );      \
        flint( x->Q    );      \
        flint( x->Mu   );      \
        flint( x->u    );      \
        flint( x->v    );      \
        flint( x->x1   );      \
        flint( x->x2   );      \
    }
/* following to be defined by individual curves
 * This *really* needs to be in system init */
#define ec_set_staticmem_var( x, y ) x.y.buf = x.y##_BUF; \
                             x.y.size = sizeof(x.y##_BUF)

#define ec_init_staticmem( ecvar )       \
    ec_set_staticmem_var(ecvar,  X);     \
    ec_set_staticmem_var(ecvar,  Y);     \
    ec_set_staticmem_var(ecvar, X1);     \
    ec_set_staticmem_var(ecvar, Y1);     \
    ec_set_staticmem_var(ecvar, s);      \
    ec_set_staticmem_var(ecvar, s_sq);   \
    ec_set_staticmem_var(ecvar, a);      \
    ec_set_staticmem_var(ecvar, p);      \
    ec_set_staticmem_var(ecvar, yInv);   \
    ec_set_staticmem_var(ecvar, Q);      \
    ec_set_staticmem_var(ecvar, Qo);     \
    ec_set_staticmem_var(ecvar, Mu);     \
    ec_set_staticmem_var(ecvar, u);      \
    ec_set_staticmem_var(ecvar, v);      \
    ec_set_staticmem_var(ecvar, x1);     \
    ec_set_staticmem_var(ecvar, x2)

#define ec_assign_staticmem_var( ec, ecm, var ) ec->var = &ecm.var; \
                                                 setOffset(ec->var)

#define ec_vars_staticmem_ref( ec, ecvar )    \
    ec_assign_staticmem_var(ec, ecvar, X);    \
    ec_assign_staticmem_var(ec, ecvar, Y);    \
    ec_assign_staticmem_var(ec, ecvar, X1);   \
    ec_assign_staticmem_var(ec, ecvar, Y1);   \
    ec_assign_staticmem_var(ec, ecvar, s);    \
    ec_assign_staticmem_var(ec, ecvar, s_sq); \
    ec_assign_staticmem_var(ec, ecvar, a);    \
    ec_assign_staticmem_var(ec, ecvar, p);    \
    ec_assign_staticmem_var(ec, ecvar, yInv); \
    ec_assign_staticmem_var(ec, ecvar, Q);    \
    ec_assign_staticmem_var(ec, ecvar, Qo);   \
    ec_assign_staticmem_var(ec, ecvar, Mu);   \
    ec_assign_staticmem_var(ec, ecvar, u);    \
    ec_assign_staticmem_var(ec, ecvar, v);    \
    ec_assign_staticmem_var(ec, ecvar, x1);   \
    ec_assign_staticmem_var(ec, ecvar, x2)

RESULT ec_point_add( EC_vars_p );
RESULT ec_point_dbl( EC_vars_p );
RESULT ec_init_vars( SHORT, Integer, EC_vars_p, BYTE );
RESULT ec_init_configured_curve( Integer,  EC_vars_p, BYTE );
RESULT ec_scalar_mul( EC_vars_p, Integer );
RESULT ecc_verify( SHORT, BYTE*, SHORT,
           BYTE*, SHORT, BYTE*, SHORT, BYTE*, SHORT );
RESULT ec_set_mod_param( BYTE, EC_vars_p, BYTE );
SHORT ec_get_curve_id(void);
const BYTE* ec_get_g(void);
SHORT ec_get_glen(void);
const BYTE* ec_get_g_x(void);
const BYTE* ec_get_g_y(void);
SHORT ec_get_xlen(void);
SHORT ec_get_ylen(void);
const BYTE* ec_get_a(void);
SHORT ec_get_alen(void);
const BYTE* ec_get_u(void);
SHORT ec_get_ulen(void);
const BYTE* ec_get_m(void);
SHORT ec_get_mlen(void);
const BYTE* ec_get_p(void);
SHORT ec_get_plen(void);
const BYTE* ec_get_n(void);
SHORT ec_get_nlen(void);
const BYTE* ec_get_oid(void);
SHORT ec_get_oidlen(void);
void ec_print_vars( EC_vars_p );
#endif /* EC_CONFIGURED_H_ */
