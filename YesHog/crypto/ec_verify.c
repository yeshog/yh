/*
 * ec_verify.c
 *
 *  Created on: Mar 30, 2013
 *      Author: yogesh
 */
#include "ec-configured.h"

/*!
  \brief ECDSA Implementation
  \param 1: [IN] curve, named curve. Currently secp160r1
                 is supported.
  \param 2: [IN] r, part of Signature typle (r, s )
                 in X509 cert
  \param 3: [IN] length of r
  \param 4: [IN] s, part of Signature typle (r, s )
  \param 5: [IN] length of s
  \param 6: [IN] e, hash(tbsCertificate). Currently
                 SHA1(tbsCertificate) der object supported
  \param 7: [IN] length of e
  \param 8: [IN] Q, public key. Only uncompressed format
                 supported. Q(x,y)
  \param 8: [IN] length of Q
  \return OK if certificate's public key checks out,
          or error if any.
*/
RESULT ecc_verify( SHORT curve,
                   BYTE* _r, SHORT l_r, BYTE* _s, SHORT l_s,
                   BYTE* _e, SHORT l_e, BYTE* _q, SHORT l_q )
{
    /* debug */
    printf( "===== MEM PROFILE =====\n" );
    printf( "free [%u]\n", yh_mem() );
#ifdef _AVR_
    /* Really bad hacks for testing. Expose X len in configured
     * curve some day so we can make this smarter
     */
    BYTE _u[64];
    BYTE _s1[37];
    BYTE _Xg[33];
    BYTE _Yg[33];
#endif
    /* end debug */

    /* Convert parameters to Integer's */
    Int Q, E, r, s;
    RESULT _res_ = ERR_STATE;
    makeInt( &Q, _q, l_q, NO );
    makeInt( &E, _e, l_e, NO );
    makeInt( &r, _r, l_r, NO );
    makeInt( &s, _s, l_s, NO );

#ifndef _AVR_
    mint( u, (l_s << 1) );
    /* Get #E aka n corresponding to the named curve */
    mint( s1, ec_get_nlen() + 4 );
#else
    Int u_i, s1_i, Xg_i, Yg_i;
    Integer u   =  &u_i;
    Integer s1  = &s1_i;
    Integer Xg  = &Xg_i;
    Integer Yg  = &Yg_i;
    makeInt( u,   _u, sizeof(_u),  YES );
    makeInt( s1, _s1, sizeof(_s1), YES );
    makeInt( Xg, _Xg, sizeof(_Xg), YES );
    makeInt( Yg, _Yg, sizeof(_Yg), YES );
#endif
    /* X,Y are picked from G or Q */
    EC_vars ecv, *ec;
    ec = &ecv;
    memset( ec, 0, sizeof( EC_vars ) );
    op_chk( ec_init_vars( curve,    &Q,  &ecv,   EC_INIT_MODE_G ),
                                          EC_INIT_VARS_G_FAILED );
    /* debug */
    printf( "\nSignature r, s " );
    printInteger( &r );
    printf( "," );
    printInteger( &s );
    printf( "\n sig^-1 mod p " HEXCALC_OPEN " modinv(" );
    printInteger( &s );
    printf( "," );
    printInteger( ec->p );
    /* end debug */
    /* u1 = e*(s^-1) mod n
     * s^-1 mod p -> ec->s
     * Calculations are mod n where n*P = O
     * i.e. n times Point is the point at infinity */

    op_chk( modinv_( &s, ec->p, ec->s, ec->u,
                     ec->v, ec->x1, ec->x2 ), EC_S_INV_FAILED );
    /* debug */
    printf( ")" HEXCALC_CLOSE "=" );
    printInteger( ec->s );
    printf( "\n s^-1 * e " HEXCALC_OPEN );
    printInteger( ec->s );
    printf( "*" );
    printInteger( &E );
    /* end debug */

    /* s^-1 * e -> u */
    op_chk( mul( ec->s, &E, u ), EC_Sinv_X_E_FAILED );

    /* debug */
    printf( HEXCALC_CLOSE "=" );
    printInteger( u );
    printf( "\n mod( s^-1 * e, p ) " HEXCALC_OPEN " mod(" );
    printInteger( u );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE " = " );
    /* end debug */

    /* s^-1 * e mod n -> u */
    op_chk( mod_barrett_reduce( u, ec->p, ec->Mu,
                          ec->Q, ec->Qo ), EC_U1_MOD_P_FAILED );

    /* debug */
    printInteger( ec->Qo );
    /* end debug */

    reset( u );
    copy( u, ec->Qo );
    copy( s1, ec->s );
    reset( ec->s );

    /* u1 * G */

    /* debug */
    printf( "\n=== u1*G BEGIN ===\n" );
    /* end debug */
    op_chk( ec_set_mod_param( curve, ec, EC_MOD_MODE_P ),
                                EC_SET_MOD_PARAM_P_U1_FAILED );
    op_chk(   ec_scalar_mul( ec, u ),   EC_SCALAR_MUL_FAILED );
    /* debug */
    printf( "\n=== u1*G [X],[Y] = [" );
    printInteger( ec->X );
    printf( "],[" );
    printInteger( ec->Y );
    printf( "] [X1],[Y1] = [" );
    printInteger( ec->X1 );
    printf( "],[" );
    printInteger( ec->Y1 );
    printf( "] === \n" );
    /* end debug */

    /* save X, Y */
#ifndef _AVR_
    cint( Xg, ec->X );
    cint( Yg, ec->Y );
#else
    copy( Xg, ec->X );
    copy( Yg, ec->Y );
#endif
    /* u2 =  r*(s^-1) mod n */
    /* r * (s^-1) mod n -> ec->Qo
     */
    op_chk( ec_set_mod_param( curve, ec, EC_MOD_MODE_N ),
                          EC_SET_MOD_PARAM_N_U2_FAILED );
    op_chk( mul( &r, s1, u ), EC_Sinv_X_R_FAILED );

    /* debug */
    printf( "r * (s^-1) " HEXCALC_OPEN );
    printInteger( &r );
    printf( "*" );
    printInteger( s1 );
    printf( HEXCALC_CLOSE " = " );
    printInteger( u );
    printf( "\n r * s1 mod p " HEXCALC_OPEN " mod(" );
    printInteger( u );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE " = " );
    /* end debug */

    op_chk( mod_barrett_reduce( u, ec->p, ec->Mu,
                          ec->Q, ec->Qo ), EC_U2_MOD_P_FAILED );
    reset( u );
    copy( u, ec->Qo );
    /* debug */
    printInteger( u );
    /* end debug */

    op_chk( ec_init_vars( curve      , &Q, ec, EC_INIT_MODE_Q ),
                                        EC_INIT_VARS_Q_FAILED );

    /* debug */
    printf( "\n=== u2*Q BEGIN ===\n" );
    /* end debug */
    op_chk( ec_set_mod_param( curve, ec, EC_MOD_MODE_P ),
                                 EC_SET_MOD_PARAM_P_U2_FAILED );
    op_chk(   ec_scalar_mul( ec, u ),   EC_SCALAR_MUL1_FAILED );
    /* debug */
    printf( "\n=== u2*Q [X],[Y] = [" );
    printInteger( ec->X );
    printf( "],[" );
    printInteger( ec->Y );
    printf( "] [X1],[Y1] = [" );
    printInteger( ec->X1 );
    printf( "],[" );
    printInteger( ec->Y1 );
    printf( "] === \n" );
    /* end debug */
    /* Copy saved ints from u1*G */
    copy( ec->X1, Xg );
    copy( ec->Y1, Yg );
#ifndef _AVR_
    flint( Xg );
    flint( Yg );
#endif
    /* debug */
    printf( "\n=== u1*G + u2*Q [X],[Y] = [" );
    printInteger( ec->X );
    printf( "],[" );
    printInteger( ec->Y );
    printf( "] [X1],[Y1] = [" );
    printInteger( ec->X1 );
    printf( "],[" );
    printInteger( ec->Y1 );
    printf( "] === \n" );
    /* end debug */
    op_chk( ec_point_add( ec ), EC_U1xG_PLUS_U2xQ_FAILED );
    /* debug */
    printf( "\n=== RESULT R = [X],[Y] = [" );
    printInteger( ec->X );
    printf( "],[" );
    printInteger( ec->Y );
    printf( "] [X1],[Y1] = [" );
    printInteger( ec->X1 );
    printf( "],[" );
    printInteger( ec->Y1 );
    printf( "] === \n" );
    /* end debug */
    /* Finally R( Xr, Yr ) is done and Xr == Signature( r )
       means ecc verify was successful */
    op_chk( ec_set_mod_param( curve, ec, EC_MOD_MODE_N ),
                                  EC_SET_MOD_PARAM_N_R_FAILED );
    op_chk( mod_barrett_reduce( ec->X, ec->p, ec->Mu,
                          ec->Q, ec->Qo ), EC_Rs_MOD_N_FAILED );
    if( cmp( &r, ec->Qo ) != L_EQ_R )
    {
        _res_ = EC_SIG_VERIFY_X_NEQ_R;
    }
    /* debug */
    printf( "===== MEM PROFILE =====\n" );
    printf( "free [%u]\n", yh_mem() );
    /* end debug */
    goto done;
no_mem_:
    _res_ = ECC_VERIFY_NOMEM;
done:
#ifndef _AVR_
    flint( u );
    flint( s1 );
#endif
    //EC_vars_free( (ec) );
    /* debug */
    printf( "===== MEM PROFILE =====\n" );
    printf( "free [%u]\n", yh_mem() );
    /* end debug */
    return _res_;
}

