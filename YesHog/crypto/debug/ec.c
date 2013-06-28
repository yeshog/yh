/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/
#include "ec.h"
#include "ec-configured.h"

static CURVE(STATICMEM) ec_static_vars;


/*!
 * \brief: print all ec variable values
 */

void ec_print_vars( EC_vars_p ec )
{
#define SEP "\n"
#define ec_print_var( X )                 \
        printf( SEP #X "[" );             \
        printInteger( X );                \
        printf( "] Size [%d]", X->size ); \
        printf( " Len [%d]", X->bytelen )
    ec_print_var( ec->X );
    ec_print_var( ec->Y );
    ec_print_var( ec->X1 );
    ec_print_var( ec->Y1 );
    ec_print_var( ec->s );
    ec_print_var( ec->s_sq );
    ec_print_var( ec->a );
    ec_print_var( ec->p );
    ec_print_var( ec->yInv );
    ec_print_var( ec->Q );
    ec_print_var( ec->Qo );
    ec_print_var( ec->Mu );
    ec_print_var( ec->u );
    ec_print_var( ec->v );
    ec_print_var( ec->x1 );
    ec_print_var( ec->x2 );
}
/*!
 * \brief initialize ec variables from the given pub key
 *        corresponding to configured named curve
 */
RESULT ec_init_q(Integer Q, EC_vars_p ec )
{
    RESULT _res_ = OK;
    SHORT i = 0;
    /* Choose Xg, Yg from Q (pubkey ) */
    if( !Q || !ec )
    {
        return EC_INIT_G_NOT_INITED;
    }
    while( i < Q->size && Q->buf[i] == 0 ) i++;
    if( Q->buf[i] != ECPOINT_UNCOMPRESSED_FORM )
    {
        _res_ = EC_INIT_UNSUPPORTED_FORM;
        goto done;
    }
    i++;
    if( CURVE_PARMSZ(G) > Q->size )
    {
        _res_ = EC_INIT_Q_OVERFLOW;
        goto done;
    }
    fillmem( ec->X->buf,  ec->X1->size,  (Q->buf + i),
                                      ec_get_xlen() );
    fillmem( ec->Y->buf, ec->Y1->size,
       (Q->buf + i + ec_get_xlen() ), ec_get_ylen() );
    fillmem( ec->X1->buf, ec->X1->size, (Q->buf + i ),
                                      ec_get_xlen() );
    fillmem( ec->Y1->buf, ec->Y1->size, ( Q->buf + i +
                    ec_get_xlen() ),  ec_get_ylen() );
    setOffset( ec->X );
    setOffset( ec->Y );
    setOffset( ec->X1 );
    setOffset( ec->Y1 );
    /* TODO: do we really need to reset others (apart
     * from X,Y) that is */
done:
    return _res_;
}

/* debug */
#ifdef DEBUG
RESULT ec_init_configured_curve( Integer Q, EC_vars_p ec, BYTE m )
{
    RESULT _res_ = ERR_STATE;
    SHORT i = 0;
    if( !Q || !ec )
        return EC_INIT_NULL_PARAMS;
    if( m == EC_INIT_MODE_G )
    {   /* Choose Xg, Yg from G */
        memset( ec, 0, sizeof( EC_vars ) );
        bint( Xg, CURVE_XLEN(G) + 1, CURVE_X(G), CURVE_XLEN(G) );
        bint( Yg, CURVE_YLEN(G) + 1, CURVE_Y(G), CURVE_YLEN(G) );
        ec->X = Xg;
        ec->Y = Yg;
        mint( X1g, CURVE_XLEN(G) + 1 );
        mint( Y1g, CURVE_YLEN(G) + 1 );
        ec->X1 = X1g;
        ec->Y1 = Y1g;
        copy( ec->X1, ec->X );
        copy( ec->Y1, ec->Y );
        dint( a, CURVE(a), CURVE_PARMSZ(a) );
        /* We allocate N since N > P so that barrett sizes
           are calculated correctly */
        dint( p, CURVE(n), CURVE_PARMSZ(n) );
        /* variable holding _mu_ of mod n */
        dint( k, CURVE(m), CURVE_PARMSZ(m) );
        mint( s, CURVE_PARMSZ(G) + sizeof(SHORT) );
        mint( ssq, s->size * 2 );
        mint( yInv, (MAX( p->size, ec->Y->size)
                                    + SZ_WORD_B) );
        ec->a    = a;
        ec->p    = p;
        ec->s    = s;
        ec->s_sq = ssq;
        ec->yInv = yInv;
        /* allocate Barrett reduction variables */
        Integer R[3];
        R[0] = R[1] = NULL;
        /* set initial _mu_ value for calc mod n */
        R[2] = ec->Mu = k;
        if( !ec->Qo )
            _res_ = mod_barrett_init( ec->p, R );
        else
            _res_ = OK;
        if( _res_ != OK )
            goto done;
        ec->Qo = R[0];
        ec->Q  = R[1];
        op_chk(modinv_init(ec->X1, ec->p, ec->yInv,
                &ec->u, &ec->v, &ec->x1, &ec->x2 ),
                                  EC_YINV_FAILED );
    } else
    {   /* Choose Xg, Yg from Q (pubkey ) */
        if( !Q || !ec )
        {
            return EC_INIT_G_NOT_INITED;
        }
        while( i < Q->size && Q->buf[i] == 0 ) i++;
        if( Q->buf[i] != ECPOINT_UNCOMPRESSED_FORM )
        {
            _res_ = EC_INIT_UNSUPPORTED_FORM;
            goto done;
        }
        i++;
        if( CURVE_PARMSZ(G) > Q->size )
        {
            _res_ = EC_INIT_Q_OVERFLOW;
            goto done;
        }
        fill( ec->X->buf,  ec->X1->size,  (Q->buf + i),
                                       CURVE_XLEN(G) );
        fill( ec->Y->buf, ec->Y1->size,
         (Q->buf + i + CURVE_XLEN(G)), CURVE_XLEN(G) );
        fill( ec->X1->buf, ec->X1->size, (Q->buf + i ),
                                       CURVE_XLEN(G) );
        fill( ec->Y1->buf, ec->Y1->size, ( Q->buf + i +
                     CURVE_XLEN(G) ),  CURVE_XLEN(G) );
        setOffset( ec->X );
        setOffset( ec->Y );
        setOffset( ec->X1 );
        setOffset( ec->Y1 );
        /* TODO: do we really need to reset others (apart
         * from X,Y) that is */
    }
    ec_print_vars( ec );
    _res_ = OK;
    goto done;
no_mem_:
    _res_ = EC_ERROR_NOMEM_INIT;
done:
    return _res_;
}
#endif
/* end debug */
/*!
  \brief: initialize the configured ec curve using static
          bufs instead of allocing
  \param [IN] Q if ec->X, ex->Y are to  be initialized
            with the public key values, this param is used.
            When Q is to be used, param m MUST be EC_INIT_MODE_Q
  \param [OUT] ec variables sizes and values are allocated here
            later when more curves are supported, this function
            must be made a lot smarter
  \param [IN] If mode is EC_INIT_MODE_G then generator point values
            G(x,y)are used, if EC_INIT_MODE_Q is used pub key
            Q(x,y) values are copied to already initiated ec(X,Y)
  \return if memory is available and allvars are allocated, function
          returns success, else returns failure code.
 */
RESULT ec_staticinit_configured_curve( Integer Q, EC_vars_p ec, BYTE m )
{
    RESULT _res_;
    if( ec->inited == NO )
    {
        memset( ec, 0, sizeof( EC_vars ) );
        memset( &ec_static_vars, 0, sizeof( ec_static_vars ) );
        ec_init_staticmem( ec_static_vars );
        ec_vars_staticmem_ref(ec, ec_static_vars );
        ec->inited = YES;
    }
    /*debug */
    printf( "\nSECP256R1_DOMAIN_PARAMS_X_LEN[%lu]  SECP256R1_G[%lu] res[%lu]"
            " X_BUF sz[%lu]\n",
            SECP256R1_DOMAIN_PARAMS_X_LEN, sizeof( SECP256R1_G),
            ( ( ( sizeof( SECP256R1_G ) - 1 ) >> 1 ) + 1 ),
            sizeof(ec_static_vars.X1_BUF) );
    /* end debug */
    if( m == EC_INIT_MODE_G )
    {
        fill( ec->X->buf, ec->X->size, ec_get_g_x(), ec_get_xlen() );
        setOffset(ec->X);
        fill( ec->X1->buf, ec->X1->size, ec_get_g_x(), ec_get_xlen() );
        setOffset(ec->X1);
        fill( ec->Y->buf, ec->Y->size, ec_get_g_y(), ec_get_ylen() );
        setOffset(ec->Y);
        fill( ec->Y1->buf, ec->Y1->size, ec_get_g_y(), ec_get_ylen() );
        setOffset(ec->Y1);
        fill( ec->a->buf, ec->a->size, ec_get_a(), ec_get_alen() );
        setOffset(ec->a);
        /* n matters only in verify mode, not in tls handshake
         * For testing certs we set p to n as default */
        //makeInt( ec->p, CURVE(n), CURVE_PARMSZ(n), NO );
        fill( ec->p->buf, ec->a->size, ec_get_n() , ec_get_nlen() );
        setOffset(ec->p);
        /* barrett reductions modulo n consistent with above */
        fill( ec->Mu->buf, ec->Mu->size, ec_get_m(), ec_get_mlen() );
        setOffset(ec->Mu);
        _res_ = OK;
    } else
    {
        _res_ =  ec_init_q( Q, ec );
    }
    /* debug */
    ec_print_vars( ec );
    /* end debug */
    return _res_;
}

/*!
  \brief: Call initializers based on curve
  \param 1: [IN] curve, the id of the curve in ec.h
*/
RESULT ec_init_vars( SHORT curve, Integer Q, EC_vars_p ec, BYTE m )
{
    if( curve == CURVE(ID) )
    {
        /* instead of mallocing */
        //return ec_init_configured_curve( Q, ec, m );
        /* use static version */
       return ec_staticinit_configured_curve(Q, ec, m);
    }
    return EC_INIT_CURVE_NOT_SUPPORTED;
}

/*!
  \brief: (Xr, Yr) = (Xp, Yp) + (Xq, Yq)
          Where P, Q and R are ec points
  \param 1: [INOUT] ec parameters. Result is:
           (ec->X, ec->Y) = (ec->X, ec->Y) +
                            (ec->X1, ec->Y1)
  \note: Caller sets all parameters necessary
         for point addition. This function is
         suitable for repeated point additions
         for y^2 = x^3 + ax +b and not used for
         2^m curves. All variables are pre-set
         by calling ec_init_vars before this
         function is called.
*/
RESULT ec_point_add( EC_vars_p ec )
{
    RESULT _res_ = 0;

    /* debug */
    printf( "\nadd X " HEXCALC_OPEN "ec_pt_add_x(" );
    printInteger( ec->X );
    printf( "," );
    printInteger( ec->Y );
    printf( "," );
    printInteger( ec->X1 );
    printf( "," );
    printInteger( ec->Y1 );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE );
    printf( "\nadd Y " HEXCALC_OPEN "ec_pt_add_y(" );
    printInteger( ec->X );
    printf( "," );
    printInteger( ec->Y );
    printf( "," );
    printInteger( ec->X1 );
    printf( "," );
    printInteger( ec->Y1 );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE );
    printf( "\nXp-Xq, " HEXCALC_OPEN );
    printInteger( ec->X );
    printf( "-" );
    printInteger( ec->X1 );
    /* end debug */

    op_chk( sub(ec->X, ec->X1, ec->Qo ), EC_PT_ADD_SUB_X_X1_ERR );
    /* debug */
    printf( HEXCALC_CLOSE " = " );
    printInteger( ec->Qo );
    printf( "\n Y-Y1, " HEXCALC_OPEN );
    printInteger( ec->Y );
    printf( "-" );
    printInteger( ec->Y1 );
    /* end debug */

    op_chk( sub(ec->Y, ec->Y1, ec->Q ),  EC_PT_ADD_SUB_Y_Y1_ERR );
   /* debug */
    printf( HEXCALC_CLOSE " = " );
    printInteger( ec->Q );
    printf( "\n (X-X1)^-1, " HEXCALC_OPEN "modinv(" );
    printInteger( ec->Qo );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE " = " );
    /* end debug */

    /* TODO: Call modinv long version */
    /* ec->Qo = X-X1 */
    op_chk(modinv_( ec->Qo, ec->p, ec->yInv, ec->u,
                 ec->v, ec->x1, ec->x2 ), EC_X_X1_MODINV_FAILED );
    /* debug */
    printInteger( ec->yInv );
    printf( "\n mod(inv(X-X1) * (Y-Y1), P), " HEXCALC_OPEN );
    printInteger( ec->yInv );
    printf( "*" );
    printInteger( ec->Q );
    printf( HEXCALC_CLOSE " = " );
    /* end debug */

    /* s = inv(X-X1) * (Y-Y1) */
    op_chk( mul( ec->yInv, ec->Q, ec->s ), EC_PT_Yx_XINV_FAILED );

    /* debug */
    printInteger( ec->s );
    printf( "\n s mod p, " HEXCALC_OPEN "mod(" );
    printInteger( ec->s );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE " = " );
    /* end debug */

    /* s = mod(inv(X-X1) * (Y-Y1), P) */
    op_chk( mod_barrett_reduce( ec->s, ec->p, ec->Mu,
                         ec->Q, ec->Qo ), EC_PT_ADD_MODP_FAILED );
    copy( ec->s, ec->Qo );

    /* debug */
    printInteger( ec->s );
    printf( "\ns^2 - Xp -Xq, s^2 mod p, s^2, " HEXCALC_OPEN );
    printInteger( ec->s );
    printf( "*" );
    printInteger( ec->s );
    printf( HEXCALC_CLOSE "=" );
    /* end debug */

    /* Xr = s^2 -Xp - Xq -> (ec->Qo) */
    /* debug */
    op_chk( mul( ec->s, ec->s, ec->s_sq ), EC_PT_ADD_SxS_FAILED );
    /* end debug */
    //op_chk( sq( ec->s, ec->s_sq ), EC_PT_ADD_SxS_FAILED );
    /* debug */
    printInteger( ec->s_sq );
    printf( "s^2 mod p" HEXCALC_OPEN "mod(");
    printInteger( ec->s_sq );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE " = " );
    /* end debug */
    op_chk( mod_barrett_reduce( ec->s_sq, ec->p, ec->Mu,
                      ec->Q, ec->Qo ), EC_PT_ADD_XR_MODP_FAILED );
    copy( ec->s_sq, ec->Qo );
    /* debug */
    printInteger( ec->s_sq );
    printf( "\n s^2 - Xp -Xq " HEXCALC_OPEN );
    printInteger( ec->s_sq );
    printf( "-" );
    printInteger( ec->X );
    printf( "-" );
    printInteger( ec->X1 );
    printf( HEXCALC_CLOSE " = " );
    /* end debug */
    op_chk( sub( ec->s_sq, ec->X, ec->s_sq ),
                                   EC_PT_ADD_SSQ_MINUS_X_FAILED );
    op_chk( sub( ec->s_sq, ec->X1, ec->s_sq ),
                                  EC_PT_ADD_SSQ_MINUS_X1_FAILED );
    /* debug */
    printInteger( ec->s_sq );
    printf( "\n mod( Xr, p ), " HEXCALC_OPEN "mod(" );
    printInteger( ec->s_sq );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE " = " );
    /* end debug */
    /* Qo = Xr = (mod((X-X1)^-1*(Y-Y1), P)) -X -X1*/
    op_chk( mod_barrett_reduce( ec->s_sq, ec->p, ec->Mu,
                      ec->Q, ec->Qo ), EC_PT_ADD_XR_MODP_FAILED );
    reset( ec->Q );

    /* debug */
    printInteger( ec->Qo );
    printf( "\n  Yr, (Xp - Xr), " HEXCALC_OPEN );
    printInteger( ec->X1 );
    printf( "-" );
    printInteger( ec->Qo );
    /* end debug */

    /* Yr = (Xp - Xr)*s - Yp */
    op_chk( sub( ec->X1, ec->Qo, ec->Q ), EC_PT_ADD_X_Xr_FAILED );
    /* ec->X = Qo (Xr) can now be set */
    copy( ec->X, ec->Qo );
    reset( ec->Qo );

    /* debug */
    printf( HEXCALC_CLOSE " = " );
    printInteger( ec->Q );
    printf( "\n (Xp-Xr)*s, " HEXCALC_OPEN );
    printInteger( ec->Q );
    printf( "*" );
    printInteger( ec->s );
    printf( HEXCALC_CLOSE " = " );
    /* end debug */

    op_chk( mul( ec->Q, ec->s, ec->s_sq ),   EC_PT_ADD_S_x_X_XR );

    /* debug */
    printInteger( ec->s_sq );
    printf( "\n (Xp - Xr)*s - Yp, " HEXCALC_OPEN );
    printInteger( ec->s_sq );
    printf( "-" );
    printInteger( ec->Y );
    printf( HEXCALC_CLOSE " = " );
    /* end debug */

    op_chk( sub( ec->s_sq, ec->Y1, ec->s_sq ),
                                        EC_PT_ADD_SUB_Yp_FAILED );

    /* debug */
    printInteger( ec->s_sq );
    printf( "\n Yr mod p " HEXCALC_OPEN "mod(");
    printInteger( ec->s_sq );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE " = " );
    /* end debug */

    op_chk( mod_barrett_reduce( ec->s_sq, ec->p, ec->Mu,
                        ec->Q, ec->Qo ), EC_PT_ADD_MODYr_FAILED );
    copy( ec->Y, ec->Qo );

    /* debug */
    printInteger( ec->Y );
    printf( "\n" );
    printf( "ADD [X],[Y] = [" );
    printInteger( ec->X );
    printf( "],[" );
    printInteger( ec->Y );
    printf( "] [X1],[Y1] = [" );
    printInteger( ec->X1 );
    printf( "],[" );
    printInteger( ec->Y1 );
    printf( "]\n" );
    /* end debug */

done:
    return _res_;
}

/*!
  \brief: EC point doubling routine for y^2 = x^3 + ax +b
          curves
  \param 1: [INOUT] (ec->X, ec->Y) = 2*(ec->X, ec->Y)
  \return: error, if any OK if doubling is successful
*/
RESULT ec_point_dbl( EC_vars_p ec )
{
    RESULT _res_ = 0;
    BYTE c[] = { 0, 3 };
    /* s = (3Xp^2 + A)/(2Yp) */
    /* debug */
    printf( "\ndbl X " HEXCALC_OPEN "ec_pt_dbl_x(" );
    printInteger( ec->a );
    printf( "," );
    printInteger( ec->X );
    printf( "," );
    printInteger( ec->Y );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE );
    printf( "\ndbl Y " HEXCALC_OPEN "ec_pt_dbl_y(" );
    printInteger( ec->a );
    printf( "," );
    printInteger( ec->X );
    printf( "," );
    printInteger( ec->Y );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE );
    printf( "\n" HEXCALC_OPEN "mod(" );
    printInteger( ec->X );
    printf( "*" );
    printInteger( ec->X );
    printf( "," );
    /* end debug */
    /* Xp^2 mod p -> (ec->Qo) */
    /* debug */
    op_chk( mul( ec->X, ec->X, ec->s ),             EC_X2_FAILED );
    /* end debug */
    //op_chk( sq( ec->X, ec->s ),             EC_X2_FAILED );
    /* debug */
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE " = " );
    /* end debug */
    op_chk( mod_barrett_reduce( ec->s, ec->p, ec->Mu,
                          ec->Q, ec->Qo ), EC_X_x_X_MOD_P_FAILED );

    /* debug */
    printInteger( ec->Qo );
    printf( "\n" );
    printf( "3Xp^2 " HEXCALC_OPEN );
    printInteger( ec->Qo );
    printf( "*0003" HEXCALC_CLOSE "=" );
    /* end debug */
    reset( ec->s_sq );
    /* Xp^2 * 3 -> (ec->s_sq) */
    op_chk( mul_( ec->Qo->buf  +  ec->Qo->topByte,
                  ec->Qo->bytelen, c, sizeof( c ),
               ec->s_sq->buf, ec->s_sq->size ), EC_X2_x_3_FAILED );
    setOffset( ec->s_sq );
    /* TODO: copy does not check size */

    /* debug */
    printInteger( ec->s_sq );
    printf( "\n 3Xp^2 + A = " HEXCALC_OPEN );
    printInteger( ec->s_sq );
    printf( "+" );
    printInteger( ec->a );
    printf( HEXCALC_CLOSE "=" );
    /* end debug */

    /* 3Xp^2 + A -> (ec->s_sq)*/
    op_chk( add( ec->s_sq, ec->a, ec->s_sq ), 
                                         EC_NUMERATOR_ADD_FAILED );

    /* debug */
    printInteger( ec->s_sq );
    printf( "\nreduce " HEXCALC_OPEN "mod(" );
    printInteger( ec->s_sq );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE " = " );
    /* end debug */

    /* (3Xp^2 + A) mod p -> (ec->s)*/
    op_chk( mod_barrett_reduce( ec->s_sq, ec->p, ec->Mu,
                                 ec->Q, ec->Qo ), EC_MODP_FAILED );
    copy( ec->s, ec->Qo );

    /* debug */
    printInteger( ec->s );
    printf("\n modinv 2Yp = " HEXCALC_OPEN "modinv(");
    /* end debug */

    /* 2Yp */
    lshift( ec->Y, 1 );
    /* debug */
    printInteger( ec->Y );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE " = " );
    /* end debug */

    op_chk( modinv_(ec->Y , ec->p, ec->yInv, ec->u,
                   ec->v, ec->x1, ec->x2 ), EC_MODINV_2Yp_FAILED );
    /* Restore Y */
    rshift( ec->Y, 1 );

    /* debug */
    printInteger( ec->yInv );
    printf( "\n" );
    printf( "(3Xp^2 + A)*yInv mod p " HEXCALC_OPEN "mod(" );
    printInteger( ec->s );
    printf( "*" );
    printInteger( ec->yInv );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE " = " );
    /* end debug */

    /* (3Xp^2 + A)*(yInv) mod p -> (ec->Qo) */
    op_chk( mul(ec->s, ec->yInv, ec->s_sq),   EC_S_x_YINV_FAILED );
    op_chk( mod_barrett_reduce( ec->s_sq, ec->p, ec->Mu,
                         ec->Q, ec->Qo ),  EC_SxYINV_MODP_FAILED );
    reset( ec->s_sq );

    /* (3Xp^2 + A)*(yInv) mod p -> 
           (ec->Qo) -> (ec->s) */
    copy( ec->s, ec->Qo );

    /* s^2 mod p -> (e->s_sq) */
    /* debug */
    mul( ec->s, ec->s, ec->s_sq );
    /* end debug */
    //sq( ec->s, ec->s_sq );
    /* debug */
    printInteger( ec->Qo );
    printf( "\n" );
    printf( "s^2 mod p " HEXCALC_OPEN "mod(");
    printInteger( ec->s );
    printf( "*" );
    printInteger( ec->s );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE " = " );
    /* end debug */

    op_chk( mod_barrett_reduce( ec->s_sq, ec->p, ec->Mu,
                              ec->Q, ec->Qo ), EC_S2_MODP_FAILED );

    /* debug */
    printInteger( ec->Qo );
    printf( "\n Xr = s^2 mod p - 2Xp " HEXCALC_OPEN );
    printInteger( ec->Qo );
    printf( "-" );
    /* end debug */

    /* Xr = s^2 - 2Xp -> (ec->Qo) */
    reset( ec->Q );
    copy( ec->Q, ec->X );
    lshift( ec->Q, 1 );

    /* debug */
    printInteger( ec->Q );
    /* end debug */

    op_chk( sub( ec->Qo, ec->Q, ec->Qo ),   EC_SUB_S2_2Xp_FAILED );
    /* Xr mod p */
    /*debug */
    printf( HEXCALC_CLOSE " = " );
    printInteger( ec->Qo );
    printf( "\n Xr mod p " HEXCALC_OPEN "mod(" );
    /* end debug */
    copy( ec->s_sq, ec->Qo );
    /* debug */
    printInteger( ec->s_sq );
    printf( "," );
    printInteger( ec->p );
    printf( ")" );
    /* end debug */
    op_chk( mod_barrett_reduce( ec->s_sq, ec->p, ec->Mu,
                              ec->Q, ec->Qo ), EC_Xr_MODP_FAILED );
    /* debug */
    printf( HEXCALC_CLOSE " = " );
    printInteger( ec->Qo );
    printf( "\n Pt Y, (Xp -Xr)*s, Xp-Xr " HEXCALC_OPEN );
    printInteger( ec->X );
    printf( "-" );
    printInteger( ec->Qo );
    /* end debug */

    reset( ec->Q );

    /* (Xp - Xr) -> (ec->Q) */
    op_chk( sub( ec->X, ec->Qo, ec->Q ),        EC_Yr_SUB_FAILED );

    /* debug */
    printf( HEXCALC_CLOSE " = " );
    printInteger( ec->Q );
    printf( "\n (Xp-Xr)*s - Yp " );
    printInteger( ec->Q );
    printf( "*" );
    printInteger( ec->s );
    /* end debug */
    /* Now we save Qo to Xp, original X
       is hereby kaput */
    copy( ec->X, ec->Qo );
    reset( ec->Qo );
    /* (Xp - Xr)*s -> (ec->Qo) */
    reset( ec->s_sq );

    op_chk( mul( ec->Q, ec->s, ec->s_sq ),    EC_Yr_MUL_S_FAILED );

    /* debug */
    printf( "=" );
    printInteger( ec->s_sq );
    printf( "\n (Xp - Xr)*s mod n " );
    printf( HEXCALC_OPEN "mod(" );
    printInteger( ec->s_sq );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE " = " );
    /* end debug */

    op_chk( mod_barrett_reduce( ec->s_sq, ec->p, ec->Mu,
                   ec->Q, ec->Qo ), EC_Yr_Xp_MINUS_Xr_x_S_FAILED );
    /*  (Xp - Xr)*s - Yp -> (ec->Qo) */
    /* debug */
    printInteger( ec->Qo );
    printf( "\n" HEXCALC_OPEN );
    printInteger( ec->Qo );
    printf( "-" );
    printInteger( ec->Y );
    /* end debug */
    op_chk( sub( ec->Qo, ec->Y, ec->Qo ),     EC_Yr_ADD_Y_FAILED );
    /* debug */

    printf( HEXCALC_CLOSE " = " );
    printInteger( ec->Qo );
    printf( "\n (Xp-Xr)*s - Yp mod p, " HEXCALC_OPEN "mod(" );
    printInteger( ec->Qo );
    printf( "," );
    printInteger( ec->p );
    printf( ")" HEXCALC_CLOSE " = " );
    /* end debug */
    reset( ec->s_sq );
    copy( ec->s_sq, ec->Qo );
    op_chk( mod_barrett_reduce( ec->s_sq, ec->p, ec->Mu,
                              ec->Q, ec->Qo ), EC_Yr_MODP_FAILED );
    copy( ec->Y, ec->Qo );

    /* debug */
    printInteger( ec->Y );
    printf( "\n" );
    printf( "DBL [X],[Y] = [" );
    printInteger( ec->X );
    printf( "],[" );
    printInteger( ec->Y );
    printf( "] [X1],[Y1] = [" );
    printInteger( ec->X1 );
    printf( "],[" );
    printInteger( ec->Y1 );
    printf( "]\n" );
    /* end debug */

done:
    return _res_;
}

/*!
  \brief: calculate K*P(x,y) where K is an integer
  \param 1: [INOUT] ec point and parameters
  \param 2: [IN] K scalar multiplier to ec
  \return ec->X, ec->Y = K*P(x,y)
*/
RESULT ec_scalar_mul( EC_vars_p ec, Integer K )
{
    RESULT _res_ = ERR_STATE;
    SSHORT j = K->top - 2;
    SSHORT i = 0;
    /* debug */
    printf( "\n" );
    printf( "\nInteger k " );
    printInteger( K );
    printf(" Bit String [" );
    printIntegerBits( K );
    printf( "]\nECC Q = [" );
    printInteger( ec->X );
    printf( "],[" );
    printInteger( ec->Y );
    printf( "] P = [" );
    printInteger( ec->X1 );
    printf( "],[" );
    printInteger( ec->Y1 );
    printf( "]\n" );
    /* end debug */
    for( ; j >= 0; j--, i++ )
    {
        /* debug */
        printf( "ECC Iteration bit %d iteration [%d]"
                " bit [%s]\nEC DBL ec->X = 2*ec->X\n",
                 j, i, (bitAtPosition( K, j ))? "1":"0" );
        /* end debug */

        op_chk( ec_point_dbl( ec ), EC_PT_kP_DBL_FAILED );
        /* debug */
        printInteger( ec->Y );
        printf( "\n" );
        printf( "DBL [X],[Y] = [" );
        printInteger( ec->X );
        printf( "],[" );
        printInteger( ec->Y );
        printf( "] [X1],[Y1] = [" );
        printInteger( ec->X1 );
        printf( "],[" );
        printInteger( ec->Y1 );
        printf( "]\n" );
        /* end debug */
        if( bitAtPosition( K, j ) )
        {
            /* debug */
            printf( "\nEC ADD ec->X1 = ec->X1 + ec->X\n" );
            /* end debug */
            op_chk( ec_point_add( ec ), EC_PT_kP_ADD_FAILED );
            /* debug */
            printInteger( ec->Y );
            printf( "\n" );
            printf( "ADD [X],[Y] = [" );
            printInteger( ec->X );
            printf( "],[" );
            printInteger( ec->Y );
            printf( "] [X1],[Y1] = [" );
            printInteger( ec->X1 );
            printf( "],[" );
            printInteger( ec->Y1 );
            printf( "]\n" );
            /* end debug */
        }
    }
done:
    return _res_;
}

/*!
  \brief: Set value of ec operations modulus for
          y^2 = x^3 + ax^2 + b curves.
          When calculating u1 and u2 operations are modulo n
          When doing scalar multiplication operations are modulo p
*/
RESULT ec_set_mod_param( BYTE curve, EC_vars_p ec, BYTE mode )
{
    if( mode == EC_MOD_MODE_P )
    {
        fill( ec->Mu->buf, ec->Mu->size, ec_get_u(), ec_get_ulen() );
        setOffset( ec->Mu );
        fill( ec->p->buf, ec->p->size, ec_get_p(), ec_get_plen() );
        setOffset( ec->p );
    } else
    {
        fill( ec->Mu->buf, ec->Mu->size, ec_get_m(), ec_get_mlen() );
        setOffset( ec->Mu );
        fill( ec->p->buf, ec->p->size, ec_get_n(), ec_get_nlen() );
        setOffset( ec->p );
    }
    return OK;
}

/* getters to const parameters */
SHORT ec_get_curve_id(void)
{
    return CURVE(ID);
}
const BYTE* ec_get_g_x(void)
{
    return CURVE_X(G);
}
SHORT ec_get_xlen(void)
{
    return CURVE(XLEN);
}
const BYTE* ec_get_g_y(void)
{
    return CURVE_Y(G);
}
SHORT ec_get_ylen(void)
{
    return CURVE(XLEN);;
}
const BYTE* ec_get_a(void)
{
    return CURVE(a);
}
SHORT ec_get_alen(void)
{
    return CURVE_PARMSZ(a);
}
const BYTE* ec_get_g(void)
{
    return CURVE(G);
}
SHORT ec_get_glen(void)
{
    return CURVE_PARMSZ(G);
}
const BYTE* ec_get_u(void)
{
    return CURVE(u);
}
SHORT ec_get_ulen(void)
{
    return CURVE_PARMSZ(u);
}
const BYTE* ec_get_m(void)
{
    return CURVE(m);
}
SHORT ec_get_mlen(void)
{
    return CURVE_PARMSZ(m);
}
const BYTE* ec_get_p(void)
{
    return CURVE(p);
}
SHORT ec_get_plen(void)
{
    return CURVE_PARMSZ(p);
}
const BYTE* ec_get_n(void)
{
    return CURVE(n);
}
SHORT ec_get_nlen(void)
{
    return CURVE_PARMSZ(n);
}
const BYTE* ec_get_oid(void)
{
    return CURVE(OID);
}
SHORT ec_get_oidlen(void)
{
    return CURVE(OIDSZ);
}
