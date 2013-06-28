#include "tls_handshake.h"
static char TLS_MSECRET_LABEL[] ONFLASH = "master secret";
static char TLS_KEY_EXP_LABEL[] ONFLASH = "key expansion";
/* yh config certificate */
BYTE yh_servcert[] ONFLASH = 
{
  0x30, 0x82, 0x02, 0x36, 0x30, 0x82, 0x01, 0xDE, 0xA0, 0x03, 
  0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0x95, 0x4B, 0x05, 0x1B, 
  0x06, 0x4D, 0x2D, 0x5A, 0x30, 0x09, 0x06, 0x07, 0x2A, 0x86, 
  0x48, 0xCE, 0x3D, 0x04, 0x01, 0x30, 0x79, 0x31, 0x0B, 0x30, 
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 
  0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 
  0x02, 0x57, 0x41, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 
  0x04, 0x07, 0x0C, 0x07, 0x53, 0x65, 0x61, 0x74, 0x74, 0x6C, 
  0x65, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x0A, 
  0x0C, 0x06, 0x59, 0x65, 0x73, 0x48, 0x6F, 0x67, 0x31, 0x14, 
  0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0B, 0x45, 
  0x6E, 0x67, 0x69, 0x6E, 0x65, 0x65, 0x72, 0x69, 0x6E, 0x67, 
  0x31, 0x24, 0x30, 0x22, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 
  0x1B, 0x79, 0x68, 0x63, 0x61, 0x2D, 0x73, 0x65, 0x63, 0x70, 
  0x32, 0x35, 0x36, 0x72, 0x31, 0x43, 0x41, 0x2E, 0x79, 0x65, 
  0x73, 0x68, 0x6F, 0x67, 0x2E, 0x63, 0x6F, 0x6D, 0x30, 0x1E, 
  0x17, 0x0D, 0x31, 0x33, 0x30, 0x32, 0x32, 0x38, 0x30, 0x35, 
  0x35, 0x32, 0x32, 0x33, 0x5A, 0x17, 0x0D, 0x31, 0x37, 0x30, 
  0x34, 0x30, 0x38, 0x30, 0x35, 0x35, 0x32, 0x32, 0x33, 0x5A, 
  0x30, 0x79, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 
  0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0B, 0x30, 0x09, 0x06, 
  0x03, 0x55, 0x04, 0x08, 0x0C, 0x02, 0x57, 0x41, 0x31, 0x10, 
  0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x53, 
  0x65, 0x61, 0x74, 0x74, 0x6C, 0x65, 0x31, 0x0F, 0x30, 0x0D, 
  0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x06, 0x59, 0x65, 0x73, 
  0x48, 0x6F, 0x67, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 
  0x04, 0x0B, 0x0C, 0x0B, 0x45, 0x6E, 0x67, 0x69, 0x6E, 0x65, 
  0x65, 0x72, 0x69, 0x6E, 0x67, 0x31, 0x24, 0x30, 0x22, 0x06, 
  0x03, 0x55, 0x04, 0x03, 0x0C, 0x1B, 0x79, 0x68, 0x63, 0x61, 
  0x2D, 0x73, 0x65, 0x63, 0x70, 0x32, 0x35, 0x36, 0x72, 0x31, 
  0x43, 0x41, 0x2E, 0x79, 0x65, 0x73, 0x68, 0x6F, 0x67, 0x2E, 
  0x63, 0x6F, 0x6D, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 
  0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 
  0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 
  0x83, 0xB4, 0xA6, 0x0A, 0x58, 0xCF, 0xB9, 0x4B, 0x4B, 0x36, 
  0x08, 0xB4, 0xDA, 0x6C, 0x53, 0xDF, 0xF5, 0x46, 0xEB, 0x24, 
  0x5C, 0x62, 0x79, 0x77, 0x09, 0x84, 0x8F, 0x69, 0xEE, 0x41, 
  0xB8, 0x47, 0xEF, 0x16, 0xD2, 0x9B, 0x71, 0x47, 0x11, 0x77, 
  0x03, 0x58, 0x1B, 0x22, 0xF5, 0x2E, 0x89, 0x43, 0xB2, 0xA6, 
  0xD7, 0x4A, 0xF2, 0xB9, 0x2E, 0xC9, 0x3F, 0xC1, 0xE0, 0xEC, 
  0x1A, 0x2E, 0x06, 0xAF, 0xA3, 0x50, 0x30, 0x4E, 0x30, 0x1D, 
  0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x2A, 
  0x38, 0x9E, 0x30, 0x7F, 0x7A, 0x3C, 0xFA, 0xA0, 0x02, 0x8E, 
  0xC1, 0x9A, 0xDD, 0x38, 0x1C, 0xBA, 0x86, 0xEA, 0xBB, 0x30, 
  0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 
  0x80, 0x14, 0x2A, 0x38, 0x9E, 0x30, 0x7F, 0x7A, 0x3C, 0xFA, 
  0xA0, 0x02, 0x8E, 0xC1, 0x9A, 0xDD, 0x38, 0x1C, 0xBA, 0x86, 
  0xEA, 0xBB, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 
  0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x09, 0x06, 0x07, 
  0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01, 0x03, 0x47, 0x00, 
  0x30, 0x44, 0x02, 0x20, 0x4B, 0xF0, 0x76, 0x3F, 0xA6, 0x14, 
  0x0B, 0x14, 0xA4, 0xDC, 0x62, 0x00, 0xD2, 0x8C, 0x7C, 0xA3, 
  0x28, 0xC5, 0x52, 0xA1, 0xE9, 0xC0, 0x88, 0x9A, 0x1B, 0x96, 
  0x08, 0x05, 0x0F, 0xF1, 0xA0, 0x0A, 0x02, 0x20, 0x08, 0xA0, 
  0x01, 0x0D, 0x46, 0x66, 0xD9, 0x3E, 0x1E, 0x87, 0xEF, 0xE9, 
  0xBC, 0x11, 0x0C, 0x86, 0xDF, 0x02, 0x72, 0x55, 0x0D, 0xB8, 
  0x9B, 0xDD, 0xE0, 0x1A, 0xD1, 0xE2, 0x15, 0x4E, 0x30, 0xFB
};
BYTE yh_servkey[] ONFLASH =
{
  0xCF, 0x9F, 0x5A, 0x03, 0x51, 0xB0, 0x1A, 0xA5, 0xF0, 0x53,
  0xC8, 0xA7, 0xD0, 0xE3, 0xCE, 0x86, 0x05, 0xA6, 0x7F, 0x60,
  0xB5, 0xBD, 0x92, 0xA5, 0xD7, 0x13, 0x41, 0xDF, 0xD6, 0x3E,
  0x95, 0x31
};

/* end yh config certificate */
RESULT tls_check_curve( BYTE* pos, SHORT len )
{
    SSHORT l = len;
    while ( l >=0 )
    {
        if( R_SHORT( pos, 0 ) == ec_get_curve_id() )
            return OK;
        l   -= TLS_CURVEID_SZ;
        pos += TLS_CURVEID_SZ;
    }
    return TLS_CLIENTHELLO_CURVE_NOMATCH;
}

/*!
  \brief  : Client Hello
  \param 1: yh_sock with l4 information
  \todo   : it is perhaps safer to pass l4 only
  \note   : size matters - client hello is about
            250 bytes in length.
*/
RESULT tls_client_hello( yh_socket* s )
{
    tls_record              rec;
    tls_handshake            th;
    client_hello             ch;
    tls_clienthello_ext      te;
    SHORT                  j, i;
    BYTE                   *pos;
    yh_tls_data_p      sec_data;
    RESULT                _res_;
    i = j = 0;

    if( s->applen < TLS_CLIENTHELLO_MIN_LEN )
    {
        return TLS_CLIENTHELLO_MALFORMED;
    }
    /* Save client random for kdf in sock's opaque data
       for later */
    sec_data = (yh_tls_data_p) s->opaque_sec_data;
    /* TLS finish message will need sha1(handshake_msgs)
     * so initialize ctx here */
    printf( "ClientHello memory [%d]\r\n", yh_mem() );
    sec_data->h = yh_calloc( 1, sizeof( TlsHandshakeHash ) );
    if( !sec_data->h )
    {
        return TLS_CLIENTHELLO_HASH_NOMEM;
    }
    sha1_init( &sec_data->h->sh );
    md5_init(  &sec_data->h->md );

    /* debug */
    printf( "digesting [%lu] clienthello bytes\n", TLS_CH_LEN( s ) );
    hexdump( TLS_CH_OFFSET( s ) , TLS_CH_LEN( s )  );
    /* end debug */

    /*  RFC 2246 7.4.9. Finished verify_data
        All of the data from all handshake messages up to but not
        including this message. This is only data visible at the
        handshake layer and does not include record layer headers.
     */
    sha1_update( &sec_data->h->sh, TLS_CH_OFFSET( s ), TLS_CH_LEN( s ) );
    md5_update(  &sec_data->h->md, TLS_CH_OFFSET( s ), TLS_CH_LEN( s ) );

    rec = (tls_record) s->app;
    th  = (tls_handshake) ((BYTE* )rec + sizeof( TlsRecord ) );
    th->length = R_STRUCT_VAR_TYPE( SHORT, th->length );
    ch  = (client_hello) ((BYTE*)th + sizeof( TlsHandshake ) );

    if( th->msg_type != THT_ClientHello )
    {
        return TLS_CLIENTHELLO_UNEXPECTED_MSG;
    }

    pos = &ch->session_id_len;
    /* TODO: do we care about record layer version */
    if( ch->version[0]    !=   TLS_SUPPORTED_MAJOR_VER &&
        ch->version[1]    !=   TLS_SUPPORTED_MINOR_VER   )
    {
        return TLS_CLIENTHELLO_UNSUPPORTED_VER;
    }
    /* Save the security parameters */
    memcpy( sec_data->random.client_random, ch->random,
                                    TLS_HELLORND_LEN );
    /* opaque SessionID<0..32> which actually means len = 33 */
    if( ch->session_id_len > 0 )
    {
        ch->session_id = pos + 1;
        pos += ch->session_id_len;
    } else
    {
        pos++;
    }
    /* cipher suite len */
    i = ( R_SHORT( pos, 0 ) >> 1 );
    if( i > TLS_CLIENT_HELLO_MAX_SUITES )
    {
        return TLS_CLIENT_TOO_MANY_SUITES;
    }
    /* cipher suites */
    for( ; j < i; j++ )
    {
        pos += 2;
        /* evil coder says we only supporteth 1 */
        if( R_SHORT( pos, 0 ) == TLS_SUPPORTED_CIPHSUITE )
        {
            break;
        }
    }
    if( j == i )
    {
        return TLS_CIPHSUITE_NOT_SUPPORTED;
    }
    pos += ( ( i - j ) << 1 );
    /* Compression method len */
    i = *pos;
    for( j = 0; j < i ; j++ )
    {
        /* discard compression method */
        pos++;
    }
    /* extensions length */
    pos++;
    i = R_SHORT( pos, 0 );
    pos += 2;
    while( i > 0 )
    {
        if( (pos - s->app) > s->applen )
        {
            return TLS_CLIENTHELLO_PARSE_ERROR;
        }
        if( s->applen - (pos - s->app) <
            sizeof( TlsClientHelloExt ) )
        {
            return TLS_EXTENSIONS_LEN_TOO_SMALL;
        }
        te = (tls_clienthello_ext) pos;
        switch( (R_STRUCT_VAR_TYPE( SHORT, te->type )) )
        {
            case TLS_EXT_SERVER_NAME:
                break;
            case TLS_EXT_ELLIPTIC_CURVES:
                j = R_STRUCT_VAR_TYPE( SHORT, te->len );
                _res_ = tls_check_curve( pos + 
                         sizeof(TlsClientHelloExt), j );
                break;
            case TLS_EXT_ELLIPTIC_POINT_FORMATS:
                /* and this */
                break;
            case TLS_EXT_SESSION_TICKET:
                break;
            default:
                break;
        }
        pos += ( R_STRUCT_VAR_TYPE( SHORT, te->len ) +
                          sizeof(TlsClientHelloExt) );
        i   -= ( R_STRUCT_VAR_TYPE( SHORT, te->len ) +
                          sizeof(TlsClientHelloExt) );
    }
    return _res_;
}

/* TODO: strt thinkin of rand() ASAP */
#define TLS_TEST_SERV_RANDOM "\x1\x2\x3\x4\x5\x6\x7\x8" \
                             "\x1\x2\x3\x4\x5\x6\x7\x8" \
                             "\x1\x2\x3\x4\x5\x6\x7\x8" \
                             "\x1\x2\x3\x4\x5\x6\x7\x8"

RESULT tls_server_hellcertdone( yh_socket* s )
{
    tls_handshake        th;
    server_hello         sh;
    tls_certificates  certs;
    tls_certificate    cert;
    SHORT              sh_l, c_l, shd_l;
    yh_tls_data_p  sec_data;
    sec_data = (yh_tls_data_p) s->opaque_sec_data;
    sh_l = c_l = shd_l = 0;

    tls_record rec = (tls_record) s->app;
    rec->version[0]         =        TLS_SUPPORTED_MAJOR_VER;
    rec->version[1]         =        TLS_SUPPORTED_MINOR_VER;
    rec->content_type       =           TLS_RECORD_HANDSHAKE;

    th  = (tls_handshake)( (BYTE* )rec + sizeof(TlsRecord) );
    th->msg_type            =                THT_ServerHello;
    th->tlen                =                              0;

    sh = (server_hello) ( (BYTE*) th + sizeof(TlsHandshake));
    sh->version[0]          =        TLS_SUPPORTED_MAJOR_VER;
    sh->version[1]          =        TLS_SUPPORTED_MINOR_VER;
    sh->cipher_suite        =  REVS(TLS_SUPPORTED_CIPHSUITE);
    sh->compression_method  =    TLS_COMPRESSION_METHOD_NULL;
    memcpy( sh->random, TLS_TEST_SERV_RANDOM, TLS_HELLORND_LEN );

    sh_l = sizeof(ServerHello);
    W_STRUCT_VAR_TYPE( SHORT,  th->length, sh_l );
    sh_l = sh_l + sizeof( TlsHandshake );

    /* debug */
    printf( "digesting [%d] serverhello bytes\n", sh_l );
    hexdump( (BYTE*)th, sh_l );
    /* end debug */

    /* digest handshake layer */
    sha1_update( &sec_data->h->sh, (BYTE*) th, sh_l );
    md5_update(  &sec_data->h->md, (BYTE*) th, sh_l );

    W_STRUCT_VAR_TYPE( SHORT, rec->length, sh_l );
    sh_l += sizeof( TlsRecord );

    /* Server Certificate */
    rec  = (tls_record)                      (s->app + sh_l);
    rec->version[0]         =        TLS_SUPPORTED_MAJOR_VER;
    rec->version[1]         =        TLS_SUPPORTED_MINOR_VER;
    rec->content_type       =           TLS_RECORD_HANDSHAKE;

    th = (tls_handshake) ( (BYTE* )rec + sizeof(TlsRecord) );
    th->msg_type      =                      THT_Certificate;
    th->tlen                =                             0;

    certs = ( tls_certificates )
                     ( (BYTE*) th + sizeof( TlsHandshake ) );
    certs->tlen             =                              0;

    cert = ( tls_certificate )
               ( (BYTE*) certs + sizeof( TlsCertificates ) );
    cert->tlen              =                              0;
    yh_memcpy( ( (BYTE*) cert + sizeof(TlsCertificate) ),
                           yh_servcert, sizeof(yh_servcert));

    c_l = sizeof(yh_servcert);
    W_STRUCT_VAR_TYPE( SHORT, cert->length,  c_l );
    c_l += sizeof( TlsCertificate );
    W_STRUCT_VAR_TYPE( SHORT, certs->length, c_l );
    c_l += sizeof( TlsCertificates );
    W_STRUCT_VAR_TYPE( SHORT, th->length,    c_l );
    c_l += sizeof( TlsHandshake );

    /* debug */
    printf( "digesting [%d] certificate bytes\n", c_l );
    hexdump( (BYTE*)th, c_l );
    /* end debug */

    /* digest handshake layer */
    sha1_update( &sec_data->h->sh, (BYTE*) th, c_l );
    md5_update(  &sec_data->h->md, (BYTE*) th, c_l );

    W_STRUCT_VAR_TYPE( SHORT, rec->length,   c_l );
    c_l += sizeof( TlsRecord );

    /* ServerHelloDone  */
    rec = (tls_record)               ( s->app + sh_l + c_l );
    rec->version[0]         =        TLS_SUPPORTED_MAJOR_VER;
    rec->version[1]         =        TLS_SUPPORTED_MINOR_VER;
    rec->content_type       =           TLS_RECORD_HANDSHAKE;

    th  = (tls_handshake)( (BYTE* )rec + sizeof(TlsRecord) );
    th->msg_type            =            THT_ServerHelloDone;
    th->tlen                =                              0;
    th->length              =                              0;

    shd_l = sizeof( TlsHandshake );
    W_STRUCT_VAR_TYPE( SHORT, rec->length, shd_l );

    /* debug */
    printf( "digesting [%d] serverhellodone bytes\n", shd_l );
    hexdump( (BYTE*)th, shd_l );
    /* end debug */
    /* digest serverhellodone */
    sha1_update( &sec_data->h->sh, (BYTE*) th, shd_l );
    md5_update(  &sec_data->h->md, (BYTE*) th, shd_l );

    shd_l += sizeof( TlsRecord );

    /* save server random for kdf */
    sec_data = (yh_tls_data_p) s->opaque_sec_data;
    memcpy( sec_data->random.server_random,
            sh->random, TLS_HELLORND_LEN );

    s->txlen = sh_l + c_l + shd_l;
    sec_data->tls_state = TLS_SERVER_HELLO_DONE_SENT;
    return OK;
}

RESULT tls_handle_client_hello( yh_socket* s )
{
    RESULT _res_   =  tls_client_hello(s);
    if( _res_ != OK )
    {
        return _res_;
    }
    /* now we are free to muck with the client hello */
    _res_ = s->resize_cb( s, 1024 );
    if( _res_ != OK )
    {
        return TLS_RESIZE_CLIENTHELLO_FAILED;
    }
    _res_ = tls_server_hellcertdone( s );
    return _res_;
}

/*!
  \brief : exchange the client and server randoms
  \note: assumes the 2 hellos are declared
         in the same block.
         i.e. right after each other, else .. good
         luck
*/
void tls_switch_random(BYTE* s)
{
    BYTE b[TLS_HELLORND_LEN];
    memcpy( b, s, sizeof(b) );
    memcpy( s, s + TLS_HELLORND_LEN, TLS_HELLORND_LEN );
    memcpy( s + TLS_HELLORND_LEN, b, TLS_HELLORND_LEN );
}

/*!
  brief : handle client key exchange
*/
RESULT tls_handle_client_key_exchange( yh_socket* s )
{
    tls_record                                    rec;
    tls_handshake                                  th;
    SHORT                                       cke_l;
    EC_vars ecv, *ec;
    BYTE* pos;
    Int Q, d;
    RESULT _res_;
    yh_tls_data_p sec_data;
    BYTE random[ TLS_HELLORND_LEN << 1 ];
    /* Is there a better way */
    cke_l = R_SHORT( s->app + 3, 0 );

    /* TODO: whnever your dumb ass brain has config.h
       check min lengths */
    if( s->applen < TLS_MIN_CLIENT_KEY_XCHG_ECDH_LEN )
    {
        return TLS_CLIENT_KEYXCHG_ECDH_MALFORMED;
    }

    /* debug */
    printf( "Digesting client key xchg \n" );
    hexdump( s->app + sizeof(TlsRecord), cke_l );
    /* end debug */

    /* digest clientkeyexchange */
    sec_data = (yh_tls_data_p) s->opaque_sec_data;
    sha1_update( &sec_data->h->sh, s->app + sizeof(TlsRecord),
                                                      cke_l );
    md5_update(  &sec_data->h->md, s->app + sizeof(TlsRecord),
                                                      cke_l );

    rec = (tls_record) s->app;
    th  = (tls_handshake)  ( ( BYTE* ) rec + sizeof(TlsRecord) );
    pos = ( (BYTE*) th ) + sizeof( TlsHandshake );

    if( th->msg_type != THT_ClientKeyExchange )
    {
        return TLS_CLIENT_KEYXCHG_UNEXPECTED_MSG;
    }
    if( R_STRUCT_VAR_TYPE( SHORT, th->length ) !=
                         ec_get_xlen() * 2 + 2 )
    {
        return TLS_CLIENT_KEYXCHG_EC_PT_BADLEN;
    }
    pos ++;
    if( *pos != ECPOINT_UNCOMPRESSED_FORM )
    {
        return TLS_CLIENT_KEYXCHG_EC_PT_COMPRESSED;
    }

    makeInt( &Q, pos, ec_get_xlen() * 2 + 1, NO );
    makeInt( &d, yh_servkey, sizeof( yh_servkey ), NO );

    /* Calculate d*Qc where Qc is the public key of
     * the client.
     * First we initialize the sizes so memory is allocated
     */
    ec = &ecv;
    op_chk( ec_init_vars( ec_get_curve_id(),  &Q,  ec,
            EC_INIT_MODE_G ),    TLS_INIT_EC_FAILED );

    /* Since we are not in verify mode, initialize it
       the pubkey of the peer */
    op_chk( ec_init_vars( ec_get_curve_id(),  &Q,  ec,
            EC_INIT_MODE_Q ),    TLS_INIT_EC_FAILED );

    /* TODO: Optimmize */
    fill( ec->Mu->buf, ec->Mu->size, ec_get_u(), ec_get_ulen() );
    setOffset( ec->Mu );
    fill( ec->p->buf, ec->p->size, ec_get_p(), ec_get_plen() );
    setOffset( ec->p );
    /* debug */
    printf( "ECKAS-DH1 Client Pubkey\n" );
    ec_print_vars( ec );
    printf( "\n" );
    /* end debug */

    /* d(sG), where d is our pvk, s is the peer's
       pvk and G is the common point */
    _res_ = ec_scalar_mul( ec, &d );
    if( _res_ != OK )
    {
        printf( "ECDH Failed with error [%X]\n", _res_ );
        return TLS_ECDH_FAILED;
    }
    /* debug */
    printf( "Scalar mul result [%X]\n", _res_ );
    printInteger( &d );
    printf( "\n" );
    ec_print_vars( ec );
    printf( "\n" );
    /* end debug */

    /* debug */
    printf( "EC value of Z\n" );
    hexdump( ec->X->buf, ec_get_xlen() );
    /* end debug */

    /* debug */
    int i = 0;
    printf( "tls_prf(" );
    for( ; i < ec_get_xlen() - ec->X->bytelen; i++ )
    {
        printf( "00" );
    }
    printInteger( ec->X );
    printf( ", %d, %s, %lu,", ec_get_xlen(),TLS_MSECRET_LABEL,
                                 strlen( TLS_MSECRET_LABEL ) );
    for( i = 0; i < (TLS_HELLORND_LEN << 1) ; i++ )
    {
        printf( "%02X", sec_data->random.client_random[i] );
    }
    printf( ", %d", (TLS_HELLORND_LEN << 1) );
    printf( ") = " );
    /* end debug */
    tls_prf(ec->X->buf + ( ec->X->size - ec_get_xlen() ),
               ec_get_xlen(), (BYTE*)  TLS_MSECRET_LABEL,
                               strlen(TLS_MSECRET_LABEL),
                          sec_data->random.client_random,
                                 (TLS_HELLORND_LEN << 1),
                                 sec_data->master_secret,
                                 TLS_MASTER_SECRET_LEN );

    /* debug */
    for( i = 0; i < TLS_MASTER_SECRET_LEN; i++ )
    {
        printf( "%02X", sec_data->master_secret[i] );
    }
    /* end debug */
    /* When generating key_block random(s) are
       reversed */
    memcpy( random, sec_data->random.client_random,
                           TLS_HELLORND_LEN << 1 );
    tls_switch_random( random );

    /* key block, after this cli, srv random is fubar */
    tls_prf(      sec_data->master_secret,
                    TLS_MASTER_SECRET_LEN,
                (BYTE*) TLS_KEY_EXP_LABEL,
                strlen(TLS_KEY_EXP_LABEL),
            random, TLS_HELLORND_LEN << 1,
                (BYTE*) &sec_data->sparam,
               sizeof(tlsv1_sec_params) );
    /* debug */
    printf( "\nKey block\n" );
    hexdump( (BYTE*) &sec_data->sparam, sizeof(tlsv1_sec_params) );
    /* end debug */
    sec_data->tls_state = TLS_CLI_KEYXCHG_OK;
    _res_ = OK;
done:
    EC_vars_free( (ec) );
    return _res_;
}

RESULT tls_fin_rx( yh_socket* s, SHORT pos )
{
    tls_record                                     rec;
    yh_tls_data_p                             sec_data;
    sha1_ctx                               cli_sha_ctx;
    md5_ctx                                cli_md5_ctx;
    SHORT                                            l;
    BYTE*                                          enc;

    BYTE verify_data[12];
    BYTE cli_hash[ SHA1_LEN + MD5_LEN ];
    enc      = s->app + pos;
    rec      = (tls_record) enc;
    sec_data = (yh_tls_data_p) s->opaque_sec_data;

    if( sec_data->tls_state != TLS_CHANGE_CIPHSPEC_RX )
    {
        return TLS_FIN_BAD_STATE;
    }
    if( R_STRUCT_VAR_TYPE( SHORT, rec->length ) < TLS_FINVFY_SZ )
    {
        return TLS_FIN_DECRYPT_SZ;
    }

    enc = enc + sizeof(TlsRecord);

    /* debug */
    printf( "tls_fin_rx app [%p] rec[%p] enc[%p]\n",
                                 s->app, rec, enc );
    /* end debug */

    /* copy sha1 and md5 ctx from the clients perspective
       into a different ctx so we can verify later */
    memcpy( &cli_sha_ctx, &sec_data->h->sh, sizeof( sha1_ctx ) );
    memcpy( &cli_md5_ctx, &sec_data->h->md, sizeof( md5_ctx  ) );

    /* update our hash before we muck with the data via
       'in place' decryption */
    l = R_STRUCT_VAR_TYPE( SHORT, rec->length );
    /* debug */
    printf( "All application data\n" );
    hexdump( s->app, s->applen );
    printf( "Before decrypt\n" );
    hexdump( enc, l );
    /* end debug */

    /* debug */
    printf( "App address[%p]\n", enc );
    printf( "aes_cbc_decrypt( " );
    printBuf( sec_data->sparam.client_write_IV, CIPH_BLOCK_SZ );
    printf( "," );
    printBuf( sec_data->sparam.client_write_key, CIPH_BLOCK_SZ );
    printf( ", " );
    printBuf( enc, l );
    printf( " )\n" );
    /* end debug */

    /* decrypt the client FIN */
    l = R_STRUCT_VAR_TYPE( SHORT, rec->length );
    l = aes_cbc_decrypt( sec_data->sparam.client_write_IV,
                        sec_data->sparam.client_write_key,
                                                 enc, l );
    /*
     * enc now has finished handshake of l = 12 + 4 + 20 = 36
     * bytes. If not talk to the hand
     */
    if( l != TLS_VFY_LEN )
    {
        return TLS_FIN_DECRYPT_FAILED;
    }

    /* debug */
    printf( "verify data - client \n" );
    hexdump( enc, 48 );
    /* end debug */

    /* check the FIN and verify_data */
    md5_final( &cli_md5_ctx, cli_hash );
    sha1_final( &cli_sha_ctx, cli_hash + MD5_LEN );
    sec_data = (yh_tls_data_p) s->opaque_sec_data;

    /* verify the clients verify_data in FIN */
    tls_prf( sec_data->master_secret, TLS_MASTER_SECRET_LEN,
                               (BYTE*) TLS_FIN_CLIENT_LABEL,
                               strlen(TLS_FIN_CLIENT_LABEL),
                               cli_hash, sizeof( cli_hash ),
                        verify_data, sizeof( verify_data ));

    /* debug */
    printf( "verify_data, calculated\n" );
    hexdump( verify_data, sizeof( verify_data ) );
    /* end debug */

    /* judgement day, point enc to the right offset.
       At this point enc points to decrypted data and
       its contents are a TlsHandshake with 12 bytes
       of verify_data */
    if( memcmp( enc + sizeof( TlsHandshake ), verify_data,
                                 sizeof( verify_data ) ) )
    {
        return TLS_VERIFY_DATA_FAILED;
    }
    /* debug */
    printf( "TLSv1 verify OK\n" );
    printf( "Digesting client handshake\n" );
    /* end debug */
    /* digest handshake only for S -> C */
    sha1_update( &sec_data->h->sh, enc, TLS_VFY_HS_LEN );
    md5_update(  &sec_data->h->md, enc, TLS_VFY_HS_LEN );

    /* debug */
    hexdump( enc, TLS_VFY_HS_LEN );
    /* end debug */

    sec_data->tls_state = TLS_FIN_RX_OK;
    return OK;
}

/*!
 * \brief write a tls record
 * \param [INOUT] yh_socket*
 * \param [INOUT] data to be sent via tls. Data IS overwritten
 *                with encrypted data and mac
 * \param [IN]    data content type
 * \param [IN]    data length
 * \param [OUT]   size of written data
 */
RESULT tls_write( yh_socket* s, BYTE* data, SHORT len,
     BYTE type, SHORT* outlen )
{
    SSHORT w_l = 0;
    yh_tls_data_p sec_data;
    BYTE *text[5];
    SHORT text_len[5];
    BYTE sseq[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    BYTE  ver[2] = { 0x03, 0x01 };
    w_l = (s->applen - (data - s->app )) -
             ( TLS_WRITE_OVERHEAD + len );
    if( w_l < 0 )
    {
        return TLS_WRITE_OVERFLOW;
    }
    /*
     * TLS MAC (sha1) = HMAC_SHA1( mac write secret, seq_num +
     *                          handshake type + tls version +
     *                                     datalen + content )
     */
    sec_data = (yh_tls_data_p) s->opaque_sec_data;
    W_SHORT( sseq, (sizeof(sseq) - sizeof(SHORT) ),
                                  sec_data->sseq );
    w_l = REVS( len );
    text[0]     =         sseq;
    text_len[0] = sizeof(sseq);
    text[1]     =        &type;
    text_len[1] =            1;
    text[2]     =          ver;
    text_len[2] =            2;
    text[3]     = (BYTE*) &w_l;
    text_len[3] =  sizeof(w_l);
    text[4]     =         data;
    text_len[4] =          len;
    /* debug */
    SHORT i = 0;
    printf( "hmac_sha1( ");
    printBuf( sec_data->sparam.server_write_MAC_secret,
                                            SHA1_LEN );
    for( ; i < 5; i++ )
    {
        printf( "," );
        printBuf( text[i], text_len[i] );
    }
    printf( " )\n" );
    /* end debug */
    /* write hmac @ data + len */
    hmac_sha1( text, text_len, 5,
               sec_data->sparam.server_write_MAC_secret,
               SHA1_LEN, data + len );
    /* encrypt data and hmac */
    w_l = len + SHA1_LEN;
    w_l = aes_cbc_encrypt(sec_data->sparam.server_write_IV,
                    sec_data->sparam.server_write_key,
                    data, w_l, data, 0 );
    *outlen = w_l;
    return OK;
}

RESULT tls_write_type(yh_socket* s, SHORT s_o, BYTE** text,
                             SHORT* text_len, BYTE text_ct,
                                  BYTE type, SHORT* outlen)
{
    SHORT text_sz = 0;
    BYTE i = 0;
    BYTE* w = s->app + s_o;
    SSHORT w_l = s->applen;
    for( ; i< text_ct; i++ )
    {
        text_sz += text_len[i];
    }
    if( type == TLS_RECORD_HANDSHAKE )
    {
            tls_handshake th = (tls_handshake) w;
            W_STRUCT_VAR_TYPE( SHORT, th->length, text_sz );
            th->tlen = 0;
            th->msg_type = TLS_RECORD_HANDSHAKE;
            w += sizeof( TlsHandshake );
    }
    for( i = 0; i < text_ct ; i++ )
    {
        w_l -= text_len[i];
        if( w_l )
        {
            memcpy( w, text[i], text_len[i] );
            w += text_len[i];
        } else
        {
            return TLS_WRITE_TYPE_OVERFLOW;
        }
    }
    return tls_write( s, s->app + s_o, text_sz, type, outlen);
}

RESULT tls_fin_tx( yh_socket* s )
{
    tls_record                                              rec;
    RESULT _res_                           =          ERR_STATE;
    yh_tls_data_p                                      sec_data;
    BYTE                         srv_hash[ SHA1_LEN + MD5_LEN ];
    BYTE*                                                     v;
    SHORT                                             cc_l, e_l;
    tls_handshake                                            th;

    sec_data = (yh_tls_data_p) s->opaque_sec_data;
    cc_l = e_l = 0;

    if( sec_data->tls_state != TLS_FIN_RX_OK )
    {
        return TLS_FIN_TX_BAD_STATE;
    }
    /* build change cipher spec */
    rec                        =            (tls_record) s->app;
    rec->version[0]            =        TLS_SUPPORTED_MAJOR_VER;
    rec->version[1]            =        TLS_SUPPORTED_MINOR_VER;
    rec->content_type          =     TLS_RECORD_CHANGE_CIPHSPEC;
    W_STRUCT_VAR_TYPE( SHORT, rec->length, 1);
    v                          = (BYTE*)rec + sizeof(TlsRecord);
    *v                         =                              1;
    cc_l = 1 + sizeof( TlsRecord );
    /* debug */
    printf( "Change Cipher Spec\n");
    hexdump( s->app, cc_l );
    /* end debug */
    /* build fin */
    rec                   =      (tls_record) ( s->app + cc_l );
    rec->version[0]            =        TLS_SUPPORTED_MAJOR_VER;
    rec->version[1]            =        TLS_SUPPORTED_MINOR_VER;
    rec->content_type          =           TLS_RECORD_HANDSHAKE;

    th    = (tls_handshake) ( (BYTE*) rec + sizeof(TlsRecord) );
    th->msg_type               =                   THT_Finished;
    th->tlen                   =                              0;
    W_STRUCT_VAR_TYPE( SHORT, th->length, sizeof(TlsFinished));

    v = (BYTE*) th + sizeof( TlsHandshake);
    md5_final(  &sec_data->h->md, srv_hash );
    sha1_final( &sec_data->h->sh, srv_hash + MD5_LEN );

    /* write verify_data */
    tls_prf(      sec_data->master_secret, TLS_MASTER_SECRET_LEN,
            (BYTE*) TLS_FIN_SRV_LABEL, strlen(TLS_FIN_SRV_LABEL),
           srv_hash, sizeof( srv_hash ), v, sizeof(TlsFinished));

    /* debug */
    printf( "Finished un encrypted [%lu]", sizeof(TlsFinished) );
    hexdump( v, sizeof(TlsFinished) );
    /* end debug */
    v = (BYTE*) rec + sizeof( TlsRecord );
    _res_ = tls_write( s, v, TLS_VFY_HS_LEN, TLS_RECORD_HANDSHAKE,
                                                           &e_l );
    W_STRUCT_VAR_TYPE( SHORT, rec->length, e_l );
    e_l += sizeof( TlsRecord );

    s->txlen = cc_l + e_l;
    /* debug */
    printf( "Finished [%d]", e_l);
    hexdump( s->app, s->txlen );
    /* end debug */

    sec_data->tls_state = TLS_FIN_SENT;
    return _res_;
}

RESULT tls_fin( yh_socket* s, SHORT pos )
{
    RESULT _res_ = tls_fin_rx( s, pos );
    if( _res_ != OK )
    {
        return _res_;
    }
    _res_ = tls_fin_tx( s );
    return _res_;
}

RESULT tls_handle_key_exchange( yh_socket* s )
{
    tls_record                                    rec;
    tls_handshake                                  th;
    BYTE*                                cur = s->app;
    SHORT                                     pos = 0;
    SHORT                           _res_ = ERR_STATE;
    yh_tls_data_p                            sec_data;

    sec_data = (yh_tls_data_p) s->opaque_sec_data;
    /* TODO: handle upper limit of message */
    while( pos < s->applen )
    {
        rec = (tls_record) cur;
        if( rec->content_type == TLS_RECORD_HANDSHAKE )
        {
            th = (tls_handshake) (cur + sizeof(TlsRecord) );
            if( th->msg_type        == THT_ClientKeyExchange && 
                sec_data->tls_state == TLS_SERVER_HELLO_DONE_SENT )
            {
                _res_ = tls_handle_client_key_exchange( s );
            }
            if( sec_data->tls_state == TLS_CHANGE_CIPHSPEC_RX )
            {
                /* debug */
                printf( "Processing fin\n" );
                hexdump( s->app + pos, s->applen - pos );
                /* end debug */
                _res_ = tls_fin( s, pos );
            }
        }
        /* change cipherspec is not a handshale message */
        if( rec->content_type == TLS_RECORD_CHANGE_CIPHSPEC )
        {
            if( sec_data->tls_state == TLS_CLI_KEYXCHG_OK )
            {
                sec_data->tls_state = TLS_CHANGE_CIPHSPEC_RX;
            }
        }
        pos += ( R_STRUCT_VAR_TYPE(SHORT, rec->length) +
                                    sizeof(TlsRecord) );
        cur = s->app + pos;
    }
    return _res_;
}

RESULT tls_rx( yh_socket* s )
{
    RESULT _res_              =                       0;
    yh_socket* sock          =           (yh_socket*) s;
    yh_tls_data_p sec_data   =                     NULL;

    if( sizeof( yh_tls_data ) > MAX_OPAQUE_SEC_DATA_SZ )
    {
        _res_ = TLS_SOCK_OPAQUE_SZ_TOO_SMALL;
        goto done;
    }
    sec_data = (yh_tls_data_p) s->opaque_sec_data;
    switch( sec_data->tls_state )
    {
        case TLS_STATE_INITIAL:
            _res_ = tls_handle_client_hello(s);
            break;
        case TLS_SERVER_HELLO_DONE_SENT:
            _res_ = tls_handle_key_exchange(s);
            break;
        default:
            break;
    }

done:
    if( _res_ != OK )
    {
        sec_data->tls_state = TLS_ERR;
    }
    if( sec_data->tls_state == TLS_ERR ||
        sec_data->tls_state == TLS_FIN_SENT )
    {
        yh_free( sec_data->h, sizeof( TlsHandshakeHash ) );
        sec_data->h = NULL;
    }
    return _res_;
}
