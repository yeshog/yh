#include "tls_handshake.h"
static char TLS_MSECRET_LABEL[] ONFLASH = "master secret";
static char TLS_KEY_EXP_LABEL[] ONFLASH = "key expansion";
/* yh config certificate */
const BYTE yh_servcert[] ONFLASH =
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
const BYTE yh_servkey[] ONFLASH =
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
    RESULT    _res_ = ERR_STATE;
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
    sec_data->h = yh_calloc( 1, sizeof( TlsHandshakeHash ) );
    if( !sec_data->h )
    {
        return TLS_CLIENTHELLO_HASH_NOMEM;
    }
    sha1_init( &sec_data->h->sh );
    md5_init(  &sec_data->h->md );
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
    yh_memcpy(  (BYTE*) cert + sizeof(TlsCertificate),
                           yh_servcert, sizeof(yh_servcert));
    c_l = sizeof(yh_servcert);
    W_STRUCT_VAR_TYPE( SHORT, cert->length,  c_l );
    c_l += sizeof( TlsCertificate );
    W_STRUCT_VAR_TYPE( SHORT, certs->length, c_l );
    c_l += sizeof( TlsCertificates );
    W_STRUCT_VAR_TYPE( SHORT, th->length,    c_l );
    c_l += sizeof( TlsHandshake );
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
    _res_ = s->resize_cb( s, TLS_MAX_REC_SZ );
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
    makeInt( &d, (BYTE*) yh_servkey, sizeof( yh_servkey ), NO );
    /* Calculate d*Qc where Qc is the public key of
     * the client.
     * First we initialize the sizes so memory is allocated
     */
    ec = &ecv;
    memset( ec, 0, sizeof(ecv) );
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
    /* d(sG), where d is our pvk, s is the peer's
       pvk and G is the common point */
    _res_ = ec_scalar_mul( ec, &d );
    if( _res_ != OK )
    {
        printf( "ECDH Failed with error [%X]\n", (SHORT) _res_ );
        return TLS_ECDH_FAILED;
    }
    tls_prf(ec->X->buf + ( ec->X->size - ec_get_xlen() ),
               ec_get_xlen(), (BYTE*)  TLS_MSECRET_LABEL,
                               strlen(TLS_MSECRET_LABEL),
                          sec_data->random.client_random,
                                 (TLS_HELLORND_LEN << 1),
                                 sec_data->master_secret,
                                 TLS_MASTER_SECRET_LEN );
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
    sec_data->tls_state = TLS_CLI_KEYXCHG_OK;
    _res_ = OK;
done:
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
    /* copy sha1 and md5 ctx from the clients perspective
       into a different ctx so we can verify later */
    memcpy( &cli_sha_ctx, &sec_data->h->sh, sizeof( sha1_ctx ) );
    memcpy( &cli_md5_ctx, &sec_data->h->md, sizeof( md5_ctx  ) );
    memcpy( sec_data->civ, s->app + (s->applen - CIPH_BLOCK_SZ) ,
                                                CIPH_BLOCK_SZ );
    /* update our hash before we muck with the data via
       'in place' decryption */
    l = R_STRUCT_VAR_TYPE( SHORT, rec->length );
    /* decrypt the client FIN */
    l = R_STRUCT_VAR_TYPE( SHORT, rec->length );
    l = aes_cbc_decrypt( sec_data->sparam.client_write_IV,
                        sec_data->sparam.client_write_key,
                                                 enc, l );
    memcpy( sec_data->sparam.client_write_IV, sec_data->civ,
    		CIPH_BLOCK_SZ );
    /*
     * enc now has finished handshake of l = 12 + 4 + 20 = 36
     * bytes. If not talk to the hand
     */
    if( l != TLS_VFY_LEN )
    {
        return TLS_FIN_DECRYPT_FAILED;
    }
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
    /* judgement day, point enc to the right offset.
       At this point enc points to decrypted data and
       its contents are a TlsHandshake with 12 bytes
       of verify_data */
    if( memcmp( enc + sizeof( TlsHandshake ), verify_data,
                                 sizeof( verify_data ) ) )
    {
        return TLS_VERIFY_DATA_FAILED;
    }
    /* digest handshake only for S -> C */
    sha1_update( &sec_data->h->sh, enc, TLS_VFY_HS_LEN );
    md5_update(  &sec_data->h->md, enc, TLS_VFY_HS_LEN );
    sec_data->tls_state = TLS_FIN_RX_OK;
    /* increment client sequence number for next expected
     * rx data
     */
    sec_data->cseq += 1;
    return OK;
}
/*!
 * \brief write tls record data (not header)
 * \param [INOUT] yh_socket*
 * \param [INOUT] Beginning of record (pointer) to be sent via tls.
 *                Record data IS overwritten with encrypted data.
 *                So most of the things are done in place.
 * \param [IN]    data length. This is ONLY the data length and
 *                excludes sizeof(TlsRecord)
 * \param [IN]    content type
 * \param [OUT]   size of written data
 */
RESULT tls_write( yh_socket* s, BYTE* r, SHORT len,
		                 BYTE type, SHORT* outlen )
{
    SSHORT w_l                            = 0;
    tls_record rec           = (tls_record) r;
    BYTE* data        = r + sizeof(TlsRecord);
    yh_tls_data_p                    sec_data;
    BYTE                             *text[5];
    SHORT                         text_len[5];
    BYTE sseq[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    BYTE  ver[2]             = { 0x03, 0x01 };
    /* Now say incoming packet was of len 74, 2 records
     * 37 bytes each. Now this is the second tls_write
     * after the first one (response) is 37 bytes. We
     * get len 34 type appdata, so now make sure we have
     * 74 - (42 - 0) - (20 + 16) = -4 aka (no can do)
     */
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
    /* write hmac @ data + len */
    hmac_sha1( text, text_len, 5,
               sec_data->sparam.server_write_MAC_secret,
               SHA1_LEN, data + len );
    /* encrypt data and hmac */
    w_l = len + SHA1_LEN;
    w_l = aes_cbc_encrypt(sec_data->sparam.server_write_IV,
                         sec_data->sparam.server_write_key,
                                      data, w_l, data, 0 );
    /* update record header and length */
    W_STRUCT_VAR_TYPE( SHORT, rec->length, w_l );
    *outlen = w_l + sizeof(TlsRecord);
    /* increment srv sequence number for next expected
     * rx data
     */
    sec_data->sseq += 1;
    /* update the IV for the next record */
    memcpy( sec_data->sparam.server_write_IV,
              data + ( w_l - CIPH_BLOCK_SZ ),
                             CIPH_BLOCK_SZ );
    return OK;
}

/*!
 * \brief read a tls record
 * \param [INOUT] yh_socket*
 */
RESULT tls_read( yh_socket* s )
{
    tls_record                                     rec;
    SHORT                                        l = 0;
    BYTE*                                 enc = s->app;
    SSHORT                             s_l = s->applen;
    SHORT                                        i = 0;
    RESULT                           _res_ = ERR_STATE;
    BYTE                                   h[SHA1_LEN];
    yh_tls_data_p                      sec_data = NULL;
    BYTE                           *text[MAX_TLS_RECS];
    SHORT                       text_len[MAX_TLS_RECS];
    SHORT                                  text_ct = 0;
    BYTE cseq[8]          = { 0, 0, 0, 0, 0, 0, 0, 0 };
    BYTE  ver[2]                      = { 0x03, 0x01 };
    s->txlen                                       = 0;
    while( s_l > 0 )
    {
        sec_data = (yh_tls_data_p) s->opaque_sec_data;
        rec      = (tls_record) enc;
        if( !( (rec->content_type == TLS_RECORD_APPDATA) ||
               (rec->content_type == TLS_RECORD_ALERT) ) )
        {
            return TLS_EXPECTED_APP_OR_ALERT;
        }
        enc = enc + sizeof(TlsRecord);
        l = R_STRUCT_VAR_TYPE( SHORT, rec->length );
        if( l > MAX_TLS_APP_DATA )
        {
            return TLS_READ_RECORD_TOO_BIG;
        }
        memcpy( sec_data->civ, enc + (l - CIPH_BLOCK_SZ),
                CIPH_BLOCK_SZ );
        i = aes_cbc_decrypt( sec_data->sparam.client_write_IV,
                             sec_data->sparam.client_write_key,
                             enc, l );
        memcpy(sec_data->sparam.client_write_IV, sec_data->civ,
                CIPH_BLOCK_SZ );
        /* debug */
        printf( "Tls Read Data ");
        hexdump( enc, l);
        /* end debug */
        if( (i - SHA1_LEN) < 0 )
        {
            return TLS_DECRYPT_LEN_LT_ZERO;
        }
        l = i - SHA1_LEN;
        /* i holds length of [ data|hmac ] */
        /*
         * TLS MAC (sha1) = HMAC_SHA1( mac write secret, seq_num +
         *                          handshake type + tls version +
         *                                     datalen + content )
         */
        sec_data = (yh_tls_data_p) s->opaque_sec_data;
        W_SHORT( cseq, (sizeof(cseq) - sizeof(SHORT) ),
                                      sec_data->cseq );
        i = REVS( l );
        text[0]     =               cseq;
        text_len[0] =       sizeof(cseq);
        text[1]     = &rec->content_type;
        text_len[1] =                  1;
        text[2]     =                ver;
        text_len[2] =                  2;
        text[3]     =         (BYTE*) &i;
        text_len[3] =                  2;
        text[4]     =                enc;
        text_len[4] =                  l;

        hmac_sha1( text, text_len, 5,
                  sec_data->sparam.client_write_MAC_secret,
                  SHA1_LEN, h );
        if( memcmp( enc + l, h, SHA1_LEN ) != 0 )
        {
            printf( "HMAC -- do it correctly\n");
            //return TLS_HMAC_CHECK_FAIL;
        }
        if( l > 0 )
        {
            text[text_ct] = enc;
            text_len[text_ct] = l;
            text_ct++;
            if( text_ct >= MAX_TLS_RECS )
            {
                return TLS_MAX_RECS_EXCEEDED;
            }
        }
        enc = (BYTE*) rec;
        i = ( R_STRUCT_VAR_TYPE( SHORT, rec->length ) +
               sizeof( TlsRecord) );
        enc += i;
        s_l -= i;
        sec_data->cseq += 1;
    } /* end while num records */
    /* We now possess fragments of text.
     * Aggregate them and send kick them
     * to app layer
     */
    rec = (tls_record) s->app;
    enc = s->app + sizeof(TlsRecord);
    l = 0;
    for( i = 0; i < text_ct; i++ )
    {
        memmove( enc, text[i], text_len[i]);
        enc = enc + text_len[i];
        l += text_len[i];
    }
    /* reset all other bytes to 0 since we have all
     * the text we need
     */
    text_ct = 0;
    i = 0;
    memset( enc, 0, s->applen - ( l + sizeof(TlsRecord)) );
    enc = enc - l;
    _res_ = http_process( &enc, l, &enc, &i, &text_ct );
    if( _res_ != OK )
    {
        return _res_;
    }
    /* we need more data */
    if( text_ct > 0 )
    {
        sec_data->tls_state = TLS_NEED_MORE_CLI_DATA;
        return OK;
    }
    if( i > 0 )
    {
        /* app has everything it needs and it responded,
         * send the response to the client
         */
        _res_ = tls_write( s, (BYTE*) rec, i,
                    TLS_RECORD_APPDATA, &l );
        if( _res_ == OK )
        {
            s->txlen = l;
        }
    }
    return _res_;
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
    v = (BYTE*) rec;
    _res_ = tls_write( s, v, TLS_VFY_HS_LEN, TLS_RECORD_HANDSHAKE,
                                                           &e_l );
    s->txlen = cc_l + e_l;
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

RESULT tls_free_sec_data( yh_socket* s )
{
    yh_tls_data_p sec_data = (yh_tls_data_p) s->opaque_sec_data;
    return yh_free( sec_data->h, sizeof( TlsHandshakeHash ) );
}

RESULT tls_rx( yh_socket* s )
{
    printf( "tls_rx\r\n" );
    RESULT _res_              =                       0;
    yh_tls_data_p sec_data   =                     NULL;
    if( sizeof( yh_tls_data ) > MAX_OPAQUE_SEC_DATA_SZ )
    {
        _res_ = TLS_SOCK_OPAQUE_SZ_TOO_SMALL;
        goto done;
    }
    sec_data = (yh_tls_data_p) s->opaque_sec_data;
    /* debug */
    printf("Tls Rx state [%d] ", sec_data->tls_state );
    /* end debug */
    switch( sec_data->tls_state )
    {
        case TLS_STATE_INITIAL:
            _res_ = tls_handle_client_hello(s);
            break;
        case TLS_SERVER_HELLO_DONE_SENT:
        case TLS_CLI_KEYXCHG_OK:
            /* debug */
            /* end debug */
            /* usually they are a part of the same segment
               but if not handler is the same even though
               it is called tls_handle_key_exchange */
            _res_ = tls_handle_key_exchange(s);
            break;
        case TLS_FIN_SENT:
            /* now we have real app data */
            _res_ = tls_read( s );
            if( _res_ != OK )
            {
                sec_data->tls_state = TLS_APP_DATA_CLOSE;
            }
            break;
        default:
            /* debug */
            printf("Tls Rx state [%d] no match", sec_data->tls_state );
            /* end debug */
            break;
    }
done:
    if( _res_ != OK )
    {
        sec_data->tls_state = TLS_ERR;
    }
    if( sec_data->tls_state == TLS_ERR ||
        sec_data->tls_state == TLS_APP_DATA_CLOSE )
    {
        yh_free( sec_data->h, sizeof( TlsHandshakeHash ) );
        sec_data->h = NULL;
    }
    return _res_;
}
