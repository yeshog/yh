#ifndef _TLS_HANDSHAKE_H
#define _TLS_HANDSHAKE_H

#include <net.h>
#include "sha1.h"
#include "md5.h"
#include "aes.h"
#include "ec-configured.h"

#define TLS_MIN ( sizeof(TlsRecord)                + \
              sizeof(TlsHandshake) )
/* may not be precise, but fairly close */
#define TLS_CLIENTHELLO_MIN_LEN ( TLS_MIN          + \
          sizeof(ClientHello) + 10 )
/* min 160r1 has 41 bytes */
#define TLS_MIN_CLIENT_KEY_XCHG_ECDH_LEN ( TLS_MIN + \
          sizeof( TlsClientKeyExchangeECDH )       - \
             sizeof( BYTE* ) +  41 )

/* Record layer */
#define   TLS_RECORD_CHANGE_CIPHSPEC                          20
#define   TLS_RECORD_ALERT                                    21
#define   TLS_RECORD_HANDSHAKE                                22
#define   TLS_RECORD_APPDATA                                  23

#define   TLS_ECDH_ECDSA_AES_128_CBC_SHA                  0xC004
#define   TLS_SUPPORTED_CIPHSUITE TLS_ECDH_ECDSA_AES_128_CBC_SHA
#define   TLS_SUPPORTED_MAJOR_VER                           0x03
#define   TLS_SUPPORTED_MINOR_VER                           0x01
#define   TLS_CLIENT_HELLO_MAX_SUITES                        200
#define   TLS_COMPRESSION_METHOD_NULL                          0
#define   TLS_EXT_SERVER_NAME                             0x0000
#define   TLS_EXT_ELLIPTIC_CURVES                         0x000A
#define   TLS_EXT_ELLIPTIC_POINT_FORMATS                  0x000B
#define   TLS_EXT_SESSION_TICKET                          0x0023
#define   TLS_HELLORND_LEN                                    32
#define   TLS_CURVEID_SZ                                       2

/* tls handshake types */
#define   THT_HelloRequest                                     0
#define   THT_ClientHello                                      1
#define   THT_ServerHello                                      2
#define   THT_Certificate                                     11
#define   THT_ServerKeyExchange                               12
#define   THT_ServerHelloDone                                 14
#define   THT_CertificateVerify                               15
#define   THT_ClientKeyExchange                               16
#define   THT_ChangeCipherSpec                                20
#define   THT_Finished                                        20

#define   TLS_MASTER_SECRET_LEN                               48
#define   TLS_HASH_MD5                                         0
#define   TLS_HASH_SHA1                                        1
#define   TLS_PRF_LABEL                          "master secret"
#define   TLS_FIN_CLIENT_LABEL                 "client finished"
#define   TLS_FIN_SRV_LABEL                    "server finished"
#define   TLS_FINVFY_SZ                                       48

typedef struct TlsRecord
{
    BYTE        content_type;
    BYTE version         [2];
    SHORT             length;
} TlsRecord, *tls_record;

typedef struct TlsHandshake
{
    BYTE                   msg_type;
    BYTE                       tlen;
    SHORT                    length;
} TlsHandshake, *tls_handshake;

typedef struct ClientHello
{
    BYTE version           [2];
    BYTE random           [32];
    BYTE session_id_len;
    BYTE* session_id;
    SHORT    cipher_suites_len;
    BYTE* cipher_suites;
    BYTE compression_methods_len;
    BYTE   compression_methods;
    BYTE* extensions;
}  ClientHello, *client_hello;

typedef struct TlsClientHelloExt
{
    SHORT type;
    SHORT len;
} TlsClientHelloExt,
 *tls_clienthello_ext;

typedef struct ServerHello
{
    BYTE version           [2];
    BYTE random           [32];
    BYTE session_id_len;
    SHORT    cipher_suite;
    BYTE   compression_method;
} ServerHello, *server_hello;

typedef struct TlsCertificates
{
    BYTE                        tlen;
    SHORT                     length;
} TlsCertificates, *tls_certificates;

typedef struct TlsCertificate
{
    BYTE                        tlen;
    SHORT                     length;
} TlsCertificate, *tls_certificate;

typedef struct TlsClientKeyExchangeECDH
{
    BYTE len;
} TlsClientKeyExchangeECDH,
  *tls_client_key_exchange_ecdh;

/*!
  \brief : TLS security parameters
*/
typedef struct tlsv1_sec_params
{
    BYTE client_write_MAC_secret[SHA1_LEN];
    BYTE server_write_MAC_secret[SHA1_LEN];
    BYTE client_write_key[CIPH_KEY_LEN];
    BYTE server_write_key[CIPH_KEY_LEN];
    BYTE client_write_IV[CIPH_BLOCK_SZ];
    BYTE server_write_IV[CIPH_BLOCK_SZ];
} tlsv1_sec_params;

typedef struct tls_hello_random
{
    BYTE  client_random[TLS_HELLORND_LEN];
    BYTE  server_random[TLS_HELLORND_LEN];
} tls_hello_random;

typedef struct TlsHandshakeHash
{
    sha1_ctx  sh;
    md5_ctx   md;
} TlsHandshakeHash, *tls_handshake_hash;
/*!
  \brief: struct to maintain tls state in yh_socket
          To yh_socket, this will appear as opaque
          bytes
  \note: size matters: 1 + 116 + 32 + 32 + 48 + 104
                       = 229 bytes
*/
typedef struct yhTlsData
{
    BYTE tls_state;
    SHORT cseq;
    SHORT sseq;
    BYTE  master_secret[TLS_MASTER_SECRET_LEN];
    union
    {
        tls_hello_random random;
        tlsv1_sec_params sparam;
    };
    tls_handshake_hash h;
} yh_tls_data, *yh_tls_data_p;

typedef struct TlsFinished
{
    BYTE verify_data[12];
} TlsFinished;

typedef enum tlsState
{
                   TLS_STATE_INITIAL,
          TLS_SERVER_HELLO_DONE_SENT,
                  TLS_CLI_KEYXCHG_OK,
              TLS_CHANGE_CIPHSPEC_RX,
                       TLS_FIN_RX_OK,
                        TLS_FIN_SENT,
                             TLS_ERR,
} tls_state;

#define TLS_VFY_LEN                                               \
    ( sizeof( TlsFinished ) + SHA1_LEN + sizeof( TlsHandshake ) )
#define TLS_VFY_HS_LEN                                            \
               ( sizeof( TlsFinished ) + sizeof( TlsHandshake ) )
#define TLS_CH_OFFSET( s ) (s->app + sizeof(TlsRecord))
#define TLS_CH_LEN( s ) (s->applen - sizeof(TlsRecord) )
#define TLS_WRITE_OVERHEAD                                        \
       (sizeof(TlsRecord) + SHA1_LEN + CIPH_BLOCK_SZ)

void hmac_md5(  BYTE**, SHORT*, BYTE, BYTE*, SHORT, BYTE* );
void hmac_sha1( BYTE**, SHORT*, BYTE, BYTE*, SHORT, BYTE* );
void tls_prf(   BYTE*,  SHORT,  BYTE*, SHORT, BYTE*, SHORT,
                BYTE*, SHORT );

/* debug */
#define u8 BYTE
#define MD5_MAC_LEN 16
#define SHA1_MAC_LEN 20
#define os_strlen strlen
#define os_memcpy memcpy
#define os_memset memset
int tls_prf_sha1_md5(const u8 *secret, size_t secret_len, const char *label,
		     const u8 *seed, size_t seed_len, u8 *out, size_t outlen);
/* end debug */

void tls_switch_random( BYTE* );

#endif
