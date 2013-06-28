/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/
#ifndef _YH_ASN_H_
#define _YH_ASN_H_

#include <common.h>
#include <sha1.h>
#include <ec-configured.h>

#define TL_LEN_BYTES                             2
#define X690_0207_CLASS_UNIVERSAL                0
#define X690_0207_CLASS_APPLICATION              1
#define X690_0207_CLASS_CTX_SPECIFIC             2
#define X690_0207_CLASS_PRIVATE                  3
#define X690_0207_MAX_TAG                        30
#define X690_0207_LEN_FORM_LONG                  1
#define X690_0207_LEN_FORM_SHORT                 0
#define X690_0207_TYPE_PRIMITIVE                 0
#define X690_0207_TYPE_CONSTRUCTED               1
#define X690_0207_TAG_NULL                       0
#define X690_0207_TYPE_NULL                      5
#define X690_0207_TAG_SEQUENCE                   16
#define X690_0207_TAG_SET                        17
#define X690_0207_TAG_VERSION                    0
#define X690_0207_TAG_BOOLEAN                    1
#define X690_0207_TAG_INTEGER                    2
#define X690_0207_TAG_BITSTRING                  3
#define X690_0207_TAG_OCTET_STRING               4
#define X690_0207_TAG_OID                        6
#define X690_0207_TAG_UTCTIME                    23
#define RFC_3279_ALG_RSA                         0
#define RFC_ALG_ECDSA                            1
#define MAX_EXTS                                 18
#define MAX_ERRORS                               8
/**
 * X.690-0207.pdf section 8.1.2
 */
typedef struct asn_t
{
    /*
     * look at #define X690_0207_CLASS above
     */
    BYTE asn_class;
    /* Primitive/Constructed */
    BYTE type;
    /* max 30 */
    BYTE tag;
} asn_t;

#define _asn_class( x ) ( (x) >> 6 )
#define _asn_type( x )  ( ( (x) >> 5 ) & 1 )
#define _asn_tag( x )   ( ( (x) & 0x1F ) )
#define _asn_len_form( x ) ( x >> 7 )
#define _asn_len( x ) ( x & 0x7F )

/*
 * if asn_len_form == 1 (aka long) then the following
 * octets determine payload length. If these octets are
 * > 2 meaning >0xFFFF >65K cert in value then
 * we cannot process such a payload
 */

#define _asn_len_calc( x ) (     \
  ( _asn_len_form(x) > 0 )?      \
      ( (_asn_len(x) > 2 )?      \
         ASN_TLV_TOO_BIG         \
      : _asn_len(x) )            \
  :                              \
         _asn_len(x) )

 /* b=buffer x = variable */
#define _asn_decl( b, x )                                \
    x##_type.asn_class =  _asn_class( b[0] );            \
    x##_type.type      =  _asn_type( b[0] );             \
    x##_type.tag       =  _asn_tag( b[0] );              \
    x##_len.form       =  _asn_len_form( b[1] );         \
    x##_len.len        =  _asn_len_calc( b[1] );         \
    x##_s.type         =  &x##_type;                     \
    x##_s.len          =  &x##_len;                      \
    x                  =  &x##_s

/*!
    \brief Create a ber_blob on the stack
    \arg identfier, callee does not declare this
    \arg buffer to create ber blob from
    \arg len of ber blob
*/
#define mk_berblob_from_buf( x, b, l )  \
        ber_blob x_;                    \
        memset( &x_, 0, sizeof( x_ ) ); \
        x_.buf = b;                     \
        x_.len = l;                     \
        ber_blob_p x = &x_

#define asn_result_init RESULT _res_ = 0

/*!
 * @brief: get current tlv and move to next
 */
#define asn_get_next( x )                  \
        _res_ = asn_next( x );             \
        if ( _res_ == X690_0207_NULL_TAG ) \
	    _res_ = asn_next( x );         \
        if( _res_ != OK )                  \
            return _res_

#define asn_check(x, y, z)                 \
        _res_ = asn_check_##x( y, z );     \
        if( _res_ != OK )                  \
            return _res_

#define asn_return_res return _res_

#define asn_next_tlv( x, b )                          \
        x->pos += x->payload_len;                     \
        x->cur_pos += x->payload_len;                 \
        if( x->pos > x->len )                         \
            return X690_0207_PAYLOAD_OVERFLOW_##b

#define asn_rewind_to( x, y )                   \
        x->cur_pos = y;                         \
        x->pos = ( x->cur_pos - x->buf );       \
        asn_get_next( x )


/**
 * \brief check if the expected class, type, tag found
 *        from cert match what is expected if not return
          the appropriate error indicated in error.h
 * e_b  = ber_blob_p
 * e_c  = expected class
 * e_t  = expected type
 * e_g  = expected tag
 * e_o  = ASN type in error.h ex.CERTVER
 */

#define asn_tlv_check( e_b, e_o, e_c, e_t, e_g )             \
    if( e_b->tlv->type->asn_class != X690_0207_CLASS_##e_c ) \
    {                                                        \
        return ASN_CERT_##e_o##_CLASS_ERR;                   \
    }                                                        \
    if( e_b->tlv->type->type != X690_0207_TYPE_##e_t )       \
    {                                                        \
        return ASN_CERT_##e_o##_TYPE_ERR;                    \
    }                                                        \
    if( e_b->tlv->type->tag != X690_0207_TAG_##e_g )         \
                                                             \
        return ASN_CERT_##e_o##_TAG_ERR

/**
 * \brief same as asn_tlv_check but resulting action is to
          stack the error and proceed with life after bitching
          about why cert generation is different even though
          the standard is the same
*/
#define asn_tlv_check_cont( e_b, e_e, e_o, e_c, e_t, e_g )   \
    if( e_b->tlv->type->asn_class != X690_0207_CLASS_##e_c ) \
    {                                                        \
        asn_stack_err( e_e, e_b->pos,                        \
                       X690_0207_CLASS_##e_c );              \
    }                                                        \
    if( e_b->tlv->type->type != X690_0207_TYPE_##e_t )       \
    {                                                        \
        asn_stack_err( e_e, e_b->pos,                        \
                       X690_0207_TYPE_##e_t );               \
    }                                                        \
    if( e_b->tlv->type->tag != X690_0207_TAG_##e_g )         \
    {                                                        \
        asn_stack_err( e_e, e_b->pos,                        \
                       X690_0207_TAG_##e_g );                \
    }


/**
 * \brief reduce ugliness of o->extensions[o->extnum]
*/
#define cur_ext(o) o->extensions[o->extnum]
/**
 * X.690-0207.pdf section 8.1.3
 */
typedef struct asn_l
{
    /*
     * definite/infinite
     * if encoding is primitive *always 1
     * 
     * if encoding is constructed
     *   and 
     * all data is available
     *   then
     *       definite form
     *       or
     *       indefinite form (upto sender)
     *
     * if encoding is constructed
     *     and
     * all data is not available
     *     then 
     *     indefinite 
     */
    BYTE form;
    /*
     * max 127 if form is definite,short
     * arbitrary if form is definite,long
     *    length octets indicated by len. The actual payload 
     *    length in the tlv is in the following len octets.
     * asn_l single octet form is indefinite marked by
     *    end of contents octet in that case
     *    asn_l = 1 0000000
     */
    SHORT len;
} asn_l;

typedef struct asn_tl
{
    asn_t* type;
    asn_l* len;
} asn_tl, *asn_tl_p;

/*! \brief struct holding the parsing types of a BER blob
 *  \note Do not change variable names tlv_type, tlv_len, tlv_s
 *        and tlv since macros depend on these names
 */
typedef struct ber_blob
{
    BYTE* buf;
    SHORT len;
    SHORT pos;
    BYTE* begin;
    BYTE* cur_pos;
    SHORT payload_len;
    asn_t tlv_type;    /*< save the currently parsed type here */
    asn_l tlv_len;     /*< save the currently parsed len  here */
    asn_tl tlv_s;
    asn_tl_p tlv;
} ber_blob, *ber_blob_p;

typedef struct extension
{
    SHORT indx;
    BYTE* extnOid;
    SHORT extnOid_len;
    BYTE* critical;
    SHORT critical_len;
    BYTE* extnValue;
    SHORT extnValue_len;
} extension, *ext;

typedef struct sig_alg
{
    BYTE indx;
    SHORT len;
    BYTE* oid;
    SHORT oid_len;
    BYTE* param;
    BYTE param_len;
} sig_alg, *sig_alg_p;

typedef struct asn_err
{
    SHORT offset;
    SHORT err;
} asn_err;

/*!
 * \brief: wrapper to stack errors max 8
 * \param 1: o ber_blob_p
 * \param 2: error 1
 */
#define asn_stack_err( o, a, b )                   \
    o->asn_parse_errs[o->asn_err_num].offset  = a; \
    o->asn_parse_errs[o->asn_err_num].err     = b; \
    o->asn_err_num++;                              \
    if( o->asn_err_num >= MAX_ERRORS )             \
        return ASN_CERT_TOO_MANY_ERRORS
    
/*! \brief: RFC 3280 page 14 */
typedef struct _Certificate
{
    SHORT certificate_len;

    BYTE* tbsCertificate;
    SHORT tbsCertificate_len;

    sig_alg signatureAlg;

    BYTE* signatureValue;
    SHORT signatureValue_len;

    /* tbsCertificate */
    BYTE* version;
    SHORT version_len;

    BYTE* serialNumber;
    SHORT serialNumber_len;

    sig_alg caSigAlg;

    BYTE* issuer;
    SHORT issuer_len;

    BYTE* validityNotBefore;
    SHORT validityNotBefore_len;

    BYTE* subject;
    SHORT subject_len;

    BYTE* publicKeyInfo;
    SHORT publicKeyInfo_len;

    BYTE* issuerUniqueID;
    SHORT issuerUniqueID_len;

    BYTE* subjectUniqueID;
    SHORT subjectUniqueID_len;

    /* Validity */
    BYTE* validNotBefore;
    SHORT validNotBefore_len; 

    BYTE* validNotAfter;
    SHORT validNotAfter_len;

    /* SubjectPublicKeyInfo */
    BYTE* subjectPublicKeyInfoAlg;
    SHORT subjectPublicKeyInfoAlg_len;

    /* pubKeyAlg is internal */
    BYTE  pubKeyAlg;
    BYTE* pubKeyAlgId;
    BYTE  pubKeyAlgId_len;

    /* pubKeyAlg param */
    BYTE* pubkAlgParam;
    BYTE pubKeyAlgParam_len;

    BYTE* publicKey;
    SHORT publicKey_len;

    /* The actual value */
    BYTE* publicKeyVal;
    SHORT publicKeyVal_len;

    /* params ex. exponent */
    BYTE* publicKeyParam1_val;
    SHORT publicKeyParam1Val_len;

    /* extentions
	 * cat rfc5280.txt|grep 'extension OID and syntax'|wc -l
	 * there are about 18 listed so allocate them here
	 * space requirement max (size_t)*7*18 = ~approx 600
	 * bytes
	 * */
    BYTE extnum;
    BYTE* extns;
    SHORT extns_len;
    extension extensions[MAX_EXTS];

    asn_err asn_parse_errs[MAX_ERRORS];
    BYTE asn_err_num;
} Certificate, *Cert;

/*
     Dss-Sig-Value  ::=  SEQUENCE  {
              r       INTEGER,
              s       INTEGER  }
*/
typedef struct Dss_Sig_Value {
    Cert     c;
    BYTE*    r;
    BYTE r_len;
    BYTE*    s;
    BYTE s_len;
} dss_sig, *dss_sig_p;

RESULT asn_next( ber_blob_p );
RESULT parse_cert(BYTE* , SHORT , Cert);

RESULT asn_check_certificate   ( ber_blob_p, Cert );
RESULT asn_check_tbscertificate( ber_blob_p, Cert );
RESULT asn_check_version       ( ber_blob_p, Cert );
RESULT asn_check_serialnum     ( ber_blob_p ,Cert );
RESULT asn_check_validity      ( ber_blob_p, Cert );
RESULT asn_check_subject       ( ber_blob_p ,Cert );
RESULT asn_check_pubk          ( ber_blob_p, Cert );
RESULT set_pubk_alg_info       ( ber_blob_p, Cert );
RESULT set_rsa_pubk_info       ( ber_blob_p, Cert );
RESULT set_ecdsa_pubk_info     ( ber_blob_p, Cert );
RESULT asn_check_ext           ( ber_blob_p, Cert );
RESULT asn_handle_ext_oid      ( ber_blob_p, Cert );
RESULT asn_check_ext           ( ber_blob_p, Cert );
RESULT asn_handle_ext_val      ( ber_blob_p, Cert );
RESULT asn_check_sig_alg       ( ber_blob_p, Cert );
RESULT asn_check_sig           ( ber_blob_p, Cert );
RESULT asn_check_verify_sig    ( Cert );

#endif
