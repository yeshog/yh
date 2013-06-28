/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/
#include "asn.h"
#include "asn_private_data.h"
/*!
    \brief: get the next value of an asn tlv
            and place its output in "ber" specified in param 1
    \param 1: [inout] ber_blob_p pointer allocated by callee
    \return error if any
*/
RESULT asn_next( ber_blob_p ber )
{
    SHORT p = ber->pos;
    BYTE* b = ber->buf;
    RESULT r = OK;
    /* save last position */
    ber->begin = ber->cur_pos;
    if( p + 1 > ber->len )
    {
        r = X690_0207_OVERFLOW;
        goto done;
    }
    _asn_decl( (b + p), ber->tlv );
    if( ber->tlv->type->asn_class == 0 &&
        ber->tlv->type->type      == 0 &&
        ber->tlv->type->tag       == 0 )
    {
        /*
         * now one may ask why the f**k this code
         * well there are weirdos sending random
         * null tag w/o the type 0x05 for no apparent
         *  reason.Slap them hard and move on.
         */
        ber->pos++;
        ber->cur_pos++;
        r = X690_0207_NULL_TAG;
        goto done;
    }
    switch( ber->tlv->len->form )
    {
        case X690_0207_LEN_FORM_LONG:
            if( ber->tlv->len->len > 2 )
            {
                r = X690_0207_LEN_OCTETS_TOO_MANY;
                goto done;
            }
            if(ber->tlv->len->len == 0)
            {
                r = X690_0207_LEN_OCTETS_INDEFINITE;
                goto done;
            }
            /* if the next 2 bytes are not available */
            if( p + ber->tlv->len->len > ber->len )
            {
                r = X690_0207_PAYLOAD_OVERFLOW;
                goto done;
            }
            /* t and l */
            p += 2;
            ber->payload_len = (ber->tlv->len->len == 1)?
                               b[p] : R_SHORT( b, p);
            /* len octets */
            p += ber->tlv->len->len;
            break;
        case X690_0207_LEN_FORM_SHORT:
            p += 2;
            ber->payload_len = ber->tlv->len->len;
            break;
        default:
            r = X690_0207_NOREACH;
            goto done;
    }
    ber->pos = p;
    ber->cur_pos = ber->buf + ber->pos;
done:
    return r;
}
RESULT asn_check_certificate( ber_blob_p cert, Cert out )
{
     /*
     * Certificate  ::=  SEQUENCE  {
     * tbsCertificate       TBSCertificate,
     * signatureAlgorithm   AlgorithmIdentifier,
     * signatureValue       BIT STRING  } 
     */
    out->asn_err_num = 0;
    asn_result_init;
    asn_get_next(cert);
    /* 
     * the 12 lines following this comment are are equivalent
     * to the macro:
     * 
     * asn_tlv_check( cert, CERT, UNIVERSAL, 
     *                CONSTRUCTED, SEQUENCE )
     * 
     * they are kept only to demo what the macro does
     */
    if( cert->tlv->type->asn_class != X690_0207_CLASS_UNIVERSAL)
    {
        return ASN_CERT_CLASS_ERR;
    }
    if( cert->tlv->type->type != X690_0207_TYPE_CONSTRUCTED)
    {
        return ASN_CERT_TYPE_ERR;
    }
    if( cert->tlv->type->tag != X690_0207_TAG_SEQUENCE)
    {
        return ASN_CERT_TAG_ERR;
    }
    out->certificate_len = cert->payload_len;
    return OK;
}
RESULT asn_check_tbscertificate( ber_blob_p cert, Cert out )
{
    /* 
     * TBSCertificate  ::=  SEQUENCE  {
     * version         [0]  EXPLICIT Version DEFAULT v1,
     * serialNumber         CertificateSerialNumber
     * signature            AlgorithmIdentifier,
     * issuer               Name,
     * validity             Validity,
     * subject              Name,
     * subjectPublicKeyInfo SubjectPublicKeyInfo,
     * issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                -- If present, version shall be v2 or v3
     * subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                -- If present, version shall be v2 or v3
     * extensions      [3]  EXPLICIT Extensions OPTIONAL
     *                -- If present, version shall be v3
     *}
     */
    asn_result_init;
    out->tbsCertificate = cert->cur_pos;
    asn_get_next(cert);
    asn_tlv_check( cert, TBSCERT, UNIVERSAL,
                        CONSTRUCTED, SEQUENCE );
    out->tbsCertificate_len = cert->payload_len +
            (cert->cur_pos - out->tbsCertificate);
    return OK;
}
RESULT asn_check_version( ber_blob_p cert, Cert out )
{
    /* 
     * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     * version tag is 0 and has an enclosed Integer 
     */
    asn_result_init;
    asn_get_next(cert);
    asn_tlv_check( cert, VER, CTX_SPECIFIC,
                    CONSTRUCTED, VERSION );
    asn_get_next(cert);
    asn_tlv_check( cert, VER_I, UNIVERSAL,
                      PRIMITIVE, INTEGER );
    out->version = cert->cur_pos;
    out->version_len = cert->payload_len;
    asn_next_tlv( cert, VERSION );
    return OK;
}
RESULT asn_check_serialnum( ber_blob_p cert, Cert out )
{
    /* CertificateSerialNumber  ::=  INTEGER */
    asn_result_init;
    asn_get_next(cert);
    asn_tlv_check( cert, SER, UNIVERSAL, PRIMITIVE, INTEGER );
    out->serialNumber = cert->buf + cert->pos;
    out->serialNumber_len = cert->payload_len;
    /* now is the *only* time to take a dump my friend */
    asn_next_tlv( cert, SERIALNUM );
    return OK;
}
RESULT asn_sig_alg( ber_blob_p cert, Cert out, sig_alg_p sa )
{
   /*
    * AlgorithmIdentifier  ::=  SEQUENCE  {
    *   algorithm               OBJECT IDENTIFIER,
    *   parameters              ANY DEFINED BY algorithm OPTIONAL}
    */
    asn_result_init;
    asn_get_next(cert);
    sa->len = cert->payload_len;
    sa->param_len = 0;
    /* move over the sequece first */
    asn_tlv_check_cont( cert, out, SIGALG, UNIVERSAL,
                             CONSTRUCTED, SEQUENCE );
    /* now the oid */
    asn_get_next(cert);
    asn_tlv_check( cert, SIGALG_OID,
                   UNIVERSAL, PRIMITIVE, OID );
    sa->oid = cert->buf + cert->pos;
    sa->oid_len = cert->payload_len;
    sa->param_len = sa->len - cert->payload_len - TL_LEN_BYTES;
    sa->indx = BYTE_FF;
    /* check if supported algorithms */
    SHORT j = 0;
    BYTE supported = NO;
    for( ; j < sizeof(algs) / sizeof (BYTE*); j++ )
    {
        if( memcmp( (void*) algs[j],
                    (void*) cert->cur_pos,
                    cert->payload_len ) == 0 )
        {
            supported = YES;
            sa->indx = j;
            break;
        }
    }
    if( supported == NO )
    {
        return ASN_CERT_SIGALG_NOT_SUPPORTED;
    }
    /* advance to next */
    asn_next_tlv( cert, SIGALG );
    /* 
     * algorithm parameters
     */
    if( sa->param_len > 0 )
    {
        asn_get_next(cert);
        asn_next_tlv( cert, SIGALGP );
    }
    return OK;
}
RESULT asn_check_ca_sig_alg_id( ber_blob_p cert, Cert out )
{
    return asn_sig_alg(cert, out, &out->caSigAlg );
}
RESULT asn_check_issuer( ber_blob_p cert, Cert out )
{
    asn_result_init;
    asn_get_next(cert);
    /*
     * issuer ::= Name
     * Name ::= CHOICE { RDNSequence }
     * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
     * RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
     * AttributeTypeAndValue ::= SEQUENCE {
     *           type     AttributeType,
     *           value    AttributeValue }
     * AttributeType ::= OBJECT IDENTIFIER
     * AttributeValue ::= ANY DEFINED BY AttributeType
     */
    asn_tlv_check( cert, ISSUER, UNIVERSAL,
                   CONSTRUCTED, SEQUENCE );
    /* issuer we are free to parse thee later */
    out->issuer = cert->buf + cert->pos;
    out->issuer_len = cert->payload_len;
    asn_next_tlv( cert,  ISSUER);
    return OK;
}
RESULT asn_check_validity( ber_blob_p cert, Cert out )
{
    asn_result_init;
    /*
     * Validity ::= SEQUENCE {
     * notBefore      Time,
     * notAfter       Time }
     */
    /* SEQUENCE */
    asn_get_next(cert);
    asn_tlv_check( cert, VALID, UNIVERSAL,
                      CONSTRUCTED, SEQUENCE);
    /* valid from notBefore*/
    asn_get_next(cert);
    asn_tlv_check( cert, VALIDFRM, UNIVERSAL,
                        PRIMITIVE, UTCTIME );
    out->validityNotBefore = cert->buf + cert->pos;
    out->validityNotBefore_len = cert->payload_len;
    asn_next_tlv( cert,  VALIDFRM );
    /* end valid from notBefore */
    /* valid to notAfter */
    asn_get_next(cert);
    asn_tlv_check( cert, VALIDTO, UNIVERSAL,
                        PRIMITIVE, UTCTIME );
    out->validNotAfter = cert->buf + cert->pos;
    out->validNotAfter_len = cert->payload_len;
    asn_next_tlv( cert,  VALIDFRM );
    /* end valid to notAfter */
    return OK;
}
RESULT asn_check_subject( ber_blob_p cert, Cert out )
{
    asn_result_init;
    asn_get_next(cert);
    /*
     * subject ::= Name
     * Name ::= CHOICE { RDNSequence }
     * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
     * RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
     * AttributeTypeAndValue ::= SEQUENCE {
     *           type     AttributeType,
     *           value    AttributeValue }
     * AttributeType ::= OBJECT IDENTIFIER
     * AttributeValue ::= ANY DEFINED BY AttributeType
     */
    asn_tlv_check( cert, SUBJECT, UNIVERSAL,
                    CONSTRUCTED, SEQUENCE );
    /* subject we are free to parse thee later */
    out->subject = cert->buf + cert->pos;
    out->subject_len = cert->payload_len;
    asn_next_tlv( cert,  SUBJECT );
    return OK;
}
RESULT asn_check_pubk( ber_blob_p cert, Cert out )
{
   /*
    * SubjectPublicKeyInfo  ::=  SEQUENCE  {
    * algorithm            AlgorithmIdentifier,
    * subjectPublicKey     BIT STRING  } 
    * 
    * AlgorithmIdentifier  ::=  SEQUENCE  {
    *   algorithm               OBJECT IDENTIFIER,
    *   parameters              ANY DEFINED BY algorithm OPTIONAL}
    */
    asn_result_init;
    asn_get_next(cert);
    /* move over  SubjectPublicKeyInfo sequence */
    asn_tlv_check( cert, PUBK, UNIVERSAL,
                 CONSTRUCTED, SEQUENCE );
    /* alg */
    asn_get_next(cert);
    out->pubKeyAlgId_len = cert->payload_len;
    asn_tlv_check( cert, PUBKALG, UNIVERSAL,
                    CONSTRUCTED, SEQUENCE );
    /* oid */
    asn_get_next(cert);
    out->pubKeyAlgId = cert->cur_pos;
    asn_tlv_check( cert, PUBKALG_OID,
               UNIVERSAL, PRIMITIVE, OID );
    return set_pubk_alg_info( cert, out );
}
/*!
    \brief: check if public key algo is
            supported and if so save the key
    \param 1: [in] ber_blob_p, cert which is a cursor
                   over asn tlvs in the ber blob
    \param 2: [out] Cert, struct in which cert values are saved
    \note     assumes that cert->pos is correctly
              past AlgorithmIdentifier at oid
*/
RESULT set_pubk_alg_info( ber_blob_p cert, Cert out )
{
    asn_result_init;
    SHORT alg_param_len = 0;
    out->subjectPublicKeyInfoAlg = cert->buf + cert->pos;
    out->subjectPublicKeyInfoAlg_len = cert->payload_len;
    alg_param_len = out->pubKeyAlgId_len - cert->payload_len
                   - TL_LEN_BYTES;
    /* check if supported algorithms */
    SHORT j = 0;
    BYTE supported = NO;
    for( ; j < SUPPORTED_PUBK_ALGS; j++ )
    {
        if( memcmp( (void*) pubk_algs[j],
                    (void*) out->subjectPublicKeyInfoAlg,
                    out->subjectPublicKeyInfoAlg_len ) == 0 )
        {
            supported = YES;
            out->pubKeyAlg = j;
            break;
        }
    }
    if( supported == NO )
    {
        return ASN_CERT_PUBKALG_NOT_SUPPORTED;
    }
    asn_next_tlv( cert, PUBKALG );
    /* 
     * do not forget algorithm parameters
     */
    if( alg_param_len > 0 )
    {
        asn_get_next(cert);
        out->pubkAlgParam = cert->cur_pos;
        out->pubKeyAlgParam_len = alg_param_len;
        if( cert->payload_len )
        {
            out->pubkAlgParam = cert->cur_pos;
            out->pubKeyAlgParam_len = cert->payload_len;
        }
        asn_next_tlv( cert, PUBKALGP );
    }
    /* public key */
    asn_get_next(cert);
    out->publicKey = cert->cur_pos;
    out->publicKey_len = cert->payload_len;
    asn_tlv_check( cert, PUBK_VAL, UNIVERSAL,
                      PRIMITIVE, BITSTRING );
    switch( out->pubKeyAlg )
    {
      case RFC_3279_ALG_RSA:
          return set_rsa_pubk_info( cert, out );
      case RFC_ALG_ECDSA:
          return set_ecdsa_pubk_info( cert, out );
      default:
          return ASN_CERT_PUBKALG_NOT_SUPPORTED;
    }
    /* should never hit this */
    return OK;
}
/*!
    \brief: save the rsa public key
    \param 1: [in] ber_blob_p, cert which is a cursor
                   over asn tlvs in the ber blob
    \param 2: [out] Cert, struct in which cert values are saved
    \note     assumes that cert->pos is correctly
              at subjectPublicKey
*/
RESULT set_rsa_pubk_info( ber_blob_p cert, Cert out )
{
    asn_result_init;
    /*
     * rfc3279
     * RSAPublicKey ::= SEQUENCE {
     * modulus            INTEGER,    -- n
     * publicExponent     INTEGER  }  -- e
     */
    asn_get_next(cert);
    asn_tlv_check(cert, PUBK_PKEY, UNIVERSAL,
                     CONSTRUCTED, SEQUENCE );
    asn_get_next(cert);
    asn_tlv_check(cert, PUBK_RSAINTVAL,
             UNIVERSAL, PRIMITIVE, INTEGER );
    out->publicKeyVal = cert->cur_pos;
    out->publicKeyVal_len = cert->payload_len;
    asn_next_tlv( cert, RSAINTPUBKVAL );
    asn_get_next(cert);
    asn_tlv_check( cert, PUBK_RSAEXPVAL,
                UNIVERSAL, PRIMITIVE, INTEGER );
    out->publicKeyParam1_val = cert->cur_pos;
    out->publicKeyParam1Val_len = cert->payload_len;
    asn_next_tlv( cert,  RSAEXPVAL );
    return OK;
}
RESULT check_ecdsa_namedcurve_supported( Cert out )
{
    if( out->pubKeyAlgParam_len !=  ec_get_oidlen() )
        return ASN_CERT_PUBKALG_ECDSA_CURVE_SZ_ERROR;
    if( yh_memcmp( out->pubkAlgParam, ec_get_oid(),
                             ec_get_oidlen() ) == 0 )
    {
            return OK;
    }
    return ASN_CERT_PUBKALG_ECDSA_CURVE_UNSUPORTED;
}
/*!
    \brief: save the ecdsa public key
    \param 1: [in] ber_blob_p, cert which is a cursor
                   over asn tlvs in the ber blob
    \param 2: [out] Cert, struct in which cert values are saved
    \note     assumes that cert->pos is correctly at pubkey
*/
RESULT set_ecdsa_pubk_info( ber_blob_p cert, Cert out )
{
    /* ANSI x9.62 section A.5.8 Octet String to Point */
    asn_result_init;
    if( out->pubkAlgParam != NULL &&
        out->pubKeyAlgParam_len > 0 )
    {
        _res_ = check_ecdsa_namedcurve_supported( out );
        if( _res_ == ASN_CERT_PUBKALG_ECDSA_CURVE_UNSUPORTED ||
            _res_ == ASN_CERT_PUBKALG_ECDSA_CURVE_SZ_ERROR)
            return _res_;
    }
    out->publicKeyVal = cert->cur_pos;
    out->publicKeyVal_len = cert->payload_len;
    asn_next_tlv( cert, ECDSA_EXT );
    return OK;
}
/*!
    \brief: Certificate extentions - is this extension support ed
    \param 1: [in] hex OID
    \param 2: [in] len of param 1
    \return: index of matched OID, error otherwise
*/
RESULT asn_extension_supported( BYTE* extn, SHORT len )
{
    int j = 0;
    for( ; j < (int) sizeof( exts_supported )
                      / sizeof(BYTE*) ; j++ )
    {
        if( memcmp( (void*) exts_supported[j],
                    (void*) extn, len ) == 0 )
        {
            return j;
        }
    }
    return ASN_CERT_EXT_NOT_SUPPORTED;
}
/*!
    \brief: Certificate extentions - handle extention keyUsage
    \param 1: [in] ber_blob_p, cert which is a cursor
                   over asn tlvs in the ber blob
    \param 2: [out] Cert, struct in which cert values are saved
    \note     assumes that cert->pos is correctly
              at Extension
*/
RESULT asn_handle_keyUsage( ber_blob_p cert, Cert out )
{
    /* keyUsage */
    asn_result_init;
    asn_get_next( cert );
    asn_tlv_check( cert, EXT_OID, UNIVERSAL,
                       PRIMITIVE, OCTET_STRING );
    asn_get_next( cert );
    cur_ext(out).extnValue = cert->cur_pos;
    cur_ext(out).extnValue_len = cert->payload_len;
    asn_next_tlv( cert, EXT_KEYUSAGE );
    return OK;
}
/*!
    \brief: Certificate extentions -handle extention BasicConstraints
    \param 1: [in] ber_blob_p, cert which is a cursor
                   over asn tlvs in the ber blob
    \param 2: [out] Cert, struct in which cert values are saved
    \note     assumes that cert->pos is correctly
              at Extension
*/
RESULT asn_handle_basicConstraints( ber_blob_p cert, Cert out )
{
    /* BasicConstraints ::= SEQUENCE {
        cA                 BOOLEAN DEFAULT FALSE,
        pathLenConstraint INTEGER (0..MAX) OPTIONAL }
    */
    /* cA */
    asn_result_init;
    asn_get_next( cert );
    asn_tlv_check( cert, EXT_OID, UNIVERSAL,
                           PRIMITIVE, BOOLEAN );
    asn_next_tlv( cert, EXT_BASCONST );
    /* pathLenConstraint */
    asn_get_next( cert );
    cur_ext(out).extnValue = cert->cur_pos;
    cur_ext(out).extnValue_len = cert->payload_len;
    asn_next_tlv( cert, EXT_BASCONST );
    return OK;
}
/*!
    \brief: Certificate extentions -handle extention BasicConstraints
    \param 1: [in] ber_blob_p, cert which is a cursor
                   over asn tlvs in the ber blob
    \param 2: [out] Cert, struct in which cert values are saved
    \note     assumes that cert->pos is correctly
              at Extension
*/
RESULT asn_handle_subjectKeyIdentifier( ber_blob_p cert, Cert out )
{
    /* SubjectKeyIdentifier ::= KeyIdentifier
     * RFC 5280 page 28
     * The keyIdentifier is composed of the 160-bit 
     * SHA-1 hash of the value of the BIT STRING
     * subjectPublicKey (excluding the tag,
     * length, and number of unused bits).
     */
    asn_result_init;
    asn_get_next( cert );
    asn_tlv_check( cert, EXT_OID, UNIVERSAL,
                     PRIMITIVE, OCTET_STRING );
    cur_ext(out).extnValue = cert->cur_pos;
    cur_ext(out).extnValue_len = cert->payload_len;
    /* sha1 hash */
    asn_get_next( cert );
    asn_tlv_check( cert, EXT_SUBKID, UNIVERSAL,
                      PRIMITIVE, OCTET_STRING );
    asn_next_tlv( cert, EXT_SUBKID );
    return OK;
}
/*!
    \brief: Certificate extentions -handle extention crlDistributionPoints
    \param 1: [in] ber_blob_p, cert which is a cursor
                   over asn tlvs in the ber blob
    \param 2: [out] Cert, struct in which cert values are saved
    \note     assumes that cert->pos is correctly
              at Extension
*/
RESULT asn_handle_crlDistributionPoints( ber_blob_p cert, Cert out )
{
    /*
     * Rfc 5280 Page 46-47
    id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 }
    CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
    DistributionPoint ::= SEQUENCE {
        distributionPoint       [0]     DistributionPointName OPTIONAL,
        reasons                 [1]     ReasonFlags OPTIONAL,
        cRLIssuer               [2]     GeneralNames OPTIONAL }
    DistributionPointName ::= CHOICE {
        fullName                [0]     GeneralNames,
        nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
   */
    asn_result_init;
    asn_get_next( cert );
    asn_get_next( cert );
    asn_get_next( cert );
    asn_get_next( cert );
    asn_get_next( cert );
    asn_get_next( cert );
    cur_ext(out).extnValue = cert->cur_pos;
    cur_ext(out).extnValue_len = cert->payload_len;
    asn_next_tlv( cert, EXT_CRLPTS );
    return OK;
}
/*!
    \brief: Certificate extentions - handle an extension value
    \param 1: [in] ber_blob_p, cert which is a cursor
                   over asn tlvs in the ber blob
    \param 2: [out] Cert, struct in which cert values are saved
    \note     assumes that cert->pos is correctly
              at Extension
*/
RESULT asn_handle_ext_val( ber_blob_p cert, Cert out )
{
    switch( out->extensions[out->extnum].indx )
    {
        case 0:
            return asn_handle_keyUsage(cert, out);
        case 1:
            return asn_handle_basicConstraints(cert, out);
        case 2:
            return asn_handle_subjectKeyIdentifier(cert, out);
        case 3:
            return asn_handle_crlDistributionPoints(cert, out);
    }
    /* should not reach here */
    return ASN_CERT_EXT_VAL_NOREACH;
}
/*!
    \brief: Certificate extentions - handle an extension oid
    \param 1: [in] ber_blob_p, cert which is a cursor
                   over asn tlvs in the ber blob
    \param 2: [out] Cert, struct in which cert values are saved
    \note     assumes that cert->pos is correctly
              at Extensions
*/
RESULT asn_handle_ext_oid( ber_blob_p cert, Cert out )
{
    asn_result_init;
    /* move over the Extention */
    asn_get_next( cert );
    cur_ext(out).extnOid = cert->begin;
    cur_ext(out).extnOid_len = cert->payload_len;
    asn_tlv_check( cert, EXT, UNIVERSAL,
                    CONSTRUCTED, SEQUENCE );
    /* move over the oid */
    asn_get_next( cert );
    asn_tlv_check( cert, EXT_OID, UNIVERSAL,
                            PRIMITIVE, OID );
    int j = asn_extension_supported( cert->cur_pos,
                            cert->payload_len );
    if( j == ASN_CERT_EXT_NOT_SUPPORTED )
    {
        asn_stack_err( out,
           cert->cur_pos - (BYTE*) cert,
           ASN_CERT_EXT_NOT_SUPPORTED );
        return ASN_CERT_EXT_NOT_SUPPORTED;
    }
    cur_ext(out).indx = j;
    asn_next_tlv( cert, EXT_OID );
    /* get extension values */
    return asn_handle_ext_val( cert, out );
}
/*!
    \brief: Certificate extentions - save an extension
    \param 1: [in] ber_blob_p, cert which is a cursor
                   over asn tlvs in the ber blob
    \param 2: [out] Cert, struct in which cert values are saved
    \note     assumes that cert->pos is correctly
              at Extensions
*/
RESULT asn_check_ext(ber_blob_p cert, Cert out)
{
    /*
       Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
       Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING
                    -- contains the DER encoding of an ASN.1 value
                    -- corresponding to the extension type identified
                    -- by extnID
        }
     */
    asn_result_init;
    /* move over the Extentions bit string */
    asn_get_next(cert);
    out->extns = cert->cur_pos;
    out->extns_len = cert->payload_len;
    asn_tlv_check( cert, EXTS, CTX_SPECIFIC,
                   CONSTRUCTED, BITSTRING );
    /* move over the Extention sequence */
    asn_get_next( cert );
    asn_tlv_check( cert, EXT, UNIVERSAL,
                 CONSTRUCTED, SEQUENCE );
    out->extnum = 0;
    do
    {
        /*
         * handle individual OIDs. _res_ is inited via
         * asn_result_init
         */
        _res_ = asn_handle_ext_oid( cert, out );
        if( _res_ != OK )
        {
            asn_rewind_to( cert,
                           cur_ext(out).extnOid );
            asn_stack_err( out,
                           cur_ext(out).extnOid -
                           (BYTE*) cert,
                           _res_ );
            asn_next_tlv( cert, EXT_OID );
        }
        out->extnum++;
    } while( out->extnum < SUPPORTED_EXTS &&
             cert->cur_pos < 
             ( out->extns + out->extns_len ));
    asn_return_res;
}
/*!
    \brief: Certificate - signature algorithm
    \param 1: [in] ber_blob_p, cert which is a cursor
                   over asn tlvs in the ber blob
    \param 2: [out] Cert, struct in which cert values are saved
    \note     assumes that cert->pos is correctly
              at signature algorithm
*/
RESULT asn_check_sig_alg(ber_blob_p cert, Cert out)
{
    return asn_sig_alg(cert, out, &out->signatureAlg);
}
/*!
    \brief: Certificate - signature
    \param 1: [in] ber_blob_p, cert which is a cursor
                   over asn tlvs in the ber blob
    \param 2: [out] Cert, struct in which cert values are saved
    \note     assumes that cert->pos is correctly
              at signature
*/
RESULT asn_check_sig(ber_blob_p cert, Cert out)
{
    asn_result_init;
    asn_get_next( cert );
    out->signatureValue = cert->cur_pos;
    out->signatureValue_len = cert->payload_len;
    return OK;
}
/*!
    \brief: Certificate - get sha1 hash tbsCertificate data
            object
    \param 1: [in] Cert, struct in which cert values are saved
    \param 2: [out] sha1 checksum of tbsCertificate
    \return: error if any
*/
RESULT asn_check_sha1_sig_hash( Cert out, BYTE* checksum )
{
    asn_result_init;
    sha1_ctx ctx;
    sha1_init( &ctx );
    sha1_update( &ctx, out->tbsCertificate,
                 out->tbsCertificate_len );
    _res_ = sha1_final( &ctx, checksum );
    asn_return_res;
}
/*!
    \brief: Certificate - get hash tbsCertificate data
            object.
    \param 1: [in] Cert, struct in which cert values are saved
    \param 2: [out] checksum of tbsCertificate based on hash alg
    \return: error if any
*/
RESULT asn_check_sig_hash( Cert out, BYTE* checksum )
{
    asn_result_init;
    if( out->signatureAlg.indx !=
        out->caSigAlg.indx )
    {
        return ASN_CERT_SIG_ALG_INCONSISTENT;
    }
    switch( out->caSigAlg.indx )
    {
        case ALG_RSA_SHA1:
        case ALG_ECDSA_SHA1:
            return asn_check_sha1_sig_hash( out, checksum );
        default:
            return ASN_CERT_SIGALG_NOT_SUPPORTED;
    }
    asn_return_res;
}
RESULT asn_check_verify_rsa_sha1_sig( BYTE* checksum, Integer C )
{
    asn_result_init;
    SHORT j = C->topByte;
    if( C->buf[j] != 0x01 )
    {
        return ASN_CERT_SIG_BLOCK_INVALID;
    }
    while( C->buf[j++] && (j < C->size) );
    if( j == C->size )
    {
        return ASN_CERT_SIG_BLOCK_NO_MSG;
    }
    /* 0x01 0xFF 0xFF 0x00 */
    mk_berblob_from_buf( pvk, C->buf + j, C->size - j );
    asn_get_next( pvk );
    asn_get_next( pvk );
    asn_get_next( pvk );
    asn_next_tlv( pvk, RSA_SIG_PARAM );
    asn_get_next( pvk );
    asn_get_next( pvk );
    if( pvk->payload_len != 20 )
    {
        return ASN_CERT_SIG_RSASHA1_PAYLOAD_LEN_ERR;
    }
    if( memcmp( checksum, pvk->cur_pos, 20 ) == 0 )
    {
        _res_ = OK;
    } else
    {
        _res_ = ASN_CERT_SIG_RSASHA1_VERIFY_FAILED;
    }
    asn_return_res;
}
RESULT asn_check_verify_ecc_sig( BYTE* checksum, dss_sig_p d )
{
    asn_result_init;
    if(  !( d->c ) || !( d->r ) || !( d->r_len )
      || !( d->s ) || !( d->s_len ) )
        return ASN_CERT_ECDSA_SIG_VAL_ERROR;
     /* u1 = e' (s') mod n and u2 = r' (s') mod n */
    if( d->c->caSigAlg.indx == ALG_ECDSA_SHA1 )
    {
        _res_ = ecc_verify( ec_get_curve_id() , d->r, d->r_len,
                                  d->s, d->s_len, checksum, 20, 
                   d->c->publicKeyVal, d->c->publicKeyVal_len);
    }
    return _res_;
}
/*!
    \brief: Certificate - verify ecdsa signature
    \param 1: [in] Cert, struct in which cert values are saved
    \param 2: [in] checksum of tbsCertificate based on hash alg
    \return: error if any
*/
RESULT asn_check_ecdsa_sig_decrypt( Cert out, BYTE* checksum )
{
    asn_result_init;
    dss_sig ds;
    /* ECC Sig (r,s) */
    mk_berblob_from_buf( dss, out->signatureValue,
                         out->signatureValue_len );
    asn_get_next( dss );
    asn_get_next( dss );
    ds.r = dss->cur_pos;
    ds.r_len = dss->payload_len;
    asn_next_tlv( dss, DSSSIG_S );
    asn_get_next( dss );
    ds.s = dss->cur_pos;
    ds.s_len = dss->payload_len;
    ds.c = out;
    if( out->caSigAlg.indx == ALG_ECDSA_SHA1 )
    {
        _res_ = asn_check_verify_ecc_sig( checksum, &ds );
    }
    asn_return_res;
}
/*!
    \brief: Certificate - compare checksum and decrypted message
                          in rsa sig
    \param 1: [in] Cert, struct in which cert values are saved
    \param 2: [in] checksum of tbsCertificate based on hash alg
    \return: error if any
*/
RESULT asn_check_rsa_sig_decrypt( Cert out, BYTE* checksum )
{
    /* TODO: move this to rsa_verify ASAP
    asn_result_init;
    dint( N, out->publicKeyVal,
             out->publicKeyVal_len );
    dint( E, out->publicKeyParam1_val,
             out->publicKeyParam1Val_len );
    dint( A, out->signatureValue,
             out->signatureValue_len );
    mint( C, 2* (out->publicKeyVal_len) );
    _res_ = mont_modexp_n( A, E, N, C );
    if( _res_ != OK )
    {
        return _res_;
    }
    printf( "=== Decrypted digest ===\n" );
    hexdump( C->buf, C->size );
    printf( "========================\n" );
    if( out->caSigAlg.indx == ALG_RSA_SHA1 )
    {
        _res_ = asn_check_verify_rsa_sha1_sig( checksum, C );
    }
    goto done;
no_mem_:
    _res_ = NO_MEM;
done:
    flint( C );
    flint( N );
    flint( E );
    flint( A );
    asn_return_res;
    */
    return OK;
}
/*!
    \brief: Certificate - return signature message based
                          on alg.
    \param 1: [in] Cert, struct in which cert values are saved
    \param 2: [in] Calculated checksum
    \param 3: [out] Integer Message
    \return: error if any
    \note: TODO:dsa returns yes or no instead of Integer
           caller uses flint( M ) to free memory
*/
RESULT asn_check_sig_decrypt( Cert out, BYTE* checksum )
{
    asn_result_init;
    if( out->signatureAlg.indx !=
        out->caSigAlg.indx )
    {
        return ASN_CERT_SIG_ALG_INCONSISTENT;
    }
    switch( out->caSigAlg.indx )
    {
        case ALG_RSA_SHA1:
            return asn_check_rsa_sig_decrypt( out, checksum );
        case ALG_ECDSA_SHA1:
            return asn_check_ecdsa_sig_decrypt( out, checksum );
        default:
            return ASN_CERT_SIGALG_NOT_SUPPORTED;
    }
    asn_return_res;
}
/*!
    \brief: Certificate - verify signature
*/
RESULT asn_check_verify_sig(Cert out)
{
    asn_result_init;
    BYTE checksum[20];
    switch( out->caSigAlg.indx )
    {
        case ALG_RSA_SHA1:
        case ALG_ECDSA_SHA1:
            _res_ = asn_check_sig_hash( out, checksum );
            if( _res_ != OK )
            {
                printf( "sig hash failed [%X]\r\n", _res_ );
                break;
            }
            _res_ = asn_check_sig_decrypt( out, checksum );
            break;
        default:
            break;
    }
    asn_return_res;
}
/*!
    \brief: parse a buffer as a certificate
    \param 1: [in] buffer = value of integer
    \param 2: [in] SHORT len of buffer
    \param 3: [out] buffer parsed into Certificate struct
*/
RESULT parse_cert(BYTE* buffer, SHORT n, Cert out)
{
    asn_result_init;
    mk_berblob_from_buf(      cert, buffer, n );
    asn_check( certificate,         cert, out );
    asn_check( tbscertificate,      cert, out );
    asn_check( version,             cert, out );
    asn_check( serialnum,           cert, out );
    asn_check( ca_sig_alg_id,       cert, out );
    asn_check( issuer,              cert, out );
    asn_check( validity,            cert, out );
    asn_check( subject,             cert, out );
    asn_check( pubk,                cert, out );
    asn_check( ext,                 cert, out );
    asn_check( sig_alg,             cert, out );
    asn_check( sig,                 cert, out );
    asn_return_res;
}
