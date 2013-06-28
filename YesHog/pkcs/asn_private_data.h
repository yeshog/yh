#define SUPPORTED_EXTS 4
#define SUPPORTED_SIG_ALGS 3
#define SUPPORTED_PUBK_ALGS 2

/* This could be done in a table, or enum however
    keep static tables and other luxuries to a minimum */
#define ALG_RSA_SHA1   0
#define ALG_DSA_SHA1   1
#define ALG_ECDSA_SHA1 2

#define SIGALG(x) alg_##x

static BYTE ext_keyUsage              [] = { 0x55, 0x1D, 0x0F };
static BYTE ext_basicConstraints      [] = { 0x55, 0x1D, 0x13 };
static BYTE ext_subjKeyIdentifier     [] = { 0x55, 0x1D, 0x0E };
static BYTE ext_crlDistributionPoints [] = { 0x55, 0x1D, 0x1F };

static BYTE* exts_supported[ SUPPORTED_EXTS] = 
     {        ext_keyUsage,        ext_basicConstraints,
     ext_subjKeyIdentifier,    ext_crlDistributionPoints      };

/* Signature algorithms */
static BYTE alg_rsa_sha1[]   = { 0x2A, 0x86, 0x48, 0x86, 0xF7,
                                 0x0D, 0x01, 0x01, 0x05 };
static BYTE alg_dsa_sha1[]   = { 0x2A, 0x86, 0x48, 0xCE, 0x38,
                                 0x04, 0x03 };
static BYTE alg_ecdsa_sha1[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                 0x04, 0x01 };
static BYTE* algs[SUPPORTED_SIG_ALGS] =  { alg_rsa_sha1,
                                           alg_dsa_sha1,
                                       alg_ecdsa_sha1 };

static BYTE alg_rsa[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
                          0x01, 0x01, 0x01 };
static BYTE alg_ecdsa[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
                            0x01 };

static BYTE* pubk_algs[SUPPORTED_PUBK_ALGS] = { alg_rsa, alg_ecdsa };
