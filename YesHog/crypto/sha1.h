/*
 * RFC 3174
 *  sha1.h
 *
 *  Description:
 *      This is the header file for code which implements the Secure
 *      Hashing Algorithm 1 as defined in FIPS PUB 180-1 published
 *      April 17, 1995.
 *
 *      Many of the variable names in this code, especially the
 *      single character names, were used because those were the names
 *      used in the publication.
 *
 *      Please read the file sha1.c for more information.
 *
 */

#ifndef _SHA1_H_
#define _SHA1_H_
#include <common.h>
#define SHA1_LEN 20
/*
 *  This structure will hold context information for the hashing
 *  operation
 */
typedef struct sha1_ctx
{
    WORD Message_Digest[5]; /* Message Digest (output)          */

    WORD Length_Low;        /* Message length in bits           */
    WORD Length_High;       /* Message length in bits           */

    unsigned char Message_Block[64]; /* 512-bit message blocks      */
    WORD Message_Block_Index;    /* Index into message block array   */

    BYTE Computed;               /* Is the digest computed?          */
    BYTE Corrupted;              /* Is the message digest corruped?  */
} sha1_ctx, *sha1_ctx_p;

/*
 *  Function Prototypes
 */
void sha1_init(sha1_ctx *);
void sha1_update( sha1_ctx *, BYTE*, SHORT );
RESULT sha1_final(sha1_ctx *, BYTE*);
#endif
