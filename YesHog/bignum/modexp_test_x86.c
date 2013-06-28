#include<stdio.h>
#include<string.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
void printInt(unsigned char* x, size_t len)
{
    size_t j = 0;
    for ( j=0; j< len; j++ )
    {
        printf("%02X", x[j]);
    }
    printf("\n");
}
int chunk_print(char* out, unsigned char* x, size_t len)
{
    size_t j = 0;
    for ( j=0; j< len; j++ )
    {
        snprintf( out + (j*2), 3, "%02X", x[j]);
    }
    snprintf( out + (j*2), 2, ",");
    return strlen(out);
    printf("**\n%s\n**", out );
}

static int
modexp(unsigned char* out,
       unsigned char* in, size_t len,
       unsigned char* m, size_t m_sz,
       unsigned char* e, size_t e_sz
      )
{
        BN_CTX *ctx;
        BIGNUM mod, exp, x, y;
        ctx = BN_CTX_new();
        BN_init(&mod);
        BN_init(&exp);
        BN_init(&x);
        BN_init(&y);
        BN_bin2bn(m, m_sz, &mod);
        BN_bin2bn(e, e_sz, &exp);
        BN_bin2bn(in, len, &x);
        /*
        printInt(m, m_sz);
        printInt(e, e_sz);
        printInt(in, len);
        printf("mod %s\n", BN_bn2dec(&mod));
        printf("exp %s\n", BN_bn2dec(&exp));
        printf("msg %s\n", BN_bn2dec(&x));
        */
        BN_mod_exp(&y, &x, &exp, &mod, ctx);
        int outlen = BN_bn2bin(&y, out);
        /*
        printf("out len = [%d]\n", outlen);
        */
        if (outlen < (int) m_sz)
        {
            memset(out + outlen, 0, m_sz - outlen);
        }
        BN_free(&y);
        BN_clear_free(&x);
        BN_free(&exp);
        BN_free(&mod);
        BN_CTX_free(ctx);
        return outlen;
}

unsigned char* str2byte( char* number, unsigned char* out, size_t outlen )
{
    if( !number || strlen(number) == 0 )
    {
        return NULL;
    }
    memset( out, 0, outlen );
    size_t numlen = strlen(number);
    size_t count = outlen;
    while( numlen >= 2 )
    {
        numlen -=2;
        sscanf(number+numlen, "%2hhx", &out[--count]);
    }
    if( numlen == 1 )
    {
        numlen --;
        char c = number[numlen];
        out[--count] = atoi(&c);
    }
    return out + (outlen - (outlen-count));
}

int main(int argc, char** argv)
{
    if( argc != 4 )
    {
        printf( "Usage modexp x e n output "
                "(x^e mod n )\n" );
        return 0;
    }
    unsigned char out[2048];
    unsigned char x  [512];
    unsigned char e  [512];
    unsigned char n  [512];

    str2byte( argv[1], x, sizeof(x) );    
    str2byte( argv[2], e, sizeof(e) );
    str2byte( argv[3], n, sizeof(n));
    printf( "%s^%s mod %s\n", argv[1], argv[2], argv[3] );
    int l = modexp( out, x, sizeof(x), n, sizeof(n), e, sizeof(e) );
    printInt( out, l );
    return 0;
}

