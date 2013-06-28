#include "asn.h"
#include <stdio.h>
#include <sys/stat.h>
#define MAX_FILE_SIZE 8192
static char CERT_FILE[] ="sample-Certificate-1.der";

int test_asn_verify_rsa_sig( int, char** );
int test_ecc_verify( void );
int test_ec_pt_add( EC_vars_p );
int test_ec_pt_dbl( EC_vars_p );
int test_ec_scalar_mul( EC_vars_p, Integer );

SWORD get_test_cert(BYTE* buffer)
{
    FILE *f;
    SWORD n = 0;
    struct stat sb;
    RESULT r = OK;

    if( stat( CERT_FILE, &sb ) < 0 )
    {
        goto err;
    }

    f = fopen(CERT_FILE, "rb");
    if (f)
    {
        n = fread(buffer, 1, MAX_FILE_SIZE, f);
            printf("Opening [%s] read [%d] bytes\n", CERT_FILE, n);
        if ( n == 0 )
        {
            r = -1;
            goto err;
        }
        goto done;
    }
err:
    printf("Error reading file [%d]\n", r);
done:
    fclose(f);
    return n;
}

/* TODO: calculate stack heap size of entire operation for 20 bit
int test_ecc_verify_160r1( void )
{
    BYTE _r[] = { 0x00 , 0x84 , 0x2B , 0x01 , 0x00 , 0x30 , 0xEA , 0x6D , 0x39 ,
                  0x9E , 0x6B , 0xA3 , 0x12 , 0x8B , 0x70 , 0x1A , 0x2B , 0xCF ,
                  0x9D , 0x99 , 0x05 };
    BYTE _s[] = { 0x00 , 0x96 , 0xF1 , 0x9F , 0x5B , 0xAC , 0xC9 , 0x86 , 0x19 ,
                  0x39 , 0x64 , 0xF7 , 0xE4 , 0x61 , 0xE1 , 0x56 , 0xCE , 0x69 ,
                  0x3E , 0x1A , 0x53 };
    BYTE _e[] = { 0x04 , 0xD6 , 0x05 , 0x83 , 0x39 , 0xCC , 0x6F , 0xED , 0x24 ,
                  0x37 , 0x39 , 0xEF , 0x0D , 0xD9 , 0xD3 , 0xE3, 0xF6 , 0x7A ,
                  0x02 , 0x4A };
    BYTE _q[] = { 0x00 ,0x04 ,0x17 ,0x8C ,0x2F ,0x22 ,0x20 ,0x9D,
                  0xFC ,0x29 ,0xB3 ,0x17 ,0xDD ,0x38 ,0xFB ,0xF3,
                  0x9A ,0x98 ,0xB2 ,0x7C ,0x08 ,0xC3 ,0xB4 ,0xEC,
                  0xD4 ,0x45 ,0x96 ,0x74 ,0x8D ,0x70 ,0xF4 ,0xE2,
                  0x15 ,0xB5 ,0xF6 ,0x72 ,0x7F ,0x62 ,0x71 ,0xBB,
                  0xBD ,0x40 };
   return ecc_verify( SECP160R1_ID, _r, sizeof(_r), _s, sizeof( _s ),
                                    _e, sizeof(_e), _q, sizeof( _q ) );
}

int test_ecc_verify_secp384_r1( void )
{
    BYTE _r[] = {  };
    BYTE _s[] = {  };
    BYTE _e[] = {  };
    BYTE _q[] = {  };
   return ecc_verify( SECP384R1_ID, _r, sizeof(_r), _s, sizeof( _s ),
                                    _e, sizeof(_e), _q, sizeof( _q ) );
}
 */
int test_asn_verify_rsa_sig( int argc, char** argv )
{
    BYTE *buffer;
    char *filename;
    RESULT r;
    SWORD n;
    filename = (argc > 1) ? argv[1]:CERT_FILE;

    buffer = get_file_data( filename, &n );
    if( n <= 0 || buffer == NULL )
    {
        printf("File [%s] not found or len 0\n",
                filename);
        if( buffer ) free( buffer );
        return 1;
    };
    printf("Read [%d] bytes from [%s]\n",
            n, filename);
    Certificate c;
    Cert cert = &c;
    r = parse_cert( buffer, n, cert );
    if( r != OK )
    {
        printf("parse_cert failed with [%X] \n", r);
        return r;
    }
    r = asn_check_verify_sig( cert );
    printf("Result %X [%s]\n", r, (r == OK)? "OK":"Failed" );
    return r;
}

int main(int argc, char** argv)
{
    RESULT _res_ = OK;
    _res_ = test_asn_verify_rsa_sig( argc, argv );
    if( _res_ != OK )
    {
        printf( "test_asn_verify_rsa_sig failed [%X]\n", _res_ );
    }
    /*
    _res_ = test_ecc_verify();
    if( _res_ != OK )
    {
        printf( "test_ecc_verify failed [%X]\n", _res_ );
    }
    */
    return OK;
}
