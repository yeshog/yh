#include <common.h>

RESULT test_memfind_fail()
{
    BYTE fail_buf[] = {
                      0x01, 0x01, 0x08, 0x0a, 0x00,
                      0xb7, 0x0a, 0xcc, 0x00, 0xb7,
                      0x07, 0xd0
                      };
    SSHORT n_l = memfind( fail_buf, 0, "\x08\x0A", 2 );
    printf( "n_l [%d]\n", n_l );
    return (n_l > 0) ? OK:-1;
}
int main(void)
{
    if( test_memfind_fail() < 0 )
    {
        printf( "memfind failed \n");
    }
    return 0;
}
