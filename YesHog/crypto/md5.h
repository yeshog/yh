#include <common.h>
#define MD5_LEN 16
typedef struct {
    WORD lo, hi;
    WORD a, b, c, d;
    BYTE buffer[64];
    WORD block[16];
} md5_ctx;

void md5_init( md5_ctx* );
void md5_update( md5_ctx *, BYTE*, SHORT );
void md5_final( md5_ctx*, BYTE* );