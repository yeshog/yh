#include <yhmemory.h>
#define AES_KEY_LEN 16
#define AES_BLOCK_SZ 16
#define CIPH_KEY_LEN AES_KEY_LEN
#define CIPH_BLOCK_SZ AES_BLOCK_SZ
#define Nb 4
#define Nk 4
#define Nr 10
#define CIPH_KEY_SZ (4 * Nb * (Nr + 1))

void aes_expand_key( BYTE*, BYTE* );
void aes_encrypt (BYTE*, BYTE*, BYTE*);
SHORT aes_cbc_decrypt( BYTE*, BYTE*, BYTE*, SHORT );
void aes_decrypt(BYTE*, BYTE* , BYTE* );
SHORT aes_cbc_encrypt(BYTE*, BYTE*, BYTE*, SHORT, BYTE* , SHORT);
SHORT aes_cbc_decrypt( BYTE*, BYTE*, BYTE*, SHORT );
extern void printBuf( BYTE*, SHORT );