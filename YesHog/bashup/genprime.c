#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
/* for bn tests 
gcc -g -lcrypto -o genprime genprime.c */
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

static const char rnd_seed[] = "string to make the random number generator think it has entropy";
int genprime_cb(int p, int n, BN_GENCB *arg);
BN_CTX *ctx;
BIO *out;
int main(int argc, char** argv){

	int p=512;

	if(argc==2) {
		p=atoi(argv[1]);
	}

	char *outfile=NULL;

	RAND_seed(rnd_seed, sizeof rnd_seed); /* or BN_generate_prime may fail */

	ctx=BN_CTX_new();
	if (ctx == NULL) exit(1);

	out=BIO_new(BIO_s_file());
	if (out == NULL) exit(1);
	if (outfile == NULL)
		{
		BIO_set_fp(out,stdout,BIO_NOCLOSE);
		}
	else
		{
		if (!BIO_write_filename(out,outfile))
			{
			perror(outfile);
			exit(1);
			}
		}
	/* generate prime here */
	BIGNUM a;
	BN_GENCB cb;
	BN_init(&a);
	BN_GENCB_set(&cb, genprime_cb, NULL);
	if (!BN_generate_prime_ex(&a, p, 0, NULL, NULL, &cb)) goto err;
        printf("%s", BN_bn2dec(&a));
	BN_free(&a);
	/* end test here */
	(void)BIO_flush(out);
        return 0;
    err:
        if(&a!=NULL) BN_free(&a);
	return 1;
}

int genprime_cb(int p, int n, BN_GENCB *arg)
	{
	return 1;
	}
