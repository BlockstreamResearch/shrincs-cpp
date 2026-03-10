//  rng.h
//  2018-04-28  Markku-Juhani O. Saarinen <mjos@iki.fi>
//              Simple AES-256 CTR Generator

#ifndef __RNG_H__
#define __RNG_H__

#include <openssl/aes.h>

#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

typedef struct {
    int             ptr;
    unsigned char   ctr[16];
    unsigned char   buf[16];
    AES_KEY         key;
} AES_XOF_struct;

int
seedexpander_init(AES_XOF_struct *ctx,
                  unsigned char *seed,
                  unsigned char *diversifier,
                  unsigned long maxlen);

int
seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen);

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength);

int
randombytes(unsigned char *x, unsigned long long xlen);

#endif /* rng_h */
