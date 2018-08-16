/* $OpenBSD: chacha.h,v 1.4 2016/08/27 04:04:56 guenther Exp $ */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#ifndef CHACHA_H
#define CHACHA_H

#include <stdint.h>
#include <stdlib.h>


typedef uint8_t u8;
typedef uint32_t u32;

struct chacha_ctx {
	u32 input[16];
};

#define CHACHA_MINKEYLEN 	16
#define CHACHA_NONCELEN		8
#define CHACHA_CTRLEN		8
#define CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN		64

void chacha_keysetup(struct chacha_ctx *x, const u8 *k, u32 kbits);
void chacha_ivsetup(struct chacha_ctx *x, const u8 *iv, const u8 *ctr);
void chacha_encrypt_bytes(struct chacha_ctx *x, const u8 *m, u8 *c, u32 bytes);

#endif	/* CHACHA_H */

