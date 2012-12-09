/*
 * Our own RC4 based on the "original" as posted to sci.crypt in 1994 and
 * tweaked for  performance  on  x86-64.   OpenSSL is probably faster for
 * decrypting larger amounts of data but we are more interested in a very
 * fast key setup.  On Intel and AMD x64, I have seen up to 50% speedups.
 *
 * The speed  improvement  (if you see one) is due to OpenSSL's  (or your
 * distributor's) choice of type for RC4_INT. Some systems perform bad if
 * this is defined as char. Others perform bad if it's not. If needed, we
 * could move JOHN_RC4_INT to arch.h
 *
 * Syntax is same as OpenSSL;
 * just #include "rc4.h"  instead of  <openssl/rc4.h>
 *
 * Put together by magnum in 2011. No Rights Reserved.
 */

#ifndef HEADER_RC4_H
#define HEADER_RC4_H

#include <stdint.h>

#define RC4_INT uint32_t

typedef struct rc4_key
{
	RC4_INT state[256];
	RC4_INT x;
	RC4_INT y;
} RC4_KEY;

extern void RC4_set_key(RC4_KEY *ctx, RC4_INT len, const unsigned char *data);
extern void RC4(RC4_KEY *ctx, RC4_INT len, const unsigned char *indata,
                unsigned char *outdata);
extern void RC4_single(void *key, unsigned int keylen, const unsigned char *in, int len,
                       unsigned char *out);

#endif /* HEADER_RC4_H */
