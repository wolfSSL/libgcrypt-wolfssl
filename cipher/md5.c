/* md5.c - MD5 Message-Digest Algorithm
 * Copyright (C) 1995,1996,1998,1999,2001,2002,
 *               2003  Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * According to the definition of MD5 in RFC 1321 from April 1992.
 * NOTE: This is *not* the same file as the one from glibc.
 * Written by Ulrich Drepper <drepper@gnu.ai.mit.edu>, 1995.
 * heavily modified for GnuPG by Werner Koch <wk@gnupg.org>
 */

/* Test values:
 * ""                  D4 1D 8C D9 8F 00 B2 04  E9 80 09 98 EC F8 42 7E
 * "a"                 0C C1 75 B9 C0 F1 B6 A8  31 C3 99 E2 69 77 26 61
 * "abc                90 01 50 98 3C D2 4F B0  D6 96 3F 7D 28 E1 7F 72
 * "message digest"    F9 6B 69 7D 7C B7 93 8D  52 5A 2F 31 AA F1 61 D0
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g10lib.h"
#include "cipher.h"

#include "bithelp.h"
#include "bufhelp.h"
#include "hash-common.h"


typedef struct {
    gcry_md_block_ctx_t bctx;
    u32 A,B,C,D;	  /* chaining variables */
} MD5_CONTEXT;

static unsigned int
transform ( void *ctx, const unsigned char *data, size_t datalen );

static void
md5_init( void *context, unsigned int flags)
{
  MD5_CONTEXT *ctx = context;

  (void)flags;

  ctx->A = 0x67452301;
  ctx->B = 0xefcdab89;
  ctx->C = 0x98badcfe;
  ctx->D = 0x10325476;

  ctx->bctx.nblocks = 0;
  ctx->bctx.nblocks_high = 0;
  ctx->bctx.count = 0;
  ctx->bctx.blocksize_shift = _gcry_ctz(64);
  ctx->bctx.bwrite = transform;
}


/* These are the four functions used in the four steps of the MD5 algorithm
   and defined in the RFC 1321.  The first function is a little bit optimized
   (as found in Colin Plumbs public domain implementation).  */
/* #define FF(b, c, d) ((b & c) | (~b & d)) */
#define FF(b, c, d) (d ^ (b & (c ^ d)))
#define FG(b, c, d) FF (d, b, c)
#define FH(b, c, d) (b ^ c ^ d)
#define FI(b, c, d) (c ^ (b | ~d))


/****************
 * transform 64 bytes
 */
static unsigned int
transform_blk ( void *c, const unsigned char *data )
{
  MD5_CONTEXT *ctx = c;
  u32 correct_words[16];
  register u32 A = ctx->A;
  register u32 B = ctx->B;
  register u32 C = ctx->C;
  register u32 D = ctx->D;
  u32 *cwp = correct_words;
  int i;

  for ( i = 0; i < 16; i++ )
    correct_words[i] = buf_get_le32(data + i * 4);

#define OP(a, b, c, d, s, T) \
  do			         	   \
    {					   \
      a += FF (b, c, d) + (*cwp++) + T;    \
      a = rol(a, s);			   \
      a += b;				   \
    }					   \
  while (0)

  /* Before we start, one word about the strange constants.
     They are defined in RFC 1321 as

     T[i] = (int) (4294967296.0 * fabs (sin (i))), i=1..64
  */

  /* Round 1.  */
  OP (A, B, C, D,  7, 0xd76aa478);
  OP (D, A, B, C, 12, 0xe8c7b756);
  OP (C, D, A, B, 17, 0x242070db);
  OP (B, C, D, A, 22, 0xc1bdceee);
  OP (A, B, C, D,  7, 0xf57c0faf);
  OP (D, A, B, C, 12, 0x4787c62a);
  OP (C, D, A, B, 17, 0xa8304613);
  OP (B, C, D, A, 22, 0xfd469501);
  OP (A, B, C, D,  7, 0x698098d8);
  OP (D, A, B, C, 12, 0x8b44f7af);
  OP (C, D, A, B, 17, 0xffff5bb1);
  OP (B, C, D, A, 22, 0x895cd7be);
  OP (A, B, C, D,  7, 0x6b901122);
  OP (D, A, B, C, 12, 0xfd987193);
  OP (C, D, A, B, 17, 0xa679438e);
  OP (B, C, D, A, 22, 0x49b40821);

#undef OP
#define OP(f, a, b, c, d, k, s, T)  \
    do								      \
      { 							      \
	a += f (b, c, d) + correct_words[k] + T;		      \
	a = rol(a, s);						      \
	a += b; 						      \
      } 							      \
    while (0)

  /* Round 2.  */
  OP (FG, A, B, C, D,  1,  5, 0xf61e2562);
  OP (FG, D, A, B, C,  6,  9, 0xc040b340);
  OP (FG, C, D, A, B, 11, 14, 0x265e5a51);
  OP (FG, B, C, D, A,  0, 20, 0xe9b6c7aa);
  OP (FG, A, B, C, D,  5,  5, 0xd62f105d);
  OP (FG, D, A, B, C, 10,  9, 0x02441453);
  OP (FG, C, D, A, B, 15, 14, 0xd8a1e681);
  OP (FG, B, C, D, A,  4, 20, 0xe7d3fbc8);
  OP (FG, A, B, C, D,  9,  5, 0x21e1cde6);
  OP (FG, D, A, B, C, 14,  9, 0xc33707d6);
  OP (FG, C, D, A, B,  3, 14, 0xf4d50d87);
  OP (FG, B, C, D, A,  8, 20, 0x455a14ed);
  OP (FG, A, B, C, D, 13,  5, 0xa9e3e905);
  OP (FG, D, A, B, C,  2,  9, 0xfcefa3f8);
  OP (FG, C, D, A, B,  7, 14, 0x676f02d9);
  OP (FG, B, C, D, A, 12, 20, 0x8d2a4c8a);

  /* Round 3.  */
  OP (FH, A, B, C, D,  5,  4, 0xfffa3942);
  OP (FH, D, A, B, C,  8, 11, 0x8771f681);
  OP (FH, C, D, A, B, 11, 16, 0x6d9d6122);
  OP (FH, B, C, D, A, 14, 23, 0xfde5380c);
  OP (FH, A, B, C, D,  1,  4, 0xa4beea44);
  OP (FH, D, A, B, C,  4, 11, 0x4bdecfa9);
  OP (FH, C, D, A, B,  7, 16, 0xf6bb4b60);
  OP (FH, B, C, D, A, 10, 23, 0xbebfbc70);
  OP (FH, A, B, C, D, 13,  4, 0x289b7ec6);
  OP (FH, D, A, B, C,  0, 11, 0xeaa127fa);
  OP (FH, C, D, A, B,  3, 16, 0xd4ef3085);
  OP (FH, B, C, D, A,  6, 23, 0x04881d05);
  OP (FH, A, B, C, D,  9,  4, 0xd9d4d039);
  OP (FH, D, A, B, C, 12, 11, 0xe6db99e5);
  OP (FH, C, D, A, B, 15, 16, 0x1fa27cf8);
  OP (FH, B, C, D, A,  2, 23, 0xc4ac5665);

  /* Round 4.  */
  OP (FI, A, B, C, D,  0,  6, 0xf4292244);
  OP (FI, D, A, B, C,  7, 10, 0x432aff97);
  OP (FI, C, D, A, B, 14, 15, 0xab9423a7);
  OP (FI, B, C, D, A,  5, 21, 0xfc93a039);
  OP (FI, A, B, C, D, 12,  6, 0x655b59c3);
  OP (FI, D, A, B, C,  3, 10, 0x8f0ccc92);
  OP (FI, C, D, A, B, 10, 15, 0xffeff47d);
  OP (FI, B, C, D, A,  1, 21, 0x85845dd1);
  OP (FI, A, B, C, D,  8,  6, 0x6fa87e4f);
  OP (FI, D, A, B, C, 15, 10, 0xfe2ce6e0);
  OP (FI, C, D, A, B,  6, 15, 0xa3014314);
  OP (FI, B, C, D, A, 13, 21, 0x4e0811a1);
  OP (FI, A, B, C, D,  4,  6, 0xf7537e82);
  OP (FI, D, A, B, C, 11, 10, 0xbd3af235);
  OP (FI, C, D, A, B,  2, 15, 0x2ad7d2bb);
  OP (FI, B, C, D, A,  9, 21, 0xeb86d391);

  /* Put checksum in context given as argument.  */
  ctx->A += A;
  ctx->B += B;
  ctx->C += C;
  ctx->D += D;

  return /*burn_stack*/ 80+6*sizeof(void*);
}


static unsigned int
transform ( void *c, const unsigned char *data, size_t nblks )
{
  unsigned int burn;

  do
    {
      burn = transform_blk (c, data);
      data += 64;
    }
  while (--nblks);

  return burn;
}


/* The routine final terminates the message-digest computation and
 * ends with the desired message digest in mdContext->digest[0...15].
 * The handle is prepared for a new MD5 cycle.
 * Returns 16 bytes representing the digest.
 */

static void
md5_final( void *context)
{
  MD5_CONTEXT *hd = context;
  u32 t, th, msb, lsb;
  byte *p;
  unsigned int burn;

  t = hd->bctx.nblocks;
  if (sizeof t == sizeof hd->bctx.nblocks)
    th = hd->bctx.nblocks_high;
  else
    th = hd->bctx.nblocks >> 32;

  /* multiply by 64 to make a byte count */
  lsb = t << 6;
  msb = (th << 6) | (t >> 26);
  /* add the count */
  t = lsb;
  if( (lsb += hd->bctx.count) < t )
    msb++;
  /* multiply by 8 to make a bit count */
  t = lsb;
  lsb <<= 3;
  msb <<= 3;
  msb |= t >> 29;

  if (hd->bctx.count < 56)  /* enough room */
    {
      hd->bctx.buf[hd->bctx.count++] = 0x80; /* pad */
      if (hd->bctx.count < 56)
	memset (&hd->bctx.buf[hd->bctx.count], 0, 56 - hd->bctx.count);

      /* append the 64 bit count */
      buf_put_le32(hd->bctx.buf + 56, lsb);
      buf_put_le32(hd->bctx.buf + 60, msb);
      burn = transform (hd, hd->bctx.buf, 1);
    }
  else /* need one extra block */
    {
      hd->bctx.buf[hd->bctx.count++] = 0x80; /* pad character */
      /* fill pad and next block with zeroes */
      memset (&hd->bctx.buf[hd->bctx.count], 0, 64 - hd->bctx.count + 56);

      /* append the 64 bit count */
      buf_put_le32(hd->bctx.buf + 64 + 56, lsb);
      buf_put_le32(hd->bctx.buf + 64 + 60, msb);
      burn = transform (hd, hd->bctx.buf, 2);
    }

  p = hd->bctx.buf;
#define X(a) do { buf_put_le32(p, hd->a); p += 4; } while(0)
  X(A);
  X(B);
  X(C);
  X(D);
#undef X

  hd->bctx.count = 0;

  _gcry_burn_stack (burn);
}

static byte *
md5_read( void *context )
{
  MD5_CONTEXT *hd = (MD5_CONTEXT *) context;
  return hd->bctx.buf;
}

static const byte asn[18] = /* Object ID is 1.2.840.113549.2.5 */
  { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,0x48,
    0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };

static const gcry_md_oid_spec_t oid_spec_md5[] =
  {
    /* iso.member-body.us.rsadsi.pkcs.pkcs-1.4 (md5WithRSAEncryption) */
    { "1.2.840.113549.1.1.4" },
    /* RSADSI digestAlgorithm MD5 */
    { "1.2.840.113549.2.5" },
    { NULL },
  };

const gcry_md_spec_t _gcry_digest_spec_md5 =
  {
    GCRY_MD_MD5, {0, 0},
    "MD5", asn, DIM (asn), oid_spec_md5, 16,
    md5_init, _gcry_md_block_write, md5_final, md5_read, NULL,
    NULL,
    sizeof (MD5_CONTEXT)
  };
