/* cipher-xts.c  - XTS mode implementation
 * Copyright (C) 2017 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "cipher.h"
#include "bufhelp.h"
#include "./cipher-internal.h"


static inline void xts_gfmul_byA (unsigned char *out, const unsigned char *in)
{
  u64 hi = buf_get_le64 (in + 8);
  u64 lo = buf_get_le64 (in + 0);
  u64 carry = -(hi >> 63) & 0x87;

  hi = (hi << 1) + (lo >> 63);
  lo = (lo << 1) ^ carry;

  buf_put_le64 (out + 8, hi);
  buf_put_le64 (out + 0, lo);
}


static inline void xts_inc128 (unsigned char *seqno)
{
  u64 lo = buf_get_le64 (seqno + 0);
  u64 hi = buf_get_le64 (seqno + 8);

  hi += !(++lo);

  buf_put_le64 (seqno + 0, lo);
  buf_put_le64 (seqno + 8, hi);
}


gcry_err_code_t
_gcry_cipher_xts_crypt (gcry_cipher_hd_t c,
			unsigned char *outbuf, size_t outbuflen,
			const unsigned char *inbuf, size_t inbuflen,
			int encrypt)
{
  gcry_cipher_encrypt_t tweak_fn = c->spec->encrypt;
  gcry_cipher_encrypt_t crypt_fn =
    encrypt ? c->spec->encrypt : c->spec->decrypt;
  union
  {
    cipher_context_alignment_t xcx;
    byte x1[GCRY_XTS_BLOCK_LEN];
    u64 x64[GCRY_XTS_BLOCK_LEN / sizeof(u64)];
  } tmp;
  unsigned int burn, nburn;
  size_t nblocks;

  if (c->spec->blocksize != GCRY_XTS_BLOCK_LEN)
    return GPG_ERR_CIPHER_ALGO;
  if (outbuflen < inbuflen)
    return GPG_ERR_BUFFER_TOO_SHORT;
  if (inbuflen < GCRY_XTS_BLOCK_LEN)
    return GPG_ERR_BUFFER_TOO_SHORT;

  /* Data-unit max length: 2^20 blocks. */
  if (inbuflen > GCRY_XTS_BLOCK_LEN << 20)
    return GPG_ERR_INV_LENGTH;

  nblocks = inbuflen / GCRY_XTS_BLOCK_LEN;
  nblocks -= !encrypt && (inbuflen % GCRY_XTS_BLOCK_LEN) != 0;

  /* Generate first tweak value.  */
  burn = tweak_fn (c->u_mode.xts.tweak_context, c->u_ctr.ctr, c->u_iv.iv);

  /* Use a bulk method if available.  */
  if (nblocks && c->bulk.xts_crypt)
    {
      c->bulk.xts_crypt (&c->context.c, c->u_ctr.ctr, outbuf, inbuf, nblocks,
			 encrypt);
      inbuf  += nblocks * GCRY_XTS_BLOCK_LEN;
      outbuf += nblocks * GCRY_XTS_BLOCK_LEN;
      inbuflen -= nblocks * GCRY_XTS_BLOCK_LEN;
      nblocks = 0;
    }

  /* If we don't have a bulk method use the standard method.  We also
    use this method for the a remaining partial block.  */

  while (nblocks)
    {
      /* Xor-Encrypt/Decrypt-Xor block. */
      cipher_block_xor (tmp.x64, inbuf, c->u_ctr.ctr, GCRY_XTS_BLOCK_LEN);
      nburn = crypt_fn (&c->context.c, tmp.x1, tmp.x1);
      burn = nburn > burn ? nburn : burn;
      cipher_block_xor (outbuf, tmp.x64, c->u_ctr.ctr, GCRY_XTS_BLOCK_LEN);

      outbuf += GCRY_XTS_BLOCK_LEN;
      inbuf += GCRY_XTS_BLOCK_LEN;
      inbuflen -= GCRY_XTS_BLOCK_LEN;
      nblocks--;

      /* Generate next tweak. */
      xts_gfmul_byA (c->u_ctr.ctr, c->u_ctr.ctr);
    }

  /* Handle remaining data with ciphertext stealing. */
  if (inbuflen)
    {
      if (!encrypt)
	{
	  gcry_assert (inbuflen > GCRY_XTS_BLOCK_LEN);
	  gcry_assert (inbuflen < GCRY_XTS_BLOCK_LEN * 2);

	  /* Generate last tweak. */
	  xts_gfmul_byA (tmp.x1, c->u_ctr.ctr);

	  /* Decrypt last block first. */
	  cipher_block_xor (outbuf, inbuf, tmp.x64, GCRY_XTS_BLOCK_LEN);
	  nburn = crypt_fn (&c->context.c, outbuf, outbuf);
	  burn = nburn > burn ? nburn : burn;
	  cipher_block_xor (outbuf, outbuf, tmp.x64, GCRY_XTS_BLOCK_LEN);

	  inbuflen -= GCRY_XTS_BLOCK_LEN;
	  inbuf += GCRY_XTS_BLOCK_LEN;
	  outbuf += GCRY_XTS_BLOCK_LEN;
	}

      gcry_assert (inbuflen < GCRY_XTS_BLOCK_LEN);
      outbuf -= GCRY_XTS_BLOCK_LEN;

      /* Steal ciphertext from previous block. */
      cipher_block_cpy (tmp.x64, outbuf, GCRY_XTS_BLOCK_LEN);
      buf_cpy (tmp.x64, inbuf, inbuflen);
      buf_cpy (outbuf + GCRY_XTS_BLOCK_LEN, outbuf, inbuflen);

      /* Decrypt/Encrypt last block. */
      cipher_block_xor (tmp.x64, tmp.x64, c->u_ctr.ctr, GCRY_XTS_BLOCK_LEN);
      nburn = crypt_fn (&c->context.c, tmp.x1, tmp.x1);
      burn = nburn > burn ? nburn : burn;
      cipher_block_xor (outbuf, tmp.x64, c->u_ctr.ctr, GCRY_XTS_BLOCK_LEN);
    }

  /* Auto-increment data-unit sequence number */
  xts_inc128 (c->u_iv.iv);

  wipememory (&tmp, sizeof(tmp));
  wipememory (c->u_ctr.ctr, sizeof(c->u_ctr.ctr));

  if (burn > 0)
    _gcry_burn_stack (burn + 4 * sizeof(void *));

  return 0;
}


gcry_err_code_t
_gcry_cipher_xts_encrypt (gcry_cipher_hd_t c,
                          unsigned char *outbuf, size_t outbuflen,
                          const unsigned char *inbuf, size_t inbuflen)
{
  return _gcry_cipher_xts_crypt (c, outbuf, outbuflen, inbuf, inbuflen, 1);
}


gcry_err_code_t
_gcry_cipher_xts_decrypt (gcry_cipher_hd_t c,
                          unsigned char *outbuf, size_t outbuflen,
                          const unsigned char *inbuf, size_t inbuflen)
{
  return _gcry_cipher_xts_crypt (c, outbuf, outbuflen, inbuf, inbuflen, 0);
}


#if defined(HAVE_WOLFSSL) && defined(WOLFSSL_AES_XTS)
#include <wolfssl/wolfcrypt/error-crypt.h>

/* AES-XTS through the module (wc_AesXts*, mapped to the _fips entry
   points by wolfssl/wolfcrypt/fips.h).  As in _gcry_cipher_xts_crypt,
   each call is one data unit whose tweak is the IV, a partial last block
   is handled by ciphertext stealing, and the IV is then incremented.  */

void
_wc_cipher_aes_xts_close (gcry_cipher_hd_t c)
{
  XtsAes *x = c->u_mode.xts.wc_xts;

  wc_AesXtsFree (&x[0]);
  wc_AesXtsFree (&x[1]);
  wipememory (x, 2 * sizeof *x);
}

/* KEY is both halves, KEYLEN their total length.  */
gcry_err_code_t
_wc_cipher_aes_xts_setkey (gcry_cipher_hd_t c, const byte *key, size_t keylen)
{
  XtsAes *x = c->u_mode.xts.wc_xts;
  int ret;

  _wc_cipher_aes_xts_close (c);
  /* The module refuses equal key halves (BAD_FUNC_ARG); report them as
     libgcrypt does in FIPS mode.  */
  if (buf_eq_const (key, key + keylen / 2, keylen / 2))
    return GPG_ERR_WEAK_KEY;
  ret = wc_AesXtsSetKey (&x[0], key, keylen, AES_ENCRYPTION,
                         NULL, INVALID_DEVID);
  if (!ret)
    ret = wc_AesXtsSetKey (&x[1], key, keylen, AES_DECRYPTION,
                           NULL, INVALID_DEVID);
  if (!ret)
    return GPG_ERR_NO_ERROR;
  _wc_cipher_aes_xts_close (c);
  switch (ret)
    {
    case BAD_FUNC_ARG:
      return GPG_ERR_INV_KEYLEN;
    default:
      return GPG_ERR_NOT_OPERATIONAL;
    }
}

static gcry_err_code_t
wc_xts_crypt (gcry_cipher_hd_t c, unsigned char *outbuf, size_t outbuflen,
              const unsigned char *inbuf, size_t inbuflen, int encrypt)
{
  XtsAes *x = c->u_mode.xts.wc_xts;
  int ret;

  if (outbuflen < inbuflen)
    return GPG_ERR_BUFFER_TOO_SHORT;
  if (inbuflen < GCRY_XTS_BLOCK_LEN)
    return GPG_ERR_BUFFER_TOO_SHORT;
  /* Data-unit max length: 2^20 blocks. */
  if (inbuflen > GCRY_XTS_BLOCK_LEN << 20)
    return GPG_ERR_INV_LENGTH;

  if (encrypt)
    ret = wc_AesXtsEncrypt (&x[0], outbuf, inbuf, inbuflen,
                            c->u_iv.iv, GCRY_XTS_BLOCK_LEN);
  else
    ret = wc_AesXtsDecrypt (&x[1], outbuf, inbuf, inbuflen,
                            c->u_iv.iv, GCRY_XTS_BLOCK_LEN);
  if (ret)
    {
      wipememory (outbuf, inbuflen);
      return ret == BAD_FUNC_ARG ? GPG_ERR_INV_ARG : GPG_ERR_NOT_OPERATIONAL;
    }

  /* Auto-increment data-unit sequence number */
  xts_inc128 (c->u_iv.iv);
  return GPG_ERR_NO_ERROR;
}

gcry_err_code_t
_wc_cipher_aes_xts_encrypt (gcry_cipher_hd_t c,
                            unsigned char *outbuf, size_t outbuflen,
                            const unsigned char *inbuf, size_t inbuflen)
{
  return wc_xts_crypt (c, outbuf, outbuflen, inbuf, inbuflen, 1);
}

gcry_err_code_t
_wc_cipher_aes_xts_decrypt (gcry_cipher_hd_t c,
                            unsigned char *outbuf, size_t outbuflen,
                            const unsigned char *inbuf, size_t inbuflen)
{
  return wc_xts_crypt (c, outbuf, outbuflen, inbuf, inbuflen, 0);
}
#endif /* HAVE_WOLFSSL && WOLFSSL_AES_XTS */
