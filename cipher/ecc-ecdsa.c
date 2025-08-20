/* ecc-ecdsa.c  -  Elliptic Curve ECDSA signatures
 * Copyright (C) 2007, 2008, 2010, 2011 Free Software Foundation, Inc.
 * Copyright (C) 2013 g10 Code GmbH
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
#include "mpi.h"
#include "cipher.h"
#include "context.h"
#include "ec-context.h"
#include "pubkey-internal.h"
#include "ecc-common.h"

#ifdef HAVE_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/dsa.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/integer.h>
#endif

/* Compute an ECDSA signature.
 * Return the signature struct (r,s) from the message hash.  The caller
 * must have allocated R and S.
 */

#ifndef HAVE_WOLFSSL
gpg_err_code_t
_gcry_ecc_ecdsa_sign (gcry_mpi_t input, gcry_mpi_t k_supplied, mpi_ec_t ec,
                      gcry_mpi_t r, gcry_mpi_t s,
                      int flags, int hashalgo)
{
  gpg_err_code_t rc = 0;
  int extraloops = 0;
  gcry_mpi_t k, dr, sum, k_1, x;
  mpi_point_struct I;
  gcry_mpi_t hash;
  const void *abuf;
  unsigned int abits, qbits;
  gcry_mpi_t b;                /* Random number needed for blinding.  */
  gcry_mpi_t bi;               /* multiplicative inverse of B.        */
  gcry_mpi_t hash_computed_internally = NULL;

  if (DBG_CIPHER)
    log_mpidump ("ecdsa sign hash  ", input );

  qbits = mpi_get_nbits (ec->n);

  if ((flags & PUBKEY_FLAG_PREHASH))
    {
      rc = _gcry_dsa_compute_hash (&hash_computed_internally, input, hashalgo);
      if (rc)
        return rc;
      input = hash_computed_internally;
    }

  /* Convert the INPUT into an MPI if needed.  */
  rc = _gcry_dsa_normalize_hash (input, &hash, qbits);

  if (rc)
    {
      mpi_free (hash_computed_internally);
      return rc;
    }

  b  = mpi_snew (qbits);
  bi = mpi_snew (qbits);
  do
    {
      _gcry_mpi_randomize (b, qbits, GCRY_WEAK_RANDOM);
      mpi_mod (b, b, ec->n);
    }
  while (!mpi_invm (bi, b, ec->n));

  k = NULL;
  dr = mpi_alloc (0);
  sum = mpi_alloc (0);
  k_1 = mpi_alloc (0);
  x = mpi_alloc (0);
  point_init (&I);

  /* Two loops to avoid R or S are zero.  This is more of a joke than
     a real demand because the probability of them being zero is less
     than any hardware failure.  Some specs however require it.  */
  while (1)
    {
      while (1)
        {
          if (k_supplied)
            k = k_supplied;
          else
            {
              mpi_free (k);
              k = NULL;
              if ((flags & PUBKEY_FLAG_RFC6979) && hashalgo)
                {
                  if (fips_mode () &&
                      (hashalgo == GCRY_MD_SHAKE128
                       || hashalgo == GCRY_MD_SHAKE256))
                    {
                      rc = GPG_ERR_DIGEST_ALGO;
                      goto leave;
                    }

                  /* Use Pornin's method for deterministic DSA.  If this
                     flag is set, it is expected that HASH is an opaque
                     MPI with the to be signed hash.  That hash is also
                     used as h1 from 3.2.a.  */
                  if (!mpi_is_opaque (input))
                    {
                      rc = GPG_ERR_CONFLICT;
                      goto leave;
                    }

                  abuf = mpi_get_opaque (input, &abits);
                  rc = _gcry_dsa_gen_rfc6979_k (&k, ec->n, ec->d,
                                                abuf, (abits+7)/8,
                                                hashalgo, extraloops);
                  if (rc)
                    goto leave;
                  extraloops++;
                }
              else
                k = _gcry_dsa_gen_k (ec->n, GCRY_STRONG_RANDOM);
            }

          mpi_invm (k_1, k, ec->n);     /* k_1 = k^(-1) mod n  */

          _gcry_dsa_modify_k (k, ec->n, qbits);

          _gcry_mpi_ec_mul_point (&I, k, ec->G, ec);
          if (_gcry_mpi_ec_get_affine (x, NULL, &I, ec))
            {
              if (DBG_CIPHER)
                log_debug ("ecc sign: Failed to get affine coordinates\n");
              rc = GPG_ERR_BAD_SIGNATURE;
              goto leave;
            }
          mpi_mod (r, x, ec->n);  /* r = x mod n */

          if (mpi_cmp_ui (r, 0))
            break;

          if (k_supplied)
            {
              rc = GPG_ERR_INV_VALUE;
              goto leave;
            }
        }

      /* Computation of dr, sum, and s are blinded with b.  */
      mpi_mulm (dr, b, ec->d, ec->n);
      mpi_mulm (dr, dr, r, ec->n);      /* dr = d*r mod n */
      mpi_mulm (sum, b, hash, ec->n);
      mpi_addm (sum, sum, dr, ec->n);   /* sum = hash + (d*r) mod n */
      mpi_mulm (s, k_1, sum, ec->n);    /* s = k^(-1)*(hash+(d*r)) mod n */
      /* Undo blinding by b^-1 */
      mpi_mulm (s, bi, s, ec->n);
      if (mpi_cmp_ui (s, 0))
        break;

      if (k_supplied)
        {
          rc = GPG_ERR_INV_VALUE;
          break;
        }
    }

  if (DBG_CIPHER)
    {
      log_mpidump ("ecdsa sign result r ", r);
      log_mpidump ("ecdsa sign result s ", s);
    }

 leave:
  mpi_free (b);
  mpi_free (bi);
  point_free (&I);
  mpi_free (x);
  mpi_free (k_1);
  mpi_free (sum);
  mpi_free (dr);
  if (!k_supplied)
    mpi_free (k);

  if (hash != input)
    mpi_free (hash);
  mpi_free (hash_computed_internally);

  return rc;
}


/* Verify an ECDSA signature.
 * Check if R and S verifies INPUT.
 */
gpg_err_code_t
_gcry_ecc_ecdsa_verify (gcry_mpi_t input, mpi_ec_t ec,
                        gcry_mpi_t r, gcry_mpi_t s, int flags, int hashalgo)
{
  gpg_err_code_t err = 0;
  gcry_mpi_t hash, h, h1, h2, x;
  mpi_point_struct Q, Q1, Q2;
  unsigned int nbits;
  gcry_mpi_t hash_computed_internally = NULL;

  if (!_gcry_mpi_ec_curve_point (ec->Q, ec))
    return GPG_ERR_BROKEN_PUBKEY;

  if( !(mpi_cmp_ui (r, 0) > 0 && mpi_cmp (r, ec->n) < 0) )
    return GPG_ERR_BAD_SIGNATURE; /* Assertion	0 < r < n  failed.  */
  if( !(mpi_cmp_ui (s, 0) > 0 && mpi_cmp (s, ec->n) < 0) )
    return GPG_ERR_BAD_SIGNATURE; /* Assertion	0 < s < n  failed.  */

  nbits = mpi_get_nbits (ec->n);
  if ((flags & PUBKEY_FLAG_PREHASH))
    {
      err = _gcry_dsa_compute_hash (&hash_computed_internally, input,
                                    hashalgo);
      if (err)
        return err;
      input = hash_computed_internally;
    }

  err = _gcry_dsa_normalize_hash (input, &hash, nbits);
  if (err)
    {
      mpi_free (hash_computed_internally);
      return err;
    }

  h  = mpi_alloc (0);
  h1 = mpi_alloc (0);
  h2 = mpi_alloc (0);
  x = mpi_alloc (0);
  point_init (&Q);
  point_init (&Q1);
  point_init (&Q2);

  /* h  = s^(-1) (mod n) */
  mpi_invm (h, s, ec->n);
  /* h1 = hash * s^(-1) (mod n) */
  mpi_mulm (h1, hash, h, ec->n);
  /* Q1 = [ hash * s^(-1) ]G  */
  _gcry_mpi_ec_mul_point (&Q1, h1, ec->G, ec);
  /* h2 = r * s^(-1) (mod n) */
  mpi_mulm (h2, r, h, ec->n);
  /* Q2 = [ r * s^(-1) ]Q */
  _gcry_mpi_ec_mul_point (&Q2, h2, ec->Q, ec);
  /* Q  = ([hash * s^(-1)]G) + ([r * s^(-1)]Q) */
  _gcry_mpi_ec_add_points (&Q, &Q1, &Q2, ec);

  if (!mpi_cmp_ui (Q.z, 0))
    {
      if (DBG_CIPHER)
          log_debug ("ecc verify: Rejected\n");
      err = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }
  if (_gcry_mpi_ec_get_affine (x, NULL, &Q, ec))
    {
      if (DBG_CIPHER)
        log_debug ("ecc verify: Failed to get affine coordinates\n");
      err = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }
  mpi_mod (x, x, ec->n); /* x = x mod E_n */
  if (mpi_cmp (x, r))   /* x != r */
    {
      if (DBG_CIPHER)
        {
          log_mpidump ("     x", x);
          log_mpidump ("     r", r);
          log_mpidump ("     s", s);
        }
      err = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }

 leave:
  point_free (&Q2);
  point_free (&Q1);
  point_free (&Q);
  mpi_free (x);
  mpi_free (h2);
  mpi_free (h1);
  mpi_free (h);
  if (hash != input)
    mpi_free (hash);
  mpi_free (hash_computed_internally);

  return err;
}

#else
/* wolfSSL implementation */

/* wolfSSL helper files */


static int
wc_name_to_curve_id(const char *curve_name)
{
    if (curve_name == NULL)
        return ECC_CURVE_INVALID;

    /* NIST curves - check for different naming conventions */
    if (strcmp(curve_name, "NIST P-192") == 0 ||
        strcmp(curve_name, "secp192r1") == 0 ||
        strcmp(curve_name, "nistp192") == 0) {
      return ECC_SECP192R1;
    }

    if (strcmp(curve_name, "NIST P-224") == 0 ||
        strcmp(curve_name, "secp224r1") == 0 ||
        strcmp(curve_name, "nistp224") == 0) {
      return ECC_SECP224R1;
    }

    if (strcmp(curve_name, "NIST P-256") == 0 ||
        strcmp(curve_name, "secp256r1") == 0 ||
        strcmp(curve_name, "nistp256") == 0) {
      return ECC_SECP256R1;
    }

    if (strcmp(curve_name, "NIST P-384") == 0 ||
        strcmp(curve_name, "secp384r1") == 0 ||
        strcmp(curve_name, "nistp384") == 0) {
      return ECC_SECP384R1;
    }

    if (strcmp(curve_name, "NIST P-521") == 0 ||
        strcmp(curve_name, "secp521r1") == 0 ||
        strcmp(curve_name, "nistp521") == 0) {
      return ECC_SECP521R1;
    }

    return ECC_CURVE_INVALID;
}



/* Way to convert wolfSSL mpi to libgcrypt mpi */
static int
_wc_mpi_to_libgcrypt_mpi(mp_int *wc_mpi, gcry_mpi_t gcry_mpi)
{
  int ret = 0;

  /* Temp Buffer for conversion */
  word32 mpi_len = 0;
  byte* mpi_bin = NULL;

  /* Temp libgcrypt mpi */
  gcry_mpi_t temp_mpi;

  ret = mp_unsigned_bin_size(wc_mpi);
  if (ret <= 0) {
    return GPG_ERR_ENOMEM;
  }
  else {
    /* cast to word32 */
    mpi_len = (word32)ret;
  }

  /* allocate memory for the temp buffer */
  mpi_bin = (byte*)XMALLOC(mpi_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
  if (mpi_bin == NULL) {
    return GPG_ERR_ENOMEM;
  }

  ret = mp_to_unsigned_bin(wc_mpi, mpi_bin);
  if (ret != 0) {
    XFREE(mpi_bin, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
  }

  /* convert the temp buffer to libgcrypt mpi */
  ret = _gcry_mpi_scan(&temp_mpi, GCRYMPI_FMT_USG, mpi_bin, mpi_len, NULL);
  if (ret != 0) {
    XFREE(mpi_bin, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
  }

  XFREE(mpi_bin, NULL, DYNAMIC_TYPE_TMP_BUFFER);

  /* Explicitly set the libgcrypt mpi to the temp mpi */
  /* to avoid and copy issues */
  _gcry_mpi_set(gcry_mpi, temp_mpi);

  /* Free the temporary MPI to prevent memory leak */
  _gcry_mpi_release(temp_mpi);

  return ret;
}

/* need to convert libgcrypt mpi to wolfSSL mpi */
/* must pass a lenght of the expected char array */
/* Can be 0 if not needed, but used for right aligning */
static int
_libgcrypt_mpi_to_wc_mpi(gcry_mpi_t gcry_mpi, mp_int *wc_mpi, word32 wc_mpi_len)
{
  int ret = 0;
  byte* mpi_bin = NULL;
  size_t mpi_bin_len = 0;
  byte* mpi_bin_rightAligned = NULL;
  word32 mpi_bin_rightAligned_len = 0;

  ret = _gcry_mpi_aprint(GCRYMPI_FMT_USG, &mpi_bin, &mpi_bin_len, gcry_mpi);
  if (ret != 0) {
    return ret;
  }

  if (wc_mpi_len > 0) {
    mpi_bin_rightAligned_len = wc_mpi_len;
    mpi_bin_rightAligned = (byte*)XMALLOC(mpi_bin_rightAligned_len, NULL,
                                            DYNAMIC_TYPE_TMP_BUFFER);
    if (mpi_bin_rightAligned == NULL) {
      _gcry_free(mpi_bin);
      return GPG_ERR_ENOMEM;
    }
    XMEMSET(mpi_bin_rightAligned, 0, mpi_bin_rightAligned_len);

    memcpy(mpi_bin_rightAligned + (mpi_bin_rightAligned_len - mpi_bin_len),
                mpi_bin, mpi_bin_len);

  }
  else {
    /* just use the original pointer */
    mpi_bin_rightAligned = mpi_bin;
    mpi_bin_rightAligned_len = mpi_bin_len;
  }


  ret = mp_read_unsigned_bin(wc_mpi, mpi_bin_rightAligned,
                                mpi_bin_rightAligned_len);

  /* Only free if we allocated the right aligned buffer */
  if (wc_mpi_len > 0 && mpi_bin_rightAligned != mpi_bin) {
    XFREE(mpi_bin_rightAligned, NULL, DYNAMIC_TYPE_TMP_BUFFER);
  }
  _gcry_free(mpi_bin);

  return ret;
}


#define WC_MAX_CURVE_SIZE (528/8) /* 528 bits = 66 bytes */
                                    /* Max Curver supported is P-521 */
                                    /* So 66 bytes is the max size */

/* Copy original function name from libgcrypt */
/* As code is called from libgcrypt and not switchable function pointers */
gpg_err_code_t
_gcry_ecc_ecdsa_sign (gcry_mpi_t input, gcry_mpi_t k_supplied, mpi_ec_t ec,
                      gcry_mpi_t r, gcry_mpi_t s,
                      int flags, int hashalgo)
{
  gpg_err_code_t rc = 0;
  int extraloops = 0;
  gcry_mpi_t k, dr, sum, k_1, x;
  mpi_point_struct I;
  gcry_mpi_t hash;
  const void *abuf;
  unsigned int abits, qbits;
  gcry_mpi_t b;                /* Random number needed for blinding.  */
  gcry_mpi_t bi;               /* multiplicative inverse of B.        */
  gcry_mpi_t hash_computed_internally = NULL;

  /* wolfSSL declarations */
  int ret;
  ecc_key wc_key;
  WC_RNG rng;
  int wolf = 0;
  ecc_curve_id wc_curve_id = ECC_CURVE_INVALID; /* no curve id */

  byte wc_D[WC_MAX_CURVE_SIZE] = {0};
  byte wc_D_rightAligned[WC_MAX_CURVE_SIZE] = {0};
  byte wc_k[WC_MAX_CURVE_SIZE] = {0};

  word32 wc_D_len = 0;
  word32 wc_D_rightAligned_len = 0;
  word32 wc_k_len = 0;
  int wc_curve_size = 0;


  mp_int wc_r_mpi;
  mp_int wc_s_mpi;

  /* wc_hash */
  /* will grab from libgcrypt */
  byte* wc_hash = NULL;
  word32 wc_hash_len = 0;
  size_t hash_buflen = 0;
  size_t k_buflen = 0;


  wc_curve_id = wc_name_to_curve_id(ec->name);
  if (wc_curve_id != ECC_CURVE_INVALID) {
    wc_curve_size = wc_ecc_get_curve_size_from_id(wc_curve_id);
  }
#if defined(ENABLED_WOLFSSL_FIPS)
  else {
    return GPG_ERR_NOT_SUPPORTED; /* Needed for FIPS mode */
  }
#endif

  if (DBG_CIPHER)
    log_mpidump ("ecdsa sign hash  ", input );

  qbits = mpi_get_nbits (ec->n);

  if ((flags & PUBKEY_FLAG_PREHASH))
    {
      rc = _gcry_dsa_compute_hash (&hash_computed_internally, input, hashalgo);
      if (rc)
        return rc;
      input = hash_computed_internally;
    }

  /* Convert the INPUT into an MPI if needed.  */
  rc = _gcry_dsa_normalize_hash (input, &hash, qbits);

  if (rc)
    {
      mpi_free (hash_computed_internally);
      return rc;
    }

  if (wc_curve_id != ECC_CURVE_INVALID) {
    wolf = 1;
    ret = wc_InitRng(&rng);
    if (ret != 0) {
      goto leave;
    }

    ret = wc_ecc_init(&wc_key);
    if (ret != 0) {
      wc_FreeRng(&rng);
      goto leave;
    }


    /* Allocate memory for the key */
    wc_D_len = (word32)wc_curve_size;
    wc_D_rightAligned_len = wc_D_len;

    /* Get Curve Parameters from libgcrypt */
    ret = _gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *)&wc_D,
                                WC_MAX_CURVE_SIZE, (size_t *)&wc_D_len, ec->d);
    if (ret != 0) {
      rc = GPG_ERR_BROKEN_PUBKEY;
      wc_ecc_free(&wc_key);
      wc_FreeRng(&rng);
      goto leave;
    }

    /* LIBGCRYPT CODE -- BEGIN: */
    /* Eventually wolfssl code will handle this */
    k = NULL;
    if (k_supplied) {
      k = k_supplied;
    }
    else
    {
      mpi_free (k);
      k = NULL;
      if ((flags & PUBKEY_FLAG_RFC6979) && hashalgo)
      {
        if (fips_mode () &&
            (hashalgo == GCRY_MD_SHAKE128
             || hashalgo == GCRY_MD_SHAKE256))
        {
          rc = GPG_ERR_DIGEST_ALGO;
          goto leave;
        }

        /* Use Pornin's method for deterministic DSA.  If this
           flag is set, it is expected that HASH is an opaque
           MPI with the to be signed hash.  That hash is also
           used as h1 from 3.2.a.  */
        if (!mpi_is_opaque (input))
        {
          rc = GPG_ERR_CONFLICT;
          goto leave;
        }

        abuf = mpi_get_opaque (input, &abits);
        rc = _gcry_dsa_gen_rfc6979_k (&k, ec->n, ec->d,
                                      abuf, (abits+7)/8,
                                      hashalgo, extraloops);
        if (rc)
          goto leave;
        extraloops++;
      }
      else {
        k = _gcry_dsa_gen_k (ec->n, GCRY_STRONG_RANDOM);
      }
    }
    /* LIBGCRYPT CODE -- END: */

  if (k != NULL) {
    k_buflen = 0;
    ret = _gcry_mpi_print(GCRYMPI_FMT_USG, wc_k, WC_MAX_CURVE_SIZE, &k_buflen, k);
    if (ret != 0) {
      rc = GPG_ERR_BROKEN_PUBKEY;
      wc_ecc_free(&wc_key);
      wc_FreeRng(&rng);
      goto leave;
    }
    wc_k_len = k_buflen;
  }
    /* Right align the key */
    /* libgcrypt wont extend to full length, so we need to do it manually */
    memcpy(wc_D_rightAligned + (wc_D_rightAligned_len - wc_D_len), wc_D, wc_D_len);

    /* Import the key into wolfSSL */
    ret = wc_ecc_import_private_key_ex(wc_D_rightAligned, wc_D_rightAligned_len,
                                        NULL, 0, &wc_key, wc_curve_id);
    if (ret != 0) {
      rc = GPG_ERR_BROKEN_PUBKEY;
      wc_ecc_free(&wc_key);
      wc_FreeRng(&rng);
      goto leave;
    }

    /* Do not need these anymore */
  if (k != NULL) {
    ret = wc_ecc_sign_set_k(wc_k, wc_k_len, &wc_key);
    if (ret != 0) {
      rc = GPG_ERR_BROKEN_PUBKEY;
      wc_ecc_free(&wc_key);
      wc_FreeRng(&rng);
      goto leave;
    }
  }
    /* Get the hash */
    /* Use _gcry_mpi_print instead of _gcry_mpi_aprint to avoid corrupting the source MPI */
    /* First call: get required buffer size */
    ret = _gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &hash_buflen, hash);
    if (ret != 0) {
      rc = GPG_ERR_BROKEN_PUBKEY;
      wc_ecc_free(&wc_key);
      wc_FreeRng(&rng);
      goto leave;
    }

    /* Allocate buffer (secure if source MPI is secure) */
    size_t alloc_size = hash_buflen ? hash_buflen : 1;
    if (mpi_is_secure(hash)) {
      wc_hash = _gcry_malloc_secure(alloc_size);
    }
    else {
      wc_hash = _gcry_malloc(alloc_size);
    }
    if (!wc_hash) {
      rc = GPG_ERR_ENOMEM;
      wc_ecc_free(&wc_key);
      wc_FreeRng(&rng);
      goto leave;
    }

    /* Second call: fill the buffer */
    ret = _gcry_mpi_print(GCRYMPI_FMT_USG, wc_hash, alloc_size, &hash_buflen, hash);
    if (ret != 0) {
      rc = GPG_ERR_BROKEN_PUBKEY;
      _gcry_free(wc_hash);
      wc_hash = NULL;
      wc_ecc_free(&wc_key);
      wc_FreeRng(&rng);
      goto leave;
    }
    wc_hash_len = hash_buflen;

    ret = mp_init(&wc_r_mpi);
    if (ret != 0) {
      rc = GPG_ERR_BROKEN_PUBKEY;
      wc_ecc_free(&wc_key);
      wc_FreeRng(&rng);
      goto leave;
    }

    ret = mp_init(&wc_s_mpi);
    if (ret != 0) {
      rc = GPG_ERR_BROKEN_PUBKEY;
      wc_ecc_free(&wc_key);
      wc_FreeRng(&rng);
      goto leave;
    }

    /* Generate the signature */
    /* Now that the key is imported, we can use the wolfSSL functions */
    ret = wc_ecc_sign_hash_ex(wc_hash, wc_hash_len,
                            &rng, &wc_key,
                            &wc_r_mpi, &wc_s_mpi);
    if (ret != 0) {
      rc = GPG_ERR_BROKEN_PUBKEY;
      wc_ecc_free(&wc_key);
      wc_FreeRng(&rng);
      mp_clear(&wc_r_mpi);
      mp_clear(&wc_s_mpi);
      goto leave;
    }

    _gcry_free (wc_hash);
    wc_FreeRng(&rng); /* dont need this anymore */
    wc_ecc_free(&wc_key); /* dont need this anymore */

    /* convert r and s to libgcrypt mpi */
    ret = _wc_mpi_to_libgcrypt_mpi(&wc_r_mpi, r);
    if (ret != 0) {
      rc = GPG_ERR_ENOMEM;
      mp_clear(&wc_r_mpi);
      mp_clear(&wc_s_mpi);
      goto leave;
    }

    ret = _wc_mpi_to_libgcrypt_mpi(&wc_s_mpi, s);
    if (ret != 0) {
      rc = GPG_ERR_ENOMEM;
      mp_clear(&wc_r_mpi);
      mp_clear(&wc_s_mpi);
      goto leave;
    }


    mp_clear(&wc_r_mpi);
    mp_clear(&wc_s_mpi);
  }
  else {
  if (rc)
    {
      mpi_free (hash_computed_internally);
      return rc;
    }

  b  = mpi_snew (qbits);
  bi = mpi_snew (qbits);
  do
    {
      _gcry_mpi_randomize (b, qbits, GCRY_WEAK_RANDOM);
      mpi_mod (b, b, ec->n);
    }
  while (!mpi_invm (bi, b, ec->n));

  k = NULL;
  dr = mpi_alloc (0);
  sum = mpi_alloc (0);
  k_1 = mpi_alloc (0);
  x = mpi_alloc (0);
  point_init (&I);

  /* Two loops to avoid R or S are zero.  This is more of a joke than
     a real demand because the probability of them being zero is less
     than any hardware failure.  Some specs however require it.  */
  while (1)
    {
      while (1)
        {
          if (k_supplied)
            k = k_supplied;
          else
            {
              mpi_free (k);
              k = NULL;
              if ((flags & PUBKEY_FLAG_RFC6979) && hashalgo)
                {
                  if (fips_mode () &&
                      (hashalgo == GCRY_MD_SHAKE128
                       || hashalgo == GCRY_MD_SHAKE256))
                    {
                      rc = GPG_ERR_DIGEST_ALGO;
                      goto leave;
                    }

                  /* Use Pornin's method for deterministic DSA.  If this
                     flag is set, it is expected that HASH is an opaque
                     MPI with the to be signed hash.  That hash is also
                     used as h1 from 3.2.a.  */
                  if (!mpi_is_opaque (input))
                    {
                      rc = GPG_ERR_CONFLICT;
                      goto leave;
                    }

                  abuf = mpi_get_opaque (input, &abits);
                  rc = _gcry_dsa_gen_rfc6979_k (&k, ec->n, ec->d,
                                                abuf, (abits+7)/8,
                                                hashalgo, extraloops);
                  if (rc)
                    goto leave;
                  extraloops++;
                }
              else
                k = _gcry_dsa_gen_k (ec->n, GCRY_STRONG_RANDOM);
            }

          mpi_invm (k_1, k, ec->n);     /* k_1 = k^(-1) mod n  */

          _gcry_dsa_modify_k (k, ec->n, qbits);

          _gcry_mpi_ec_mul_point (&I, k, ec->G, ec);
          if (_gcry_mpi_ec_get_affine (x, NULL, &I, ec))
            {
              if (DBG_CIPHER)
                log_debug ("ecc sign: Failed to get affine coordinates\n");
              rc = GPG_ERR_BAD_SIGNATURE;
              goto leave;
            }
          mpi_mod (r, x, ec->n);  /* r = x mod n */

          if (mpi_cmp_ui (r, 0))
            break;

          if (k_supplied)
            {
              rc = GPG_ERR_INV_VALUE;
              goto leave;
            }
        }

      /* Computation of dr, sum, and s are blinded with b.  */
      mpi_mulm (dr, b, ec->d, ec->n);
      mpi_mulm (dr, dr, r, ec->n);      /* dr = d*r mod n */
      mpi_mulm (sum, b, hash, ec->n);
      mpi_addm (sum, sum, dr, ec->n);   /* sum = hash + (d*r) mod n */
      mpi_mulm (s, k_1, sum, ec->n);    /* s = k^(-1)*(hash+(d*r)) mod n */
      /* Undo blinding by b^-1 */
      mpi_mulm (s, bi, s, ec->n);
      if (mpi_cmp_ui (s, 0))
        break;

      if (k_supplied)
        {
          rc = GPG_ERR_INV_VALUE;
          break;
        }
    }

  if (DBG_CIPHER)
    {
      log_mpidump ("ecdsa sign result r ", r);
      log_mpidump ("ecdsa sign result s ", s);
    }
  }

 leave:
  if (wolf != 1) {
    mpi_free (b);
    mpi_free (bi);
    point_free (&I);
    mpi_free (x);
    mpi_free (k_1);
    mpi_free (sum);
    mpi_free (dr);

  }
  if (!k_supplied)
    mpi_free (k);
  if (hash != input) {
    mpi_free (hash);
  }
  mpi_free (hash_computed_internally);
  return rc;
}


/* Verify an ECDSA signature.
 * Check if R and S verifies INPUT.
 */
gpg_err_code_t
_gcry_ecc_ecdsa_verify (gcry_mpi_t input, mpi_ec_t ec,
                        gcry_mpi_t r, gcry_mpi_t s, int flags, int hashalgo)
{
  gpg_err_code_t err = 0;
  gcry_mpi_t hash;
  unsigned int nbits;
  gcry_mpi_t hash_computed_internally = NULL;
  gcry_mpi_t h, h1, h2, x;
  mpi_point_struct Q, Q1, Q2;


  /* wolfSSL declarations */
  int ret;
  ecc_key wc_key;
  ecc_curve_id wc_curve_id = ECC_CURVE_INVALID; /* no curve id */

  byte wc_QX[WC_MAX_CURVE_SIZE] = {0};
  byte wc_QY[WC_MAX_CURVE_SIZE] = {0};
  byte wc_QX_rightAligned[WC_MAX_CURVE_SIZE] = {0};
  byte wc_QY_rightAligned[WC_MAX_CURVE_SIZE] = {0};

  word32 wc_QX_len = 0;
  word32 wc_QY_len = 0;
  word32 wc_QX_rightAligned_len = 0;
  word32 wc_QY_rightAligned_len = 0;
  word32 wc_r_rightAligned_len = 0;
  word32 wc_s_rightAligned_len = 0;

  mp_int wc_r_mpi;
  mp_int wc_s_mpi;

  int is_valid_signature = 0;
  size_t hash_buflen = 0;

  /* wc_hash */
  byte* wc_hash = NULL;
  word32 wc_hash_len = 0;
  size_t alloc_size = 0;

  wc_curve_id = wc_name_to_curve_id(ec->name);

#if defined(ENABLED_WOLFSSL_FIPS)
  if (wc_curve_id == ECC_CURVE_INVALID) {
    return GPG_ERR_NOT_SUPPORTED; /* Needed for FIPS mode */
  }
#endif

  if (!_gcry_mpi_ec_curve_point (ec->Q, ec))
    return GPG_ERR_BROKEN_PUBKEY;

  if( !(mpi_cmp_ui (r, 0) > 0 && mpi_cmp (r, ec->n) < 0) )
    return GPG_ERR_BAD_SIGNATURE; /* Assertion	0 < r < n  failed.  */
  if( !(mpi_cmp_ui (s, 0) > 0 && mpi_cmp (s, ec->n) < 0) )
    return GPG_ERR_BAD_SIGNATURE; /* Assertion	0 < s < n  failed.  */

  nbits = mpi_get_nbits (ec->n);
  if ((flags & PUBKEY_FLAG_PREHASH))
    {
      err = _gcry_dsa_compute_hash (&hash_computed_internally, input,
                                    hashalgo);
      if (err)
        return err;
      input = hash_computed_internally;
    }

  err = _gcry_dsa_normalize_hash (input, &hash, nbits);
  if (err)
    {
      mpi_free (hash_computed_internally);
      return err;
    }

  if (wc_curve_id != ECC_CURVE_INVALID) {
    ret = wc_ecc_init(&wc_key);
    if (ret != 0) {
      err = GPG_ERR_INTERNAL;
      goto leave;
    }

    /* Allocate memory for the key */
    wc_QX_len = (word32)wc_ecc_get_curve_size_from_id(wc_curve_id);
    wc_QY_len = wc_QX_len;
    wc_QX_rightAligned_len = wc_QX_len;
    wc_QY_rightAligned_len = wc_QX_len;
    wc_r_rightAligned_len = wc_QX_len;
    wc_s_rightAligned_len = wc_QX_len;


    /* Get public key coordinates from libgcrypt */
    ret = _gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *)&wc_QX, WC_MAX_CURVE_SIZE,
                                (size_t *)&wc_QX_len, ec->Q->x);
    if (ret != 0) {
      err = GPG_ERR_BROKEN_PUBKEY;
      wc_ecc_free(&wc_key);
      goto leave;
    }

    ret = _gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *)&wc_QY, WC_MAX_CURVE_SIZE,
                                (size_t *)&wc_QY_len, ec->Q->y);
    if (ret != 0) {
      err = GPG_ERR_BROKEN_PUBKEY;
      wc_ecc_free(&wc_key);
      goto leave;
    }

    /* Right align the key coordinates */
    memcpy(wc_QX_rightAligned + (wc_QX_rightAligned_len - wc_QX_len),
                wc_QX, wc_QX_len);
    memcpy(wc_QY_rightAligned + (wc_QY_rightAligned_len - wc_QY_len),
                wc_QY, wc_QY_len);

    /* Import the public key into wolfSSL */
    ret = wc_ecc_import_unsigned(&wc_key, wc_QX_rightAligned, wc_QY_rightAligned,
                                NULL, wc_curve_id);
    if (ret != 0) {
      err = GPG_ERR_BROKEN_PUBKEY;
      wc_ecc_free(&wc_key);
      goto leave;
    }

    ret = wc_ecc_set_curve(&wc_key, wc_QX_rightAligned_len, wc_curve_id);
    if (ret != 0) {
      err = GPG_ERR_BROKEN_PUBKEY;
      wc_ecc_free(&wc_key);
      goto leave;
    }

    /* Initialize the MP integers for r and s */
    ret = mp_init(&wc_r_mpi);
    if (ret != 0) {
      err = GPG_ERR_INTERNAL;
      wc_ecc_free(&wc_key);
      goto leave;
    }

    ret = mp_init(&wc_s_mpi);
    if (ret != 0) {
      err = GPG_ERR_INTERNAL;
      wc_ecc_free(&wc_key);
      mp_clear(&wc_r_mpi);
      goto leave;
    }


    ret = _libgcrypt_mpi_to_wc_mpi(r, &wc_r_mpi, wc_r_rightAligned_len);
    if (ret != 0) {
        err = GPG_ERR_INTERNAL;
        wc_ecc_free(&wc_key);
        goto leave;
    }

    ret = _libgcrypt_mpi_to_wc_mpi(s, &wc_s_mpi, wc_s_rightAligned_len);
    if (ret != 0) {
        err = GPG_ERR_INTERNAL;
        wc_ecc_free(&wc_key);
        goto leave;
    }

    /* Convert MPI to byte buffer for wolfSSL.
     * Use _gcry_mpi_print instead of _gcry_mpi_aprint to avoid corrupting the source MPI.
     * _gcry_mpi_aprint has internal behavior that makes the source MPI unsafe to free afterward,
     * causing segfaults. _gcry_mpi_print is read-only and leaves the source MPI untouched. */

    /* First call: get required buffer size */
    ret = _gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &hash_buflen, hash);
    if (ret != 0) {
      err = GPG_ERR_BROKEN_PUBKEY;
      wc_ecc_free(&wc_key);
      goto leave;
    }

    /* Allocate buffer (secure if source MPI is secure) */
    alloc_size = hash_buflen ? hash_buflen : 1;
    if (mpi_is_secure(hash)) {
      wc_hash = _gcry_malloc_secure(alloc_size);
    }
    else {
      wc_hash = _gcry_malloc(alloc_size);
    }

    if (!wc_hash) {
      err = GPG_ERR_ENOMEM;
      wc_ecc_free(&wc_key);
      goto leave;
    }

    /* Second call: extract MPI data to buffer */
    ret = _gcry_mpi_print(GCRYMPI_FMT_USG, wc_hash, hash_buflen, &hash_buflen, hash);
    if (ret != 0) {
      err = GPG_ERR_BROKEN_PUBKEY;
      _gcry_free(wc_hash);
      wc_ecc_free(&wc_key);
      goto leave;
    }
    wc_hash_len = (word32)hash_buflen;

    /* Verify the signature using wolfSSL */
    ret = wc_ecc_verify_hash_ex(&wc_r_mpi, &wc_s_mpi,
                              wc_hash, wc_hash_len,
                              &is_valid_signature, &wc_key);
    if (ret == 0 && is_valid_signature == 0) {
      err = GPG_ERR_BAD_SIGNATURE;
      wc_ecc_free(&wc_key);
      mp_clear(&wc_r_mpi);
      mp_clear(&wc_s_mpi);
      _gcry_free(wc_hash);
      goto leave;
    }
    else if (ret != 0) {
      err = GPG_ERR_INTERNAL;
      wc_ecc_free(&wc_key);
      mp_clear(&wc_r_mpi);
      mp_clear(&wc_s_mpi);
      _gcry_free(wc_hash);
      goto leave;
    }



    mp_clear(&wc_r_mpi);
    mp_clear(&wc_s_mpi);
    if (wc_hash != NULL)
      _gcry_free(wc_hash);
    wc_ecc_free(&wc_key);
  }
  else {
    /* Use libgcrypt's native implementation for verify if wolfSSL can't handle this curve */
    h  = mpi_alloc (0);
    h1 = mpi_alloc (0);
    h2 = mpi_alloc (0);
    x = mpi_alloc (0);
    point_init (&Q);
    point_init (&Q1);
    point_init (&Q2);

    /* h  = s^(-1) (mod n) */
    mpi_invm (h, s, ec->n);
    /* h1 = hash * s^(-1) (mod n) */
    mpi_mulm (h1, hash, h, ec->n);
    /* Q1 = [ hash * s^(-1) ]G  */
    _gcry_mpi_ec_mul_point (&Q1, h1, ec->G, ec);
    /* h2 = r * s^(-1) (mod n) */
    mpi_mulm (h2, r, h, ec->n);
    /* Q2 = [ r * s^(-1) ]Q */
    _gcry_mpi_ec_mul_point (&Q2, h2, ec->Q, ec);
    /* Q  = ([hash * s^(-1)]G) + ([r * s^(-1)]Q) */
    _gcry_mpi_ec_add_points (&Q, &Q1, &Q2, ec);

    if (!mpi_cmp_ui (Q.z, 0))
      {
        if (DBG_CIPHER)
            log_debug ("ecc verify: Rejected\n");
        err = GPG_ERR_BAD_SIGNATURE;
        goto native_cleanup;
      }
    if (_gcry_mpi_ec_get_affine (x, NULL, &Q, ec))
      {
        if (DBG_CIPHER)
          log_debug ("ecc verify: Failed to get affine coordinates\n");
        err = GPG_ERR_BAD_SIGNATURE;
        goto native_cleanup;
      }
    mpi_mod (x, x, ec->n); /* x = x mod E_n */
    if (mpi_cmp (x, r))   /* x != r */
      {
        if (DBG_CIPHER)
          {
            log_mpidump ("     x", x);
            log_mpidump ("     r", r);
            log_mpidump ("     s", s);
          }
        err = GPG_ERR_BAD_SIGNATURE;
      }

  native_cleanup:
    point_free (&Q2);
    point_free (&Q1);
    point_free (&Q);
    mpi_free (x);
    mpi_free (h2);
    mpi_free (h1);
    mpi_free (h);

  }
leave:
  if (hash != input) {
    mpi_free (hash);
  }
  mpi_free (hash_computed_internally);

  return err;
}

#endif
