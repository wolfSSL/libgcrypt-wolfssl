/* md.c  -  message digest dispatcher
 * Copyright (C) 1998, 1999, 2002, 2003, 2006,
 *               2008 Free Software Foundation, Inc.
 * Copyright (C) 2013, 2014 g10 Code GmbH
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

#undef HAVE_WOLFSSL_D

#if defined(HAVE_WOLFSSL)
#include "wolfssl/options.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/sha3.h"
#include "wolfssl/wolfcrypt/md5.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/hash.h"
#endif /* HAVE_WOLFSSL_D */

/* This is the list of the digest implementations included in
   libgcrypt.  */
static const gcry_md_spec_t * const digest_list[] =
  {
#if USE_CRC
     &_gcry_digest_spec_crc32,
     &_gcry_digest_spec_crc32_rfc1510,
     &_gcry_digest_spec_crc24_rfc2440,
#endif
#if USE_SHA1
     &_gcry_digest_spec_sha1,
#endif
#if USE_SHA256
     &_gcry_digest_spec_sha256,
     &_gcry_digest_spec_sha224,
#endif
#if USE_SHA512
     &_gcry_digest_spec_sha512,
     &_gcry_digest_spec_sha384,
     &_gcry_digest_spec_sha512_256,
     &_gcry_digest_spec_sha512_224,
#endif
#if USE_SHA3
     &_gcry_digest_spec_sha3_224,
     &_gcry_digest_spec_sha3_256,
     &_gcry_digest_spec_sha3_384,
     &_gcry_digest_spec_sha3_512,
     &_gcry_digest_spec_shake128,
     &_gcry_digest_spec_shake256,
     &_gcry_digest_spec_cshake128,
     &_gcry_digest_spec_cshake256,
#endif
#if USE_GOST_R_3411_94
     &_gcry_digest_spec_gost3411_94,
     &_gcry_digest_spec_gost3411_cp,
#endif
#if USE_GOST_R_3411_12
     &_gcry_digest_spec_stribog_256,
     &_gcry_digest_spec_stribog_512,
#endif
#if USE_WHIRLPOOL
     &_gcry_digest_spec_whirlpool,
#endif
#if USE_RMD160
     &_gcry_digest_spec_rmd160,
#endif
#if USE_TIGER
     &_gcry_digest_spec_tiger,
     &_gcry_digest_spec_tiger1,
     &_gcry_digest_spec_tiger2,
#endif
#if USE_MD5
     &_gcry_digest_spec_md5,
#endif
#if USE_MD4
     &_gcry_digest_spec_md4,
#endif
#if USE_MD2
     &_gcry_digest_spec_md2,
#endif
#if USE_BLAKE2
     &_gcry_digest_spec_blake2b_512,
     &_gcry_digest_spec_blake2b_384,
     &_gcry_digest_spec_blake2b_256,
     &_gcry_digest_spec_blake2b_160,
     &_gcry_digest_spec_blake2s_256,
     &_gcry_digest_spec_blake2s_224,
     &_gcry_digest_spec_blake2s_160,
     &_gcry_digest_spec_blake2s_128,
#endif
#if USE_SM3
     &_gcry_digest_spec_sm3,
#endif
     NULL
  };

/* Digest implementations starting with index 0 (enum gcry_md_algos) */
static const gcry_md_spec_t * const digest_list_algo0[] =
  {
    NULL, /* GCRY_MD_NONE */
#if USE_MD5
    &_gcry_digest_spec_md5,
#else
    NULL,
#endif
#if USE_SHA1
    &_gcry_digest_spec_sha1,
#else
    NULL,
#endif
#if USE_RMD160
    &_gcry_digest_spec_rmd160,
#else
    NULL,
#endif
    NULL, /* Unused index 4 */
#if USE_MD2
    &_gcry_digest_spec_md2,
#else
    NULL,
#endif
#if USE_TIGER
    &_gcry_digest_spec_tiger,
#else
    NULL,
#endif
    NULL, /* GCRY_MD_HAVAL */
#if USE_SHA256
    &_gcry_digest_spec_sha256,
#else
    NULL,
#endif
#if USE_SHA512
    &_gcry_digest_spec_sha384,
    &_gcry_digest_spec_sha512,
#else
    NULL,
    NULL,
#endif
#if USE_SHA256
    &_gcry_digest_spec_sha224
#else
    NULL
#endif
  };

/* Digest implementations starting with index 301 (enum gcry_md_algos) */
static const gcry_md_spec_t * const digest_list_algo301[] =
  {
#if USE_MD4
    &_gcry_digest_spec_md4,
#else
    NULL,
#endif
#if USE_CRC
    &_gcry_digest_spec_crc32,
    &_gcry_digest_spec_crc32_rfc1510,
    &_gcry_digest_spec_crc24_rfc2440,
#else
    NULL,
    NULL,
    NULL,
#endif
#if USE_WHIRLPOOL
    &_gcry_digest_spec_whirlpool,
#else
    NULL,
#endif
#if USE_TIGER
    &_gcry_digest_spec_tiger1,
    &_gcry_digest_spec_tiger2,
#else
    NULL,
    NULL,
#endif
#if USE_GOST_R_3411_94
    &_gcry_digest_spec_gost3411_94,
#else
    NULL,
#endif
#if USE_GOST_R_3411_12
    &_gcry_digest_spec_stribog_256,
    &_gcry_digest_spec_stribog_512,
#else
    NULL,
    NULL,
#endif
#if USE_GOST_R_3411_94
    &_gcry_digest_spec_gost3411_cp,
#else
    NULL,
#endif
#if USE_SHA3
    &_gcry_digest_spec_sha3_224,
    &_gcry_digest_spec_sha3_256,
    &_gcry_digest_spec_sha3_384,
    &_gcry_digest_spec_sha3_512,
    &_gcry_digest_spec_shake128,
    &_gcry_digest_spec_shake256,
#else
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
#endif
#if USE_BLAKE2
    &_gcry_digest_spec_blake2b_512,
    &_gcry_digest_spec_blake2b_384,
    &_gcry_digest_spec_blake2b_256,
    &_gcry_digest_spec_blake2b_160,
    &_gcry_digest_spec_blake2s_256,
    &_gcry_digest_spec_blake2s_224,
    &_gcry_digest_spec_blake2s_160,
    &_gcry_digest_spec_blake2s_128,
#else
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
#endif
#if USE_SM3
    &_gcry_digest_spec_sm3,
#else
    NULL,
#endif
#if USE_SHA512
    &_gcry_digest_spec_sha512_256,
    &_gcry_digest_spec_sha512_224,
#else
    NULL,
    NULL,
#endif
#if USE_SHA3
    &_gcry_digest_spec_cshake128,
    &_gcry_digest_spec_cshake256
#else
    NULL,
    NULL
#endif
  };


typedef struct gcry_md_list
{
  const gcry_md_spec_t *spec;
  struct gcry_md_list *next;
  size_t actual_struct_size;     /* Allocated size of this structure. */
  PROPERLY_ALIGNED_TYPE context[1];
} GcryDigestEntry;

/* This structure is put right after the gcry_md_hd_t buffer, so that
 * only one memory block is needed. */
struct gcry_md_context
{
  int  magic;
  struct {
    unsigned int secure:1;
    unsigned int finalized:1;
    unsigned int bugemu1:1;
    unsigned int hmac:1;
  } flags;
  size_t actual_handle_size;     /* Allocated size of this handle. */
  FILE  *debug;
  GcryDigestEntry *list;
};


#define CTX_MAGIC_NORMAL 0x11071961
#define CTX_MAGIC_SECURE 0x16917011

static gcry_err_code_t md_enable (gcry_md_hd_t hd, int algo);
static void md_close (gcry_md_hd_t a);
static void md_write (gcry_md_hd_t a, const void *inbuf, size_t inlen);
static byte *md_read( gcry_md_hd_t a, int algo );
static int md_get_algo( gcry_md_hd_t a );
static int md_digest_length( int algo );
static void md_start_debug ( gcry_md_hd_t a, const char *suffix );
static void md_stop_debug ( gcry_md_hd_t a );



static int
map_algo (int algo)
{
  return algo;
}

/* Some utility functions for wolfSSL */
/* These functions are used to map libgcrypt hmac to wolfSSL hmac */
#if defined(HAVE_WOLFSSL_D)
static int
map_algo_to_wc_algo (int algo)
{
  /* Map libgcrypt digest to wolfSSL digest for HMAC */
  switch (algo) {
    case GCRY_MD_SHA1:
      return WC_HASH_TYPE_SHA;
    case GCRY_MD_SHA224:
      return WC_HASH_TYPE_SHA224;
    case GCRY_MD_SHA256:
      return WC_HASH_TYPE_SHA256;
    case GCRY_MD_SHA384:
      return WC_HASH_TYPE_SHA384;
    case GCRY_MD_SHA512:
      return WC_HASH_TYPE_SHA512;
#ifdef WC_HASH_TYPE_SHA3_224
    case GCRY_MD_SHA3_224:
      return WC_HASH_TYPE_SHA3_224;
#endif
#ifdef WC_HASH_TYPE_SHA3_256
    case GCRY_MD_SHA3_256:
      return WC_HASH_TYPE_SHA3_256;
#endif
#ifdef WC_HASH_TYPE_SHA3_384
    case GCRY_MD_SHA3_384:
      return WC_HASH_TYPE_SHA3_384;
#endif
#ifdef WC_HASH_TYPE_SHA3_512
    case GCRY_MD_SHA3_512:
      return WC_HASH_TYPE_SHA3_512;
#endif
    default:
      return WC_HASH_TYPE_NONE;
  }
}


static int
wc_get_digest_size(int wc_algo)
{
  switch (wc_algo) {
    case WC_HASH_TYPE_SHA:
      return WC_SHA_DIGEST_SIZE;
    case WC_HASH_TYPE_SHA256:
      return WC_SHA256_DIGEST_SIZE;
    case WC_HASH_TYPE_SHA384:
      return WC_SHA384_DIGEST_SIZE;
    case WC_HASH_TYPE_SHA512:
      return WC_SHA512_DIGEST_SIZE;
    case WC_HASH_TYPE_SHA224:
      return WC_SHA224_DIGEST_SIZE;
    case WC_HASH_TYPE_SHA3_224:
      return WC_SHA3_224_DIGEST_SIZE;
    case WC_HASH_TYPE_SHA3_256:
      return WC_SHA3_256_DIGEST_SIZE;
    case WC_HASH_TYPE_SHA3_384:
      return WC_SHA3_384_DIGEST_SIZE;
    case WC_HASH_TYPE_SHA3_512:
      return WC_SHA3_512_DIGEST_SIZE;
    case WC_HASH_TYPE_MD5:
      return WC_MD5_DIGEST_SIZE;
    default:
      /* Default to a safe size if unknown */
      return 64;
  }
}

/* Check if wolfSSL supports the digest */
/* 0 for not supported, 1 for supported */
static int
wc_is_digest_supported(int* wc_algo)
{
  if (wc_algo == NULL) {
    /* If the algo is not set, return 0 */
    return 0;
  }
  switch (*wc_algo) {
    case WC_HASH_TYPE_SHA:
    case WC_HASH_TYPE_SHA256:
    case WC_HASH_TYPE_SHA384:
    case WC_HASH_TYPE_SHA512:
    case WC_HASH_TYPE_SHA224:
    case WC_HASH_TYPE_SHA3_224:
    case WC_HASH_TYPE_SHA3_384:
    case WC_HASH_TYPE_SHA3_512:
      return 1;
    default:
      return 0;
  }
}

static int
wc_Hmac_copy(Hmac *dst, Hmac *src, int wc_algo)
{
  switch (wc_algo) {
    case WC_SHA:
      return wc_ShaCopy((wc_Sha *)&(src->hash), (wc_Sha *)&(dst->hash));
    case WC_SHA224:
      return wc_Sha224Copy((wc_Sha224 *)&(src->hash), (wc_Sha224 *) &(dst->hash));
    case WC_SHA256:
      return wc_Sha256Copy((wc_Sha256 *)&(src->hash), (wc_Sha256 *) &(dst->hash));
    case WC_SHA384:
      return wc_Sha384Copy((wc_Sha384 *)&(src->hash), (wc_Sha384 *) &(dst->hash));
    case WC_SHA512:
      return wc_Sha512Copy((wc_Sha512 *)&(src->hash), (wc_Sha512 *) &(dst->hash));
    case WC_SHA3_224:
      return wc_Sha3_224_Copy((wc_Sha3*)&(src->hash), (wc_Sha3*) &(dst->hash));
    case WC_SHA3_256:
      return wc_Sha3_256_Copy((wc_Sha3*)&(src->hash), (wc_Sha3*) &(dst->hash));
    case WC_SHA3_384:
      return wc_Sha3_384_Copy((wc_Sha3*)&(src->hash), (wc_Sha3*) &(dst->hash));
    case WC_SHA3_512:
      return wc_Sha3_512_Copy((wc_Sha3*)&(src->hash), (wc_Sha3*) &(dst->hash));
    default:
      return -1;
  }
}

static int
_gcry_wc_md_open (gcry_md_hd_t hd, int algo, unsigned int flags)
{
  int rc = 0;
  int wc_algo;

  /* Initialize wolfSSL fields to NULL */
  hd->wc_Hmac_ptr = NULL;
  hd->wc_algo_ptr = NULL;
  hd->final_digest = NULL;

  /* If HMAC flag is set and algorithm is supported by wolfSSL, set up HMAC */
  if (flags & GCRY_MD_FLAG_HMAC) {
    /* Map libgcrypt digest to wolfSSL digest for HMAC */
    wc_algo = map_algo_to_wc_algo(algo);

    if (wc_is_digest_supported(&wc_algo)) {
      /* Initialize the HMAC structure */
      rc = wc_HmacInit(&(hd->wc_Hmac), NULL, 0);
      if (rc != 0) {
        /* Failed to initialize HMAC */
        printf("Error libgcrypt (md_open): wc_HmacInit failed\n");
        printf("Return: %d\n", rc);
        md_close(hd);
        return GPG_ERR_INTERNAL;
      }

      /* Allocate memory for algorithm ID */
      hd->wc_algo_ptr = (int*)XMALLOC(sizeof(int), NULL, DYNAMIC_TYPE_TMP_BUFFER);
      if (hd->wc_algo_ptr == NULL) {
        /* Memory allocation failed */
        wc_HmacFree(&(hd->wc_Hmac));
        md_close(hd);
        return GPG_ERR_ENOMEM;
      }

      /* Store the algorithm ID */
      *(hd->wc_algo_ptr) = wc_algo;

      /* Allocate memory for the digest */
      int digest_size = WC_MAX_DIGEST_SIZE;

      /* Ensure we have a valid digest size */
      if (digest_size <= 0) {
        XFREE(hd->wc_algo_ptr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        wc_HmacFree(&(hd->wc_Hmac));
        md_close(hd);
        return GPG_ERR_INTERNAL;
      }

      hd->final_digest = (byte *)XMALLOC(digest_size, NULL, DYNAMIC_TYPE_TMP_BUFFER);
      if (hd->final_digest == NULL) {
        /* Memory allocation failed */
        XFREE(hd->wc_algo_ptr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        wc_HmacFree(&(hd->wc_Hmac));
        md_close(hd);
        return GPG_ERR_ENOMEM;
      }

      /* Set up the HMAC pointer */
      hd->wc_Hmac_ptr = &hd->wc_Hmac;
    }
  }

  return 0;
}





static int
_gcry_wc_md_copy (gcry_md_hd_t ahd, gcry_md_hd_t bhd)
{
  int err = 0;

  /* Initialize wolfSSL fields to NULL first */
  bhd->wc_Hmac_ptr = NULL;
  bhd->wc_algo_ptr = NULL;
  bhd->final_digest = NULL;

  /* Deep copy wolfSSL fields if they exist in the source */
  if (ahd->wc_algo_ptr != NULL) {
    /* Copy algorithm information */
    bhd->wc_algo_ptr = (int *)XMALLOC(sizeof(int), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!bhd->wc_algo_ptr) {
      err = gpg_err_code_from_syserror();
      md_close(bhd);
      return err;
    }

    /* Copy the algorithm value */
    memcpy(bhd->wc_algo_ptr, ahd->wc_algo_ptr, sizeof(int));

    /* Initialize the new HMAC structure */
    int hmac_rc = wc_HmacInit(&(bhd->wc_Hmac), NULL, 0);
    if (hmac_rc != 0) {
      XFREE(bhd->wc_algo_ptr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
      bhd->wc_algo_ptr = NULL;
      err = GPG_ERR_INTERNAL;
      md_close(bhd);
      return err;
    }

    /* Set the HMAC_ptr to point to the newly initialized HMAC structure */
    bhd->wc_Hmac_ptr = &(bhd->wc_Hmac);

    /* Copy the HMAC type */
    memcpy(bhd->wc_Hmac_ptr->ipad, ahd->wc_Hmac_ptr->ipad, sizeof(bhd->wc_Hmac_ptr->ipad));
    memcpy(bhd->wc_Hmac_ptr->opad, ahd->wc_Hmac_ptr->opad, sizeof(bhd->wc_Hmac_ptr->opad));
    memcpy(bhd->wc_Hmac_ptr->innerHash, ahd->wc_Hmac_ptr->innerHash, sizeof(bhd->wc_Hmac_ptr->innerHash));
    bhd->wc_Hmac_ptr->innerHashKeyed = ahd->wc_Hmac_ptr->innerHashKeyed;
    bhd->wc_Hmac_ptr->macType = ahd->wc_Hmac_ptr->macType;

    if (wc_Hmac_copy(&(bhd->wc_Hmac), &(ahd->wc_Hmac), *(ahd->wc_algo_ptr)) != 0) {
      wc_HmacFree(bhd->wc_Hmac_ptr);
      XFREE(bhd->wc_algo_ptr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
      bhd->wc_algo_ptr = NULL;
      err = GPG_ERR_INTERNAL;
      md_close(bhd);
      return err;
    }

    /* Create a new buffer for the final digest */
    if (ahd->final_digest != NULL) {
      int digest_size = wc_get_digest_size(*(bhd->wc_algo_ptr));
      /* Double-check that we have a valid size */
      if (digest_size <= 0) {
        wc_HmacFree(bhd->wc_Hmac_ptr);
        XFREE(bhd->wc_algo_ptr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        bhd->wc_algo_ptr = NULL;
        err = GPG_ERR_INTERNAL;
        md_close(bhd);
        return err;
      }

      bhd->final_digest = (byte *)XMALLOC(digest_size, NULL, DYNAMIC_TYPE_TMP_BUFFER);
      if (!bhd->final_digest) {
        wc_HmacFree(bhd->wc_Hmac_ptr);
        XFREE(bhd->wc_algo_ptr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        bhd->wc_algo_ptr = NULL;
        err = gpg_err_code_from_syserror();
        md_close(bhd);
        return err;
      }

      memcpy(bhd->final_digest, ahd->final_digest, digest_size);
    }
  }

  return 0;
}

static void
_gcry_wc_md_close (gcry_md_hd_t a)
{
  if (a == NULL)
    return;

  /* Properly cleanup wolfSSL HMAC resources */
  if (a->wc_Hmac_ptr != NULL) {
    /* Only free HMAC if it's been initialized */
    wc_HmacFree(a->wc_Hmac_ptr);
    a->wc_Hmac_ptr = NULL;
  }

  if (a->final_digest != NULL) {
    XFREE(a->final_digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    a->final_digest = NULL;
  }

  if (a->wc_algo_ptr != NULL) {
    XFREE(a->wc_algo_ptr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    a->wc_algo_ptr = NULL;
  }
}

static int
_gcry_wc_md_write (gcry_md_hd_t hd, const void *inbuf, size_t inlen)
{
  /* Check if this is a wolfSSL HMAC operation */
  if (hd->wc_algo_ptr != NULL && hd->wc_Hmac_ptr != NULL) {
    /* Use wc_is_digest_supported which safely checks for NULL and algorithm type */
    if (wc_is_digest_supported(hd->wc_algo_ptr)) {
      int rc = wc_HmacUpdate(hd->wc_Hmac_ptr, inbuf, inlen);
      if (rc != 0) {
        /* Log error but continue to fallback path */
        printf("Error in _gcry_md_write: wc_HmacUpdate failed with %d\n", rc);
        return rc;
      }

      /* Successfully processed data with wolfSSL */
      return 0;
    }
  }

  /* Return a code that indicates to use the fallback path */
  return -1;
}



/* Set the key for a wolfSSL HMAC operation.
   Returns 0 on success or a gcry_err_code_t on failure. */
static gcry_err_code_t
_gcry_wc_md_setkey (gcry_md_hd_t hd, const void *key, size_t keylen)
{
  int rc;

  /* Check if this is a wolfSSL HMAC operation */
  if (hd->wc_algo_ptr == NULL || hd->wc_Hmac_ptr == NULL)
    return -1;  /* Not a wolfSSL handle */

  /* Use wc_is_digest_supported which safely checks for algorithm type */
  if (!wc_is_digest_supported(hd->wc_algo_ptr))
    return -1;  /* Algorithm not supported by wolfSSL */

  /* Set the key for the HMAC operation */
  rc = wc_HmacSetKey(hd->wc_Hmac_ptr, *(hd->wc_algo_ptr), key, keylen);
  if (rc != 0) {
    printf("Error libgcrypt (_gcry_wc_md_setkey): wc_HmacSetKey failed with %d\n", rc);
    return GPG_ERR_INTERNAL;
  }

  return 0; /* Success */
}




/* Read the final digest from a wolfSSL HMAC operation.
   Returns pointer to the digest on success or NULL on failure. */
static byte *
_gcry_wc_md_read (gcry_md_hd_t hd, int algo)
{
  (void)algo; /* Not used - wolfSSL handles the algorithm internally */

  /* Check if this is a wolfSSL HMAC operation */
  if (hd->wc_algo_ptr == NULL || hd->wc_Hmac_ptr == NULL || hd->final_digest == NULL)
    return NULL;  /* Not a wolfSSL handle */

  /* Use wc_is_digest_supported which safely checks for algorithm type */
  if (!wc_is_digest_supported(hd->wc_algo_ptr))
    return NULL;  /* Algorithm not supported by wolfSSL */

  /* Compute the HMAC final digest */
  int rc = wc_HmacFinal(hd->wc_Hmac_ptr, hd->final_digest);
  if (rc != 0) {
    /* Log error but continue to fallback path */
    printf("Error in _gcry_wc_md_read: wc_HmacFinal failed with %d\n", rc);
    return NULL;
  }

  /* Return the computed digest */
  return hd->final_digest;
}


#endif

/* Return the spec structure for the hash algorithm ALGO.  For an
   unknown algorithm NULL is returned.  */
static const gcry_md_spec_t *
spec_from_algo (int algo)
{
  const gcry_md_spec_t *spec = NULL;

  algo = map_algo (algo);

  if (algo >= 0 && algo < DIM(digest_list_algo0))
    spec = digest_list_algo0[algo];
  else if (algo >= 301 && algo < 301 + DIM(digest_list_algo301))
    spec = digest_list_algo301[algo - 301];

  if (spec)
    gcry_assert (spec->algo == algo);

  return spec;
}


/* Lookup a hash's spec by its name.  */
static const gcry_md_spec_t *
spec_from_name (const char *name)
{
  const gcry_md_spec_t *spec;
  int idx;

  for (idx=0; (spec = digest_list[idx]); idx++)
    {
      if (!stricmp (name, spec->name))
        return spec;
    }

  return NULL;
}


/* Lookup a hash's spec by its OID.  */
static const gcry_md_spec_t *
spec_from_oid (const char *oid)
{
  const gcry_md_spec_t *spec;
  const gcry_md_oid_spec_t *oid_specs;
  int idx, j;

  for (idx=0; (spec = digest_list[idx]); idx++)
    {
      oid_specs = spec->oids;
      if (oid_specs)
        {
          for (j = 0; oid_specs[j].oidstring; j++)
            if (!stricmp (oid, oid_specs[j].oidstring))
              return spec;
        }
    }

  return NULL;
}


static const gcry_md_spec_t *
search_oid (const char *oid, gcry_md_oid_spec_t *oid_spec)
{
  const gcry_md_spec_t *spec;
  int i;

  if (!oid)
    return NULL;

  if (!strncmp (oid, "oid.", 4) || !strncmp (oid, "OID.", 4))
    oid += 4;

  spec = spec_from_oid (oid);
  if (spec && spec->oids)
    {
      for (i = 0; spec->oids[i].oidstring; i++)
	if (!stricmp (oid, spec->oids[i].oidstring))
	  {
	    if (oid_spec)
	      *oid_spec = spec->oids[i];
	    return spec;
	  }
    }

  return NULL;
}


/****************
 * Map a string to the digest algo
 */
int
_gcry_md_map_name (const char *string)
{
  const gcry_md_spec_t *spec;

  if (!string)
    return 0;

  /* If the string starts with a digit (optionally prefixed with
     either "OID." or "oid."), we first look into our table of ASN.1
     object identifiers to figure out the algorithm */
  spec = search_oid (string, NULL);
  if (spec)
    return spec->algo;

  /* Not found, search a matching digest name.  */
  spec = spec_from_name (string);
  if (spec)
    return spec->algo;

  return 0;
}


/****************
 * This function simply returns the name of the algorithm or some constant
 * string when there is no algo.  It will never return NULL.
 * Use	the macro gcry_md_test_algo() to check whether the algorithm
 * is valid.
 */
const char *
_gcry_md_algo_name (int algorithm)
{
  const gcry_md_spec_t *spec;

  spec = spec_from_algo (algorithm);
  return spec ? spec->name : "?";
}


static gcry_err_code_t
check_digest_algo (int algorithm)
{
  const gcry_md_spec_t *spec;

  spec = spec_from_algo (algorithm);
  if (spec && !spec->flags.disabled && (spec->flags.fips || !fips_mode ()))
    return 0;

  return GPG_ERR_DIGEST_ALGO;

}


/****************
 * Open a message digest handle for use with algorithm ALGO.
 * More algorithms may be added by md_enable(). The initial algorithm
 * may be 0.
 */
static gcry_err_code_t
md_open (gcry_md_hd_t *h, int algo, unsigned int flags)
{
  gcry_err_code_t err = 0;
  int secure = !!(flags & GCRY_MD_FLAG_SECURE);
  int hmac =   !!(flags & GCRY_MD_FLAG_HMAC);
  int bufsize = secure ? 512 : 1024;
  gcry_md_hd_t hd;
  size_t n;

  /* Allocate a memory area to hold the caller visible buffer with it's
   * control information and the data required by this module. Set the
   * context pointer at the beginning to this area.
   * We have to use this strange scheme because we want to hide the
   * internal data but have a variable sized buffer.
   *
   *	+---+------+---........------+-------------+
   *	!ctx! bctl !  buffer	     ! private	   !
   *	+---+------+---........------+-------------+
   *	  !			      ^
   *	  !---------------------------!
   *
   * We have to make sure that private is well aligned.
   */
  n = offsetof (struct gcry_md_handle, buf) + bufsize;
  n = ((n + sizeof (PROPERLY_ALIGNED_TYPE) - 1)
       / sizeof (PROPERLY_ALIGNED_TYPE)) * sizeof (PROPERLY_ALIGNED_TYPE);

  /* Allocate and set the Context pointer to the private data */
  if (secure)
    hd = xtrymalloc_secure (n + sizeof (struct gcry_md_context));
  else
    hd = xtrymalloc (n + sizeof (struct gcry_md_context));

  if (! hd)
    err = gpg_err_code_from_errno (errno);

  if (! err)
    {
      struct gcry_md_context *ctx;

      ctx = (void *) (hd->buf - offsetof (struct gcry_md_handle, buf) + n);
      /* Setup the globally visible data (bctl in the diagram).*/
      hd->ctx = ctx;
      hd->bufsize = n - offsetof (struct gcry_md_handle, buf);
      hd->bufpos = 0;

      /* Initialize the private data. */
      wipememory2 (ctx, 0, sizeof *ctx);
      ctx->magic = secure ? CTX_MAGIC_SECURE : CTX_MAGIC_NORMAL;
      ctx->actual_handle_size = n + sizeof (struct gcry_md_context);
      ctx->flags.secure = secure;
      ctx->flags.hmac = hmac;
      ctx->flags.bugemu1 = !!(flags & GCRY_MD_FLAG_BUGEMU1);
    }

  if (! err)
    {
      /* Hmmm, should we really do that? - yes [-wk] */
      _gcry_fast_random_poll ();

      if (algo)
	{
	  err = md_enable (hd, algo);
	  if (err)
	    md_close (hd);
	}
    }

  if (! err)
    *h = hd;

  return err;
}

/* Create a message digest object for algorithm ALGO.  FLAGS may be
   given as an bitwise OR of the gcry_md_flags values.  ALGO may be
   given as 0 if the algorithms to be used are later set using
   gcry_md_enable. H is guaranteed to be a valid handle or NULL on
   error.  */
gcry_err_code_t
_gcry_md_open (gcry_md_hd_t *h, int algo, unsigned int flags)
{
  gcry_err_code_t rc;
  gcry_md_hd_t hd;

  if ((flags & ~(GCRY_MD_FLAG_SECURE
                 | GCRY_MD_FLAG_HMAC
                 | GCRY_MD_FLAG_BUGEMU1)))
    rc = GPG_ERR_INV_ARG;
  else {
    /* This allocates the memory for the handle and the context */
    rc = md_open (&hd, algo, flags);
    if (rc == 0) {
#if defined(HAVE_WOLFSSL_D)
      int wc_rc = _gcry_wc_md_open(hd, algo, flags);
      if (wc_rc != 0) {
        rc = wc_rc;
      }
#endif
    }
  }

  *h = rc? NULL : hd;
  return rc;
}



static gcry_err_code_t
md_enable (gcry_md_hd_t hd, int algorithm)
{
  struct gcry_md_context *h = hd->ctx;
  const gcry_md_spec_t *spec;
  GcryDigestEntry *entry;
  gcry_err_code_t err = 0;

  for (entry = h->list; entry; entry = entry->next)
    if (entry->spec->algo == algorithm)
      return 0; /* Already enabled */

  spec = spec_from_algo (algorithm);
  if (!spec)
    {
      log_debug ("md_enable: algorithm %d not available\n", algorithm);
      err = GPG_ERR_DIGEST_ALGO;
    }

  if (!err && spec->flags.disabled)
    err = GPG_ERR_DIGEST_ALGO;

  /* Any non-FIPS algorithm should go this way */
  if (!err && !spec->flags.fips && fips_mode ())
    err = GPG_ERR_DIGEST_ALGO;

  if (!err && h->flags.hmac && spec->read == NULL)
    {
      /* Expandable output function cannot act as part of HMAC. */
      err = GPG_ERR_DIGEST_ALGO;
    }

  if (!err)
    {
      size_t size = (sizeof (*entry)
                     + spec->contextsize * (h->flags.hmac? 3 : 1)
                     - sizeof (entry->context));

      /* And allocate a new list entry. */
      if (h->flags.secure)
	entry = xtrymalloc_secure (size);
      else
	entry = xtrymalloc (size);

      if (! entry)
	err = gpg_err_code_from_errno (errno);
      else
	{
	  entry->spec = spec;
	  entry->next = h->list;
          entry->actual_struct_size = size;
	  h->list = entry;

	  /* And init this instance. */
	  entry->spec->init (entry->context,
                             h->flags.bugemu1? GCRY_MD_FLAG_BUGEMU1:0);
	}
    }

  return err;
}


gcry_err_code_t
_gcry_md_enable (gcry_md_hd_t hd, int algorithm)
{
  return md_enable (hd, algorithm);
}


static gcry_err_code_t
md_copy (gcry_md_hd_t ahd, gcry_md_hd_t *b_hd)
{
  gcry_err_code_t err = 0;
  struct gcry_md_context *a = ahd->ctx;
  struct gcry_md_context *b;
  GcryDigestEntry *ar, *br;
  gcry_md_hd_t bhd;
  size_t n;

  if (ahd->bufpos)
    md_write (ahd, NULL, 0);

  n = (char *) ahd->ctx - (char *) ahd;
  if (a->flags.secure)
    bhd = xtrymalloc_secure (n + sizeof (struct gcry_md_context));
  else
    bhd = xtrymalloc (n + sizeof (struct gcry_md_context));

  if (!bhd)
    {
      err = gpg_err_code_from_syserror ();
      goto leave;
    }

  bhd->ctx = b = (void *) ((char *) bhd + n);
  /* No need to copy the buffer due to the write above. */
  gcry_assert (ahd->bufsize == (n - offsetof (struct gcry_md_handle, buf)));
  bhd->bufsize = ahd->bufsize;
  bhd->bufpos = 0;
  gcry_assert (! ahd->bufpos);
  memcpy (b, a, sizeof *a);
  b->list = NULL;
  b->debug = NULL;

#if defined(HAVE_WOLFSSL_D)
  /* Use the dedicated function for wolfSSL copy */
  int wc_result = _gcry_wc_md_copy(ahd, bhd);
  if (wc_result != 0) {
    err = wc_result;
    goto leave;
  }
#endif

  /* Copy the complete list of algorithms.  The copied list is
     reversed, but that doesn't matter. */
  for (ar = a->list; ar; ar = ar->next)
    {
      if (a->flags.secure)
        br = xtrymalloc_secure (ar->actual_struct_size);
      else
        br = xtrymalloc (ar->actual_struct_size);
      if (!br)
        {
          err = gpg_err_code_from_syserror ();
          md_close (bhd);
          goto leave;
        }

      memcpy (br, ar, ar->actual_struct_size);
      br->next = b->list;
      b->list = br;
    }

  if (a->debug)
    md_start_debug (bhd, "unknown");

  *b_hd = bhd;

 leave:
  return err;
}


gcry_err_code_t
_gcry_md_copy (gcry_md_hd_t *handle, gcry_md_hd_t hd)
{
  gcry_err_code_t rc;

  rc = md_copy (hd, handle);
  if (rc)
    *handle = NULL;
  return rc;
}


/*
 * Reset all contexts and discard any buffered stuff.  This may be used
 * instead of a md_close(); md_open().
 */
void
_gcry_md_reset (gcry_md_hd_t a)
{
  GcryDigestEntry *r;

  /* Note: We allow this even in fips non operational mode.  */

  a->bufpos = a->ctx->flags.finalized = 0;

  if (a->ctx->flags.hmac)
    for (r = a->ctx->list; r; r = r->next)
      {
        memcpy (r->context, (char *)r->context + r->spec->contextsize,
                r->spec->contextsize);
      }
  else
    for (r = a->ctx->list; r; r = r->next)
      {
        memset (r->context, 0, r->spec->contextsize);
        (*r->spec->init) (r->context,
                          a->ctx->flags.bugemu1? GCRY_MD_FLAG_BUGEMU1:0);
      }
}


static void
md_close (gcry_md_hd_t a)
{
  GcryDigestEntry *r, *r2;

  if (! a)
    return;
#if defined(HAVE_WOLFSSL_D)
  /* Use dedicated function for wolfSSL cleanup */
  _gcry_wc_md_close(a);
#endif
  if (a->ctx->debug)
    md_stop_debug (a);
  for (r = a->ctx->list; r; r = r2)
    {
      r2 = r->next;
      wipememory (r, r->actual_struct_size);
      xfree (r);
    }

  wipememory (a, a->ctx->actual_handle_size);
  xfree(a);
}


void
_gcry_md_close (gcry_md_hd_t hd)
{
  /* Note: We allow this even in fips non operational mode.  */
  md_close (hd);
}


static void
md_write (gcry_md_hd_t a, const void *inbuf, size_t inlen)
{
  GcryDigestEntry *r;

  if (a->ctx->debug)
    {
      if (a->bufpos && fwrite (a->buf, a->bufpos, 1, a->ctx->debug) != 1)
	BUG();
      if (inlen && fwrite (inbuf, inlen, 1, a->ctx->debug) != 1)
	BUG();
    }

  for (r = a->ctx->list; r; r = r->next)
    {
      if (a->bufpos)
	(*r->spec->write) (r->context, a->buf, a->bufpos);
      (*r->spec->write) (r->context, inbuf, inlen);
    }
  a->bufpos = 0;
}


/* Note that this function may be used after finalize and read to keep
   on writing to the transform function so to mitigate timing
   attacks.  */
void
_gcry_md_write (gcry_md_hd_t hd, const void *inbuf, size_t inlen)
{
#if defined(HAVE_WOLFSSL_D)
  /* Try wolfSSL implementation first */
  int wc_result = _gcry_wc_md_write(hd, inbuf, inlen);
  if (wc_result == 0) {
    /* Successfully handled by wolfSSL */
    return;
  }
#endif
  /* Default path using libgcrypt's native implementation */
    md_write (hd, inbuf, inlen);
}

static void
md_final (gcry_md_hd_t a)
{
  GcryDigestEntry *r;

  if (a->ctx->flags.finalized)
    return;

  if (a->bufpos)
    md_write (a, NULL, 0);

  for (r = a->ctx->list; r; r = r->next)
    (*r->spec->final) (r->context);

  a->ctx->flags.finalized = 1;

  if (!a->ctx->flags.hmac)
    return;

  for (r = a->ctx->list; r; r = r->next)
    {
      byte *p;
      size_t dlen = r->spec->mdlen;
      byte *hash;
      gcry_err_code_t err;

      if (r->spec->read == NULL)
        continue;

      p = r->spec->read (r->context);

      if (a->ctx->flags.secure)
        hash = xtrymalloc_secure (dlen);
      else
        hash = xtrymalloc (dlen);
      if (!hash)
        {
          err = gpg_err_code_from_errno (errno);
          _gcry_fatal_error (err, NULL);
        }

      memcpy (hash, p, dlen);
      memcpy (r->context, (char *)r->context + r->spec->contextsize * 2,
              r->spec->contextsize);
      (*r->spec->write) (r->context, hash, dlen);
      (*r->spec->final) (r->context);
      xfree (hash);
    }
}


static gcry_err_code_t
md_setkey (gcry_md_hd_t h, const unsigned char *key, size_t keylen)
{
  gcry_err_code_t rc = 0;
  GcryDigestEntry *r;
  int algo_had_setkey = 0;

  if (!h->ctx->list)
    return GPG_ERR_DIGEST_ALGO; /* Might happen if no algo is enabled.  */

  if (h->ctx->flags.hmac)
    return GPG_ERR_DIGEST_ALGO; /* Tried md_setkey for HMAC md. */

  for (r = h->ctx->list; r; r = r->next)
    {
      switch (r->spec->algo)
	{
#if USE_BLAKE2
	/* TODO? add spec->init_with_key? */
	case GCRY_MD_BLAKE2B_512:
	case GCRY_MD_BLAKE2B_384:
	case GCRY_MD_BLAKE2B_256:
	case GCRY_MD_BLAKE2B_160:
	case GCRY_MD_BLAKE2S_256:
	case GCRY_MD_BLAKE2S_224:
	case GCRY_MD_BLAKE2S_160:
	case GCRY_MD_BLAKE2S_128:
	  algo_had_setkey = 1;
	  memset (r->context, 0, r->spec->contextsize);
	  rc = _gcry_blake2_init_with_key (r->context,
					   h->ctx->flags.bugemu1
					     ? GCRY_MD_FLAG_BUGEMU1:0,
					   key, keylen, r->spec->algo);
	  break;
#endif
	default:
	  rc = GPG_ERR_DIGEST_ALGO;
	  break;
	}

      if (rc)
	break;
    }

  if (rc && !algo_had_setkey)
    {
      /* None of algorithms had setkey implementation, so contexts were not
       * modified. Just return error. */
      return rc;
    }
  else if (rc && algo_had_setkey)
    {
      /* Some of the contexts have been modified, but got error. Reset
       * all contexts. */
      _gcry_md_reset (h);
      return rc;
    }

  /* Successful md_setkey implies reset. */
  h->bufpos = h->ctx->flags.finalized = 0;

  return 0;
}


static gcry_err_code_t
prepare_macpads (gcry_md_hd_t a, const unsigned char *key, size_t keylen)
{
  GcryDigestEntry *r;

  if (!a->ctx->list)
    return GPG_ERR_DIGEST_ALGO; /* Might happen if no algo is enabled.  */

  if (!a->ctx->flags.hmac)
    return GPG_ERR_DIGEST_ALGO; /* Tried prepare_macpads for non-HMAC md. */

  for (r = a->ctx->list; r; r = r->next)
    {
      const unsigned char *k;
      size_t k_len;
      unsigned char *key_allocated = NULL;
      int macpad_Bsize;
      int i;

      switch (r->spec->algo)
        {
	/* TODO: add spec->blocksize */
        case GCRY_MD_SHA3_224:
          macpad_Bsize = 1152 / 8;
          break;
        case GCRY_MD_SHA3_256:
          macpad_Bsize = 1088 / 8;
          break;
        case GCRY_MD_SHA3_384:
          macpad_Bsize = 832 / 8;
          break;
        case GCRY_MD_SHA3_512:
          macpad_Bsize = 576 / 8;
          break;
        case GCRY_MD_SHA384:
        case GCRY_MD_SHA512:
        case GCRY_MD_SHA512_256:
        case GCRY_MD_SHA512_224:
        case GCRY_MD_BLAKE2B_512:
        case GCRY_MD_BLAKE2B_384:
        case GCRY_MD_BLAKE2B_256:
        case GCRY_MD_BLAKE2B_160:
          macpad_Bsize = 128;
          break;
        case GCRY_MD_GOSTR3411_94:
        case GCRY_MD_GOSTR3411_CP:
          macpad_Bsize = 32;
          break;
        default:
          macpad_Bsize = 64;
          break;
        }

      if ( keylen > macpad_Bsize )
        {
          k = key_allocated = xtrymalloc_secure (r->spec->mdlen);
          if (!k)
            return gpg_err_code_from_errno (errno);
          _gcry_md_hash_buffer (r->spec->algo, key_allocated, key, keylen);
          k_len = r->spec->mdlen;
          gcry_assert ( k_len <= macpad_Bsize );
        }
      else
        {
          k = key;
          k_len = keylen;
        }

      (*r->spec->init) (r->context,
                        a->ctx->flags.bugemu1? GCRY_MD_FLAG_BUGEMU1:0);
      a->bufpos = 0;
      for (i=0; i < k_len; i++ )
        _gcry_md_putc (a, k[i] ^ 0x36);
      for (; i < macpad_Bsize; i++ )
        _gcry_md_putc (a, 0x36);
      (*r->spec->write) (r->context, a->buf, a->bufpos);
      memcpy ((char *)r->context + r->spec->contextsize, r->context,
              r->spec->contextsize);

      (*r->spec->init) (r->context,
                        a->ctx->flags.bugemu1? GCRY_MD_FLAG_BUGEMU1:0);
      a->bufpos = 0;
      for (i=0; i < k_len; i++ )
        _gcry_md_putc (a, k[i] ^ 0x5c);
      for (; i < macpad_Bsize; i++ )
        _gcry_md_putc (a, 0x5c);
      (*r->spec->write) (r->context, a->buf, a->bufpos);
      memcpy ((char *)r->context + r->spec->contextsize*2, r->context,
              r->spec->contextsize);

      xfree (key_allocated);
    }

  a->bufpos = 0;
  return 0;
}


static gcry_err_code_t
md_customize (gcry_md_hd_t h, void *buffer, size_t buflen)
{
  gcry_err_code_t rc = 0;
  GcryDigestEntry *r;
  int algo_had_customize = 0;

  if (!h->ctx->list)
    return GPG_ERR_DIGEST_ALGO; /* Might happen if no algo is enabled.  */

  for (r = h->ctx->list; r; r = r->next)
    {
      switch (r->spec->algo)
        {
        case GCRY_MD_CSHAKE128:
        case GCRY_MD_CSHAKE256:
          algo_had_customize = 1;
          if (buflen != sizeof (struct gcry_cshake_customization))
            rc = GPG_ERR_INV_ARG;
          else
            rc = _gcry_cshake_customize (r->context, buffer);
          break;
        default:
          rc = GPG_ERR_DIGEST_ALGO;
          break;
        }

      if (rc)
        break;
    }

  if (rc && !algo_had_customize)
    {
      /* None of algorithms had customize implementation, so contexts were not
       * modified. Just return error. */
      return rc;
    }
  else if (rc && algo_had_customize)
    {
      /* Some of the contexts have been modified, but got error. Reset
       * all contexts. */
      _gcry_md_reset (h);
      return rc;
    }

  return 0;
}


gcry_err_code_t
_gcry_md_ctl (gcry_md_hd_t hd, int cmd, void *buffer, size_t buflen)
{
  gcry_err_code_t rc = 0;

  (void)buflen; /* Currently not used.  */

  switch (cmd)
    {
    case GCRYCTL_FINALIZE:
      md_final (hd);
      break;
    case GCRYCTL_START_DUMP:
      md_start_debug (hd, buffer);
      break;
    case GCRYCTL_STOP_DUMP:
      md_stop_debug ( hd );
      break;
    case GCRYCTL_MD_CUSTOMIZE:
      rc = md_customize (hd, buffer, buflen);
      break;
    default:
      rc = GPG_ERR_INV_OP;
    }
  return rc;
}


gcry_err_code_t
_gcry_md_setkey (gcry_md_hd_t hd, const void *key, size_t keylen)
{
  gcry_err_code_t rc;

#if defined(HAVE_WOLFSSL_D)
  /* Try wolfSSL implementation first */
  rc = _gcry_wc_md_setkey(hd, key, keylen);
  if (rc == 0) {
    /* Successfully handled by wolfSSL */
    return 0;
  }
  else if (rc != -1) {
    /* An actual error occurred in the wolfSSL function */
    return rc;
  }
  /* Otherwise (-1) fall through to the default implementation */
#endif

  /* Default path using libgcrypt's native implementation */
  if (hd->ctx->flags.hmac)
    {
      rc = prepare_macpads(hd, key, keylen);
      if (!rc)
	_gcry_md_reset (hd);
    }
  else
    {
      rc = md_setkey (hd, key, keylen);
    }

  return rc;
}


/* The new debug interface.  If SUFFIX is a string it creates an debug
   file for the context HD.  IF suffix is NULL, the file is closed and
   debugging is stopped.  */
void
_gcry_md_debug (gcry_md_hd_t hd, const char *suffix)
{
  if (suffix)
    md_start_debug (hd, suffix);
  else
    md_stop_debug (hd);
}


/****************
 * If ALGO is null get the digest for the used algo (which should be
 * only one)
 */
static byte *
md_read( gcry_md_hd_t a, int algo )
{
  GcryDigestEntry *r = a->ctx->list;

  if (! algo)
    {
      /* Return the first algorithm */
      if (r)
        {
          if (r->next)
            log_debug ("more than one algorithm in md_read(0)\n");
          if (r->spec->read)
            return r->spec->read (r->context);
        }
    }
  else
    {
      for (r = a->ctx->list; r; r = r->next)
	if (r->spec->algo == algo)
	  {
	    if (r->spec->read)
              return r->spec->read (r->context);
            break;
	  }
    }

  if (r && !r->spec->read)
    _gcry_fatal_error (GPG_ERR_DIGEST_ALGO,
                       "requested algo has no fixed digest length");
  else
    _gcry_fatal_error (GPG_ERR_DIGEST_ALGO, "requested algo not in md context");
  return NULL;
}


/*
 * Read out the complete digest, this function implictly finalizes
 * the hash.
 */
byte *
_gcry_md_read (gcry_md_hd_t hd, int algo)
{
  /* This function is expected to always return a digest, thus we
     can't return an error which we actually should do in
     non-operational state.  */
#if defined(HAVE_WOLFSSL_D)
  /* Try wolfSSL implementation first */
  byte *digest = _gcry_wc_md_read(hd, algo);
  if (digest != NULL) {
    /* Successfully handled by wolfSSL */
    return digest;
  }
  /* Otherwise fall through to the default implementation */
#endif
  /* Default path using libgcrypt's native implementation */
  _gcry_md_ctl (hd, GCRYCTL_FINALIZE, NULL, 0);
  return md_read (hd, algo);
}


/****************
 * If ALGO is null get the digest for the used algo (which should be
 * only one)
 */
static gcry_err_code_t
md_extract(gcry_md_hd_t a, int algo, void *out, size_t outlen)
{
  GcryDigestEntry *r = a->ctx->list;

  if (!algo)
    {
      /* Return the first algorithm */
      if (r && r->spec->extract)
	{
	  if (r->next)
	    log_debug ("more than one algorithm in md_extract(0)\n");

	  return r->spec->extract (r->context, out, outlen);
	}
    }
  else
    {
      for (r = a->ctx->list; r; r = r->next)
	if (r->spec->algo == algo && r->spec->extract)
	  {
	    return r->spec->extract (r->context, out, outlen);
	  }
    }

  return GPG_ERR_DIGEST_ALGO;
}


/*
 * Expand the output from XOF class digest, this function implictly finalizes
 * the hash.
 */
gcry_err_code_t
_gcry_md_extract (gcry_md_hd_t hd, int algo, void *out, size_t outlen)
{
  _gcry_md_ctl (hd, GCRYCTL_FINALIZE, NULL, 0);
  return md_extract (hd, algo, out, outlen);
}


/*
 * Read out an intermediate digest.  Not yet functional.
 */
gcry_err_code_t
_gcry_md_get (gcry_md_hd_t hd, int algo, byte *buffer, int buflen)
{
  (void)hd;
  (void)algo;
  (void)buffer;
  (void)buflen;

  /*md_digest ... */
  fips_signal_error ("unimplemented function called");
  return GPG_ERR_INTERNAL;
}


/*
 * Shortcut function to hash a buffer with a given algo. The only
 * guaranteed supported algorithms are RIPE-MD160 and SHA-1. The
 * supplied digest buffer must be large enough to store the resulting
 * hash.  No error is returned, the function will abort on an invalid
 * algo.  DISABLED_ALGOS are ignored here.  */
void
_gcry_md_hash_buffer (int algo, void *digest,
                      const void *buffer, size_t length)
{
  const gcry_md_spec_t *spec;

  spec = spec_from_algo (algo);
  if (!spec)
    {
      log_debug ("md_hash_buffer: algorithm %d not available\n", algo);
      return;
    }

  if (spec->hash_buffers != NULL)
    {
      gcry_buffer_t iov;

      iov.size = 0;
      iov.data = (void *)buffer;
      iov.off = 0;
      iov.len = length;

      if (spec->flags.disabled || (!spec->flags.fips && fips_mode ()))
        log_bug ("gcry_md_hash_buffer failed for algo %d: %s",
                algo, gpg_strerror (gcry_error (GPG_ERR_DIGEST_ALGO)));

      spec->hash_buffers (digest, spec->mdlen, &iov, 1);
    }
  else
    {
      /* For the others we do not have a fast function, so we use the
         normal functions. */
      gcry_md_hd_t h;
      gpg_err_code_t err;

      err = md_open (&h, algo, 0);
      if (err)
        log_bug ("gcry_md_open failed for algo %d: %s",
                algo, gpg_strerror (gcry_error(err)));
      md_write (h, (byte *) buffer, length);
      md_final (h);
      memcpy (digest, md_read (h, algo), md_digest_length (algo));
      md_close (h);
    }
}


/* Shortcut function to hash multiple buffers with a given algo.  In
   contrast to gcry_md_hash_buffer, this function returns an error on
   invalid arguments or on other problems; disabled algorithms are
   _not_ ignored but flagged as an error.

   The data to sign is taken from the array IOV which has IOVCNT items.

   The only supported flag in FLAGS is GCRY_MD_FLAG_HMAC which turns
   this function into a HMAC function; the first item in IOV is then
   used as the key.

   On success 0 is returned and resulting hash or HMAC is stored at
   DIGEST. DIGESTLEN may be given as -1, in which case DIGEST must
   have been provided by the caller with an appropriate length.
   DIGESTLEN may also be the appropriate length or, in case of XOF
   algorithms, DIGESTLEN indicates number bytes to extract from XOF
   to DIGEST.  */
gpg_err_code_t
_gcry_md_hash_buffers_extract (int algo, unsigned int flags, void *digest,
			       int digestlen, const gcry_buffer_t *iov,
			       int iovcnt)
{
  const gcry_md_spec_t *spec;
  int is_xof;
  int hmac;

  if (!iov || iovcnt < 0)
    return GPG_ERR_INV_ARG;
  if (flags & ~(GCRY_MD_FLAG_HMAC))
    return GPG_ERR_INV_ARG;

  hmac = !!(flags & GCRY_MD_FLAG_HMAC);
  if (hmac && iovcnt < 1)
    return GPG_ERR_INV_ARG;

  spec = spec_from_algo (algo);
  if (!spec)
    {
      log_debug ("md_hash_buffers: algorithm %d not available\n", algo);
      return GPG_ERR_DIGEST_ALGO;
    }

  is_xof = spec->extract != NULL;
  if (!is_xof && digestlen != -1 && digestlen != spec->mdlen)
    return GPG_ERR_DIGEST_ALGO;

  if (digestlen == -1)
    digestlen = spec->mdlen;

  if (!hmac && spec->hash_buffers)
    {
      if (spec->flags.disabled || (!spec->flags.fips && fips_mode ()))
        return GPG_ERR_DIGEST_ALGO;

      spec->hash_buffers (digest, digestlen, iov, iovcnt);
    }
  else
    {
      /* For the others we do not have a fast function, so we use the
         normal functions.  */
      gcry_md_hd_t h;
      gpg_err_code_t rc;

      rc = md_open (&h, algo, (hmac? GCRY_MD_FLAG_HMAC:0));
      if (rc)
        return rc;

      if (hmac)
        {
          rc = _gcry_md_setkey (h,
                                (const char*)iov[0].data + iov[0].off,
                                iov[0].len);
          if (rc)
            {
              md_close (h);
              return rc;
            }
          iov++; iovcnt--;
        }
      for (;iovcnt; iov++, iovcnt--)
        md_write (h, (const char*)iov[0].data + iov[0].off, iov[0].len);
      md_final (h);
      if (digestlen == spec->mdlen)
	memcpy (digest, md_read (h, algo), spec->mdlen);
      else if (digestlen > 0)
	md_extract (h, algo, digest, digestlen);
      md_close (h);
    }

  return 0;
}


/* Shortcut function to hash multiple buffers with a given algo.  In
   contrast to gcry_md_hash_buffer, this function returns an error on
   invalid arguments or on other problems; disabled algorithms are
   _not_ ignored but flagged as an error.

   The data to sign is taken from the array IOV which has IOVCNT items.

   The only supported flag in FLAGS is GCRY_MD_FLAG_HMAC which turns
   this function into a HMAC function; the first item in IOV is then
   used as the key.

   On success 0 is returned and resulting hash or HMAC is stored at
   DIGEST which must have been provided by the caller with an
   appropriate length.  */
gpg_err_code_t
_gcry_md_hash_buffers (int algo, unsigned int flags, void *digest,
		       const gcry_buffer_t *iov, int iovcnt)
{
  return _gcry_md_hash_buffers_extract(algo, flags, digest, -1, iov, iovcnt);
}


static int
md_get_algo (gcry_md_hd_t a)
{
  GcryDigestEntry *r = a->ctx->list;

  if (r && r->next)
    {
      fips_signal_error ("possible usage error");
      log_error ("WARNING: more than one algorithm in md_get_algo()\n");
    }
  return r ? r->spec->algo : 0;
}


int
_gcry_md_get_algo (gcry_md_hd_t hd)
{
  return md_get_algo (hd);
}


/****************
 * Return the length of the digest
 */
static int
md_digest_length (int algorithm)
{
  const gcry_md_spec_t *spec;

  spec = spec_from_algo (algorithm);
  return spec? spec->mdlen : 0;
}


/****************
 * Return the length of the digest in bytes.
 * This function will return 0 in case of errors.
 */
unsigned int
_gcry_md_get_algo_dlen (int algorithm)
{
  return md_digest_length (algorithm);
}


/* Hmmm: add a mode to enumerate the OIDs
 *	to make g10/sig-check.c more portable */
static const byte *
md_asn_oid (int algorithm, size_t *asnlen, size_t *mdlen)
{
  const gcry_md_spec_t *spec;
  const byte *asnoid = NULL;

  spec = spec_from_algo (algorithm);
  if (spec)
    {
      if (asnlen)
	*asnlen = spec->asnlen;
      if (mdlen)
	*mdlen = spec->mdlen;
      asnoid = spec->asnoid;
    }
  else
    log_bug ("no ASN.1 OID for md algo %d\n", algorithm);

  return asnoid;
}


/****************
 * Return information about the given cipher algorithm
 * WHAT select the kind of information returned:
 *  GCRYCTL_TEST_ALGO:
 *	Returns 0 when the specified algorithm is available for use.
 *	buffer and nbytes must be zero.
 *  GCRYCTL_GET_ASNOID:
 *	Return the ASNOID of the algorithm in buffer. if buffer is NULL, only
 *	the required length is returned.
 *  GCRYCTL_SELFTEST
 *      Helper for the regression tests - shall not be used by applications.
 *
 * Note:  Because this function is in most cases used to return an
 * integer value, we can make it easier for the caller to just look at
 * the return value.  The caller will in all cases consult the value
 * and thereby detecting whether a error occurred or not (i.e. while checking
 * the block size)
 */
gcry_err_code_t
_gcry_md_algo_info (int algo, int what, void *buffer, size_t *nbytes)
{
  gcry_err_code_t rc;

  switch (what)
    {
    case GCRYCTL_TEST_ALGO:
      if (buffer || nbytes)
	rc = GPG_ERR_INV_ARG;
      else
	rc = check_digest_algo (algo);
      break;

    case GCRYCTL_GET_ASNOID:
      /* We need to check that the algo is available because
         md_asn_oid would otherwise raise an assertion. */
      rc = check_digest_algo (algo);
      if (!rc)
        {
          const char unsigned *asn;
          size_t asnlen;

          asn = md_asn_oid (algo, &asnlen, NULL);
          if (buffer && (*nbytes >= asnlen))
            {
              memcpy (buffer, asn, asnlen);
              *nbytes = asnlen;
            }
          else if (!buffer && nbytes)
            *nbytes = asnlen;
          else
            {
              if (buffer)
                rc = GPG_ERR_TOO_SHORT;
              else
                rc = GPG_ERR_INV_ARG;
            }
        }
      break;

    case GCRYCTL_SELFTEST:
      /* Helper function for the regression tests.  */
      rc = gpg_err_code (_gcry_md_selftest (algo, nbytes? (int)*nbytes : 0,
                                             NULL));
      break;

    default:
      rc = GPG_ERR_INV_OP;
      break;
    }

  return rc;
}


static void
md_start_debug ( gcry_md_hd_t md, const char *suffix )
{
  static int idx=0;
  char buf[50];

  if (fips_mode ())
    return;

  if ( md->ctx->debug )
    {
      log_debug("Oops: md debug already started\n");
      return;
    }
  idx++;
  snprintf (buf, DIM(buf)-1, "dbgmd-%05d.%.10s", idx, suffix );
  md->ctx->debug = fopen(buf, "w");
  if ( !md->ctx->debug )
    log_debug("md debug: can't open %s\n", buf );
}


static void
md_stop_debug( gcry_md_hd_t md )
{
  if ( md->ctx->debug )
    {
      if ( md->bufpos )
        md_write ( md, NULL, 0 );
      fclose (md->ctx->debug);
      md->ctx->debug = NULL;
    }

  {  /* a kludge to pull in the __muldi3 for Solaris */
    volatile u32 a = (u32)(uintptr_t)md;
    volatile u64 b = 42;
    volatile u64 c;
    c = a * b;
    (void)c;
  }
}



/*
 * Return information about the digest handle.
 *  GCRYCTL_IS_SECURE:
 *	Returns 1 when the handle works on secured memory
 *	otherwise 0 is returned.  There is no error return.
 *  GCRYCTL_IS_ALGO_ENABLED:
 *     Returns 1 if the algo is enabled for that handle.
 *     The algo must be passed as the address of an int.
 */
gcry_err_code_t
_gcry_md_info (gcry_md_hd_t h, int cmd, void *buffer, size_t *nbytes)
{
  gcry_err_code_t rc = 0;

  switch (cmd)
    {
    case GCRYCTL_IS_SECURE:
      *nbytes = h->ctx->flags.secure;
      break;

    case GCRYCTL_IS_ALGO_ENABLED:
      {
	GcryDigestEntry *r;
	int algo;

	if ( !buffer || !nbytes || *nbytes != sizeof (int))
	  rc = GPG_ERR_INV_ARG;
	else
	  {
	    algo = *(int*)buffer;

	    *nbytes = 0;
	    for(r=h->ctx->list; r; r = r->next ) {
	      if (r->spec->algo == algo)
		{
		  *nbytes = 1;
		  break;
		}
	    }
	  }
	break;
      }

  default:
    rc = GPG_ERR_INV_OP;
  }

  return rc;
}


/* Explicitly initialize this module.  */
gcry_err_code_t
_gcry_md_init (void)
{
  return 0;
}


int
_gcry_md_is_secure (gcry_md_hd_t a)
{
  size_t value;

  if (_gcry_md_info (a, GCRYCTL_IS_SECURE, NULL, &value))
    value = 1; /* It seems to be better to assume secure memory on
                  error. */
  return value;
}


int
_gcry_md_is_enabled (gcry_md_hd_t a, int algo)
{
  size_t value;

  value = sizeof algo;
  if (_gcry_md_info (a, GCRYCTL_IS_ALGO_ENABLED, &algo, &value))
    value = 0;
  return value;
}


/* Run the selftests for digest algorithm ALGO with optional reporting
   function REPORT.  */
gpg_error_t
_gcry_md_selftest (int algo, int extended, selftest_report_func_t report)
{
  gcry_err_code_t ec = 0;
  const gcry_md_spec_t *spec;

  spec = spec_from_algo (algo);
  if (spec && !spec->flags.disabled
      && (spec->flags.fips || !fips_mode ())
      && spec->selftest)
    ec = spec->selftest (algo, extended, report);
  else
    {
      ec = (spec && spec->selftest) ? GPG_ERR_DIGEST_ALGO
        /* */                       : GPG_ERR_NOT_IMPLEMENTED;
      if (report)
        report ("digest", algo, "module",
                spec && !spec->flags.disabled
                && (spec->flags.fips || !fips_mode ())?
                "no selftest available" :
                spec? "algorithm disabled" : "algorithm not found");
    }

  return gpg_error (ec);
}
