/* wolfcrypt-cast-retry.h - re-issue a wolfCrypt call that was refused
 * while another thread runs the self-test (CAST) it needs
 * (FullLinuxFIPS-sg32).
 *
 * FIPS Ready runs most CASTs at the first use of an algorithm.  While one
 * thread runs a CAST, another thread's call that needs it is refused with
 * that CAST's *_KAT_FIPS_E code before it touches its arguments (the
 * module wrapper's AlgoAllowed() check), and the module stays NORMAL: the
 * call is safe to re-issue once the CAST is done.  A CAST that fails
 * leaves the module DEGRADED (v5.2.1 also degrades the race loser), so a
 * call is never re-issued unless wolfCrypt_GetMode_fips() is NORMAL.
 * Without HAVE_FIPS (wolfssl/options.h) nothing is retryable.
 *
 * Use, from code built with HAVE_WOLFSSL:
 *   #include "wolfcrypt-cast-retry.h"
 *   WC_CAST_RETRY (ret, wc_ShaUpdate (&sha, data, len));
 * RET then holds the last result; any nonzero value is a failure the
 * caller must report, never a value to ignore.
 *
 * The caller logs; _gcry_wc_log_lock() serializes those logs.  This file
 * runs, triggers or reorders no self-test.
 */
#ifndef GCRY_WOLFCRYPT_CAST_RETRY_H
#define GCRY_WOLFCRYPT_CAST_RETRY_H

#include <time.h>
#include <gpg-error.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef HAVE_FIPS
# include <wolfssl/wolfcrypt/fips_test.h>
#endif

/* ponytail: poll the module 1 ms apart, at most 10000 times, so a call
   waits at least 10 s for another thread's CAST and then fails.
   Ceiling: a CAST slower than that (a badly overloaded host) fails the
   waiting call.  Upgrade path: wait on the module's CAST state instead
   of polling, if wolfCrypt ever exports it.  */
#define WC_CAST_WAIT_TRIES 10000
#define WC_CAST_WAIT_NS    1000000L

/* Nonzero if RET, returned by a wolfCrypt call, may be issued again:
   a CAST (known-answer test) failure code of the FIPS Ready 5.9.1 and
   v5.2.1 modules while the module is NORMAL.  */
static inline int
_gcry_wc_cast_retryable (int ret)
{
#ifdef HAVE_FIPS
  switch (ret)
    {
    case WC_NO_ERR_TRACE (AES_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (AESGCM_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (AESCCM_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (DES3_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (HMAC_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (SHA3_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (PBKDF2_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (DRBG_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (RSA_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (DH_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (ECC_CDH_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (ECDHE_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (ECDSA_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (ED25519_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (ED448_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (KDF_TLS12_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (KDF_TLS13_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (KDF_SSH_KAT_FIPS_E):
    case WC_NO_ERR_TRACE (KDF_SRTP_KAT_FIPS_E):
      return wolfCrypt_GetMode_fips () == FIPS_MODE_NORMAL;
    default:
      return 0;
    }
#else
  (void)ret;
  return 0;
#endif
}

/* Return 1, after a 1 ms sleep, if the call that returned RET is to be
   issued again; *TRIES counts the attempts of that one call and caps
   them at WC_CAST_WAIT_TRIES.  */
static inline int
_gcry_wc_cast_busy (int ret, unsigned int *tries)
{
  struct timespec ts = { 0, WC_CAST_WAIT_NS };

  if (!_gcry_wc_cast_retryable (ret) || *tries >= WC_CAST_WAIT_TRIES)
    return 0;
  ++*tries;
  nanosleep (&ts, NULL);
  return 1;
}

/* Assign to RET the result of the wolfCrypt call CALL, re-issuing CALL
   while _gcry_wc_cast_busy says the CAST it waits for is still running.
   CALL is evaluated once per attempt.  */
#define WC_CAST_RETRY(ret, call)                                \
  do {                                                          \
    unsigned int wc_cast_tries_ = 0;                            \
    do                                                          \
      (ret) = (call);                                           \
    while (_gcry_wc_cast_busy ((ret), &wc_cast_tries_));        \
  } while (0)

/* libgpg-error sets up its log stream on the first log call without a
   lock (src/logging.c, 1.46 and 1.51: _gpgrt_logv_internal calls
   _gpgrt_log_set_sink when logstream is NULL, and set_file_fd clears
   logstream before it installs the new one), so threads that log for the
   first time at once can crash in _gpgrt_funlockfile on a NULL stream.
   global_init sets the stream up while the application is still
   single-threaded; for an application that skips gcry_check_version,
   the wolfCrypt glue's log calls also share one lock, defined once in
   src/misc.c.  Take _gcry_wc_log_lock around log_error/log_info calls;
   use _gcry_wc_log_fatal (takes the lock, does not return) instead of
   log_fatal.  Never hold the lock across a wolfCrypt call.  */
void _gcry_wc_log_lock (void);
void _gcry_wc_log_unlock (void);
void _gcry_wc_log_fatal (const char *fmt, ...) GPGRT_ATTR_NR_PRINTF(1,2);

#endif /*GCRY_WOLFCRYPT_CAST_RETRY_H*/
