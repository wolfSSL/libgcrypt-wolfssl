/* t-hmac-shortkey.c - a short HMAC key must not disable FIPS mode
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
 */

/* In FIPS mode an HMAC key below the 112-bit minimum may be refused,
   but that is the caller's error: the library must stay operational
   and keep hashing correctly.  gcry_md_setkey and gcry_mac_setkey
   refuse such a key up front; gcry_md_hash_buffers with
   GCRY_MD_FLAG_HMAC and the HKDF salt pass it on to the digest code.  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PGM "t-hmac-shortkey"
#include "t-common.h"

static void
check_operational (const char *when)
{
  if (!gcry_control (GCRYCTL_OPERATIONAL_P, 0))
    fail ("library not operational %s\n", when);
}

int
main (int argc, char **argv)
{
  /* SHA-256 ("abc"), FIPS 180-2 appendix B.1.  */
  static const unsigned char abc_sha256[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
  };
  static const char key[] = "Jefe";   /* RFC 4231 test case 2 */
  /* RFC 5869 test case 1: SHA-256, 13-byte salt.  */
  static const unsigned char hkdf_ikm[22] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
  };
  static const unsigned char hkdf_salt[13] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c
  };
  static const unsigned char hkdf_info[10] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9
  };
  unsigned long hkdf_param[1] = { 42 };
  unsigned char digest[42];
  gcry_buffer_t iov[2];
  gcry_kdf_hd_t kdf;
  gcry_md_hd_t md;
  gcry_mac_hd_t mac;
  gcry_error_t err;

  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;

  xgcry_control ((GCRYCTL_FORCE_FIPS_MODE, 0));
  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");
  xgcry_control ((GCRYCTL_INITIALIZATION_FINISHED, 0));
  if (!gcry_fips_mode_active ())
    die ("FIPS mode could not be enabled\n");
  check_operational ("after initialization");

  err = gcry_md_open (&md, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
  if (err)
    die ("gcry_md_open failed: %s\n", gpg_strerror (err));
  err = gcry_md_setkey (md, key, strlen (key));
  if (verbose)
    info ("gcry_md_setkey (4-byte key): %s\n", gpg_strerror (err));
  gcry_md_close (md);
  check_operational ("after gcry_md_setkey with a short key");

  err = gcry_mac_open (&mac, GCRY_MAC_HMAC_SHA256, 0, NULL);
  if (err)
    die ("gcry_mac_open failed: %s\n", gpg_strerror (err));
  err = gcry_mac_setkey (mac, key, strlen (key));
  if (verbose)
    info ("gcry_mac_setkey (4-byte key): %s\n", gpg_strerror (err));
  gcry_mac_close (mac);
  check_operational ("after gcry_mac_setkey with a short key");

  memset (iov, 0, sizeof iov);
  iov[0].data = (void *)key;
  iov[0].len = strlen (key);
  iov[1].data = "what do ya want for nothing?";
  iov[1].len = strlen (iov[1].data);
  err = gcry_md_hash_buffers (GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC, digest,
                              iov, 2);
  if (verbose)
    info ("gcry_md_hash_buffers (HMAC, 4-byte key): %s\n",
          gpg_strerror (err));
  check_operational ("after gcry_md_hash_buffers with a short HMAC key");

  err = gcry_kdf_open (&kdf, GCRY_KDF_HKDF, GCRY_MAC_HMAC_SHA256,
                       hkdf_param, 1, hkdf_ikm, sizeof hkdf_ikm,
                       NULL, 0, hkdf_salt, sizeof hkdf_salt,
                       hkdf_info, sizeof hkdf_info);
  if (err)
    die ("gcry_kdf_open (HKDF) failed: %s\n", gpg_strerror (err));
  err = gcry_kdf_compute (kdf, NULL);
  if (!err)
    err = gcry_kdf_final (kdf, hkdf_param[0], digest);
  if (verbose)
    info ("HKDF (13-byte salt): %s\n", gpg_strerror (err));
  gcry_kdf_close (kdf);
  check_operational ("after HKDF with a short salt");

  memset (iov, 0, sizeof iov);
  iov[0].data = "abc";
  iov[0].len = 3;
  err = gcry_md_hash_buffers (GCRY_MD_SHA256, 0, digest, iov, 1);
  if (err)
    fail ("SHA-256 after a short HMAC key failed: %s\n", gpg_strerror (err));
  else if (memcmp (digest, abc_sha256, sizeof abc_sha256))
    fail ("SHA-256 (\"abc\") mismatch after a short HMAC key\n");

  return !!error_count;
}
