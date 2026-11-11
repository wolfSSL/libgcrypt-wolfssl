/* t-ccm.c - AES-CCM tag checks
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PGM "t-ccm"
#include "t-common.h"


/* Start a CCM message on HD: set NONCE, the lengths, and pass AAD.  */
static gcry_error_t
start_message (gcry_cipher_hd_t hd, const char *nonce, size_t noncelen,
               size_t datalen, const char *aad, size_t aadlen, size_t taglen)
{
  uint64_t params[3];
  gcry_error_t err;

  params[0] = datalen;
  params[1] = aadlen;
  params[2] = taglen;
  err = gcry_cipher_setiv (hd, nonce, noncelen);
  if (!err)
    err = gcry_cipher_ctl (hd, GCRYCTL_SET_CCM_LENGTHS, params, sizeof params);
  if (!err)
    err = gcry_cipher_authenticate (hd, aad, aadlen);
  return err;
}


/* Check the tags of messages with associated data but no payload, also
   after a message with payload on the same handle.  The key and message A
   are NIST SP 800-38C, Example 2.  The tags of messages B and C are from
   OpenSSL 3.0.  */
static void
check_ccm_no_payload (void)
{
  static const char key[16] =
    "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f";
  static const char zeros[16] = { 0 };
  /* Message A: payload, 6 byte tag.  */
  static const char nonce_a[8] = "\x10\x11\x12\x13\x14\x15\x16\x17";
  static const char aad_a[16] =
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
  static const char ptext_a[16] =
    "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f";
  static const char ctext_a[16] =
    "\xd2\xa1\xf0\xe0\x51\xea\x5f\x62\x08\x1a\x77\x92\x07\x3d\x59\x3d";
  static const char tag_a[6] = "\x1f\xc6\x4f\xbf\xac\xcd";
  /* Message B: no payload, 6 byte tag.  */
  static const char nonce_b[12] =
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b";
  static const char aad_b[20] =
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    "\x10\x11\x12\x13";
  static const char tag_b[6] = "\x9a\x1d\x37\xc0\xb4\xec";
  /* Message C: no payload, 16 byte tag.  */
  static const char nonce_c[7] = "\x10\x11\x12\x13\x14\x15\x16";
  static const char aad_c[8] = "\x00\x01\x02\x03\x04\x05\x06\x07";
  static const char tag_c[16] =
    "\xdf\xa1\x1a\xe8\x06\x9d\x0a\xaf\x67\x73\x4c\x2e\x98\x11\x1b\x72";
  gcry_cipher_hd_t hd;
  gcry_error_t err;
  unsigned char out[16];

  info ("checking CCM tags of messages without payload\n");

  err = gcry_cipher_open (&hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM, 0);
  if (!err)
    err = gcry_cipher_setkey (hd, key, sizeof key);
  if (err)
    die ("CCM handle setup failed: %s\n", gpg_strerror (err));

  /* Message C on a new handle.  */
  err = start_message (hd, nonce_c, sizeof nonce_c, 0, aad_c, sizeof aad_c,
                       sizeof tag_c);
  if (!err)
    err = gcry_cipher_gettag (hd, out, sizeof tag_c);
  if (err)
    fail ("message C: gettag failed: %s\n", gpg_strerror (err));
  else if (memcmp (out, tag_c, sizeof tag_c))
    fail ("message C: gettag returned a wrong tag\n");

  err = start_message (hd, nonce_c, sizeof nonce_c, 0, aad_c, sizeof aad_c,
                       sizeof tag_c);
  if (!err)
    err = gcry_cipher_checktag (hd, tag_c, sizeof tag_c);
  if (err)
    fail ("message C: checktag failed for the right tag: %s\n",
          gpg_strerror (err));

  err = start_message (hd, nonce_c, sizeof nonce_c, 0, aad_c, sizeof aad_c,
                       sizeof tag_c);
  if (!err)
    err = gcry_cipher_checktag (hd, zeros, sizeof tag_c);
  if (gpg_err_code (err) != GPG_ERR_CHECKSUM)
    fail ("message C: checktag of an all-zero tag returned '%s',"
          " expected '%s'\n", gpg_strerror (err),
          gpg_strerror (GPG_ERR_CHECKSUM));

  /* Message A, with payload.  */
  err = start_message (hd, nonce_a, sizeof nonce_a, sizeof ptext_a,
                       aad_a, sizeof aad_a, sizeof tag_a);
  if (!err)
    err = gcry_cipher_encrypt (hd, out, sizeof ptext_a,
                               ptext_a, sizeof ptext_a);
  if (err)
    fail ("message A: encrypt failed: %s\n", gpg_strerror (err));
  else if (memcmp (out, ctext_a, sizeof ctext_a))
    fail ("message A: encrypt returned a wrong ciphertext\n");
  err = gcry_cipher_gettag (hd, out, sizeof tag_a);
  if (err)
    fail ("message A: gettag failed: %s\n", gpg_strerror (err));
  else if (memcmp (out, tag_a, sizeof tag_a))
    fail ("message A: gettag returned a wrong tag\n");

  /* Message B, after message A on the same handle.  */
  err = start_message (hd, nonce_b, sizeof nonce_b, 0, aad_b, sizeof aad_b,
                       sizeof tag_b);
  if (!err)
    err = gcry_cipher_checktag (hd, tag_a, sizeof tag_a);
  if (gpg_err_code (err) != GPG_ERR_CHECKSUM)
    fail ("message B: checktag of message A's tag returned '%s',"
          " expected '%s'\n", gpg_strerror (err),
          gpg_strerror (GPG_ERR_CHECKSUM));

  err = start_message (hd, nonce_b, sizeof nonce_b, 0, aad_b, sizeof aad_b,
                       sizeof tag_b);
  if (!err)
    err = gcry_cipher_checktag (hd, tag_b, sizeof tag_b);
  if (err)
    fail ("message B: checktag failed for the right tag: %s\n",
          gpg_strerror (err));

  gcry_cipher_close (hd);
}


int
main (int argc, char **argv)
{
  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;
  else if (argc > 1 && !strcmp (argv[1], "--debug"))
    verbose = debug = 1;

  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");

  xgcry_control ((GCRYCTL_DISABLE_SECMEM, 0));
  xgcry_control ((GCRYCTL_INITIALIZATION_FINISHED, 0));
  if (debug)
    xgcry_control ((GCRYCTL_SET_DEBUG_FLAGS, 1u, 0));
  check_ccm_no_payload ();

  return error_count ? 1 : 0;
}
