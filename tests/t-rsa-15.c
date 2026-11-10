/* t-rsa-15.c - Check the RSA PKCS#1 Ver1.5 crypto
 * Copyright (C) 2021 g10 Code GmbH
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "stopwatch.h"

#define PGM "t-rsa-15"
#include "t-common.h"
#define N_TESTS 120

#if defined(HAVE_WOLFSSL)
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#endif

static int no_verify;
static int custom_data_file;
static int in_fips_mode;


static void
show_note (const char *format, ...)
{
  va_list arg_ptr;

  if (!verbose && getenv ("srcdir"))
    fputs ("      ", stderr);  /* To align above "PASS: ".  */
  else
    fprintf (stderr, "%s: ", PGM);
  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  if (*format && format[strlen(format)-1] != '\n')
    putc ('\n', stderr);
  va_end (arg_ptr);
}


/* Prepend FNAME with the srcdir environment variable's value and
 * return an allocated filename.  */
char *
prepend_srcdir (const char *fname)
{
  static const char *srcdir;
  char *result;

  if (!srcdir && !(srcdir = getenv ("srcdir")))
    srcdir = ".";

  result = xmalloc (strlen (srcdir) + 1 + strlen (fname) + 1);
  strcpy (result, srcdir);
  strcat (result, "/");
  strcat (result, fname);
  return result;
}


/* Read next line but skip over empty and comment lines.  Caller must
   xfree the result.  */
static char *
read_textline (FILE *fp, int *lineno)
{
  char line[4096];
  char *p;

  do
    {
      if (!fgets (line, sizeof line, fp))
        {
          if (feof (fp))
            return NULL;
          die ("error reading input line: %s\n", strerror (errno));
        }
      ++*lineno;
      p = strchr (line, '\n');
      if (!p)
        die ("input line %d not terminated or too long\n", *lineno);
      *p = 0;
      for (p--;p > line && my_isascii (*p) && isspace (*p); p--)
        *p = 0;
    }
  while (!*line || *line == '#');
  /* if (debug) */
  /*   info ("read line: '%s'\n", line); */
  return xstrdup (line);
}


/* Copy the data after the tag to BUFFER.  BUFFER will be allocated as
   needed.  */
static void
copy_data (char **buffer, const char *line, int lineno)
{
  const char *s;

  xfree (*buffer);
  *buffer = NULL;

  s = strchr (line, '=');
  if (!s)
    {
      fail ("syntax error at input line %d", lineno);
      return;
    }
  for (s++; my_isascii (*s) && isspace (*s); s++)
    ;
  *buffer = xstrdup (s);
}


/* Convert STRING consisting of hex characters into its binary
   representation and return it as an allocated buffer. The valid
   length of the buffer is returned at R_LENGTH.  The string is
   delimited by end of string.  The function returns NULL on
   error.  */
static void *
hex2buffer (const char *string, size_t *r_length)
{
  const char *s;
  unsigned char *buffer;
  size_t length;

  buffer = xmalloc (strlen(string)/2+1);
  length = 0;
  for (s=string; *s; s +=2 )
    {
      if (!hexdigitp (s) || !hexdigitp (s+1))
        {
          xfree (buffer);
          return NULL;           /* Invalid hex digits. */
        }
      ((unsigned char*)buffer)[length++] = xtoi_2 (s);
    }
  *r_length = length;
  return buffer;
}


static void
one_test_sexp (const char *n, const char *e, const char *d,
               const char *sha_alg, const char *msg, const char *s)
{
  gpg_error_t err;
  int i;
  char *p;
  void *buffer = NULL;
  void *buffer2 = NULL;
  void *buffer3 = NULL;
  size_t buflen, buflen2, buflen3;
  int md_algo;
  const char *data_tmpl;
  gcry_md_hd_t hd = NULL;
  gcry_sexp_t s_pk = NULL;
  gcry_sexp_t s_sk = NULL;
  gcry_sexp_t s_sig= NULL;
  gcry_sexp_t s_tmp, s_tmp2;
  unsigned char *out = NULL;
  size_t out_len = 0;
  char *sig_string = NULL;

  if (verbose > 1)
    info ("Running test %s\n", sha_alg);

  if (!strcmp (sha_alg, "SHA224"))
    md_algo = GCRY_MD_SHA224;
  else if (!strcmp (sha_alg, "SHA256"))
    md_algo = GCRY_MD_SHA256;
  else if (!strcmp (sha_alg, "SHA384"))
    md_algo = GCRY_MD_SHA384;
  else if (!strcmp (sha_alg, "SHA512"))
    md_algo = GCRY_MD_SHA512;
  else if (!strcmp (sha_alg, "SHA512224"))
    md_algo = GCRY_MD_SHA512_224;
  else if (!strcmp (sha_alg, "SHA512256"))
    md_algo = GCRY_MD_SHA512_256;
  else
    {
      fail ("error for test, %s: %s",
            "d", "invalid hex string");
      goto leave;
    }

  err = gcry_md_open (&hd, md_algo, 0);
#if defined(HAVE_WOLFSSL)
  #if defined(WOLFSSL_NOSHA512_224)
  if (md_algo == GCRY_MD_SHA512_224) {
    if (strncmp(gpg_strerror(err), "Invalid digest algorithm", 26) != 0) {
        fail ("gcry_md_open failed to detect invalid digest algorithm\n");
    }
    goto leave; /* Don't check the signature because it should fail */
  }
  #endif
  #if defined(WOLFSSL_NOSHA512_256)
  if (md_algo == GCRY_MD_SHA512_256) {
    if (strncmp(gpg_strerror(err), "Invalid digest algorithm", 26) != 0) {
        fail ("gcry_md_open failed to detect invalid digest algorithm\n");
    }
    goto leave; /* Don't check the signature because it should fail */
  }
  #endif
#endif
  if (err)
    {
      fail ("algo %d, gcry_md_open failed: %s\n", md_algo, gpg_strerror (err));
      return;
    }

  if (!(buffer = hex2buffer (n, &buflen)))
    {
      fail ("error parsing for test, %s: %s",
            "n", "invalid hex string");
      goto leave;
    }
  if (!(buffer2 = hex2buffer (e, &buflen2)))
    {
      fail ("error parsing for test, %s: %s",
            "e", "invalid hex string");
      goto leave;
    }
  if (!(buffer3 = hex2buffer (d, &buflen3)))
    {
      fail ("error parsing for test, %s: %s",
            "d", "invalid hex string");
      goto leave;
    }

  err = gcry_sexp_build (&s_sk, NULL,
                         "(private-key (rsa (n %b)(e %b)(d %b)))",
                         (int)buflen, buffer,
                         (int)buflen2, buffer2,
                         (int)buflen3, buffer3);
  if (err)
    {
      fail ("error building SEXP for test, %s: %s",
            "sk", gpg_strerror (err));
      goto leave;
    }

  err = gcry_sexp_build (&s_pk, NULL,
                         "(public-key (rsa (n %b)(e %b)))",
                         (int)buflen, buffer,
                         (int)buflen2, buffer2);
  if (err)
    {
      fail ("error building SEXP for test, %s: %s",
            "pk", gpg_strerror (err));
      goto leave;
    }

  xfree (buffer);
  xfree (buffer2);
  xfree (buffer3);
  buffer = buffer2 = buffer3 = NULL;

  if (!(buffer = hex2buffer (msg, &buflen)))
    {
      fail ("error parsing for test, %s: %s",
            "msg", "invalid hex string");
      goto leave;
    }

  gcry_md_write (hd, buffer, buflen);
  xfree (buffer);
  buffer = NULL;

  data_tmpl = "(data(flags pkcs1)(hash %s %b))";
  err = gcry_pk_hash_sign (&s_sig, data_tmpl, s_sk, hd, NULL);
  #if defined(ENABLED_WOLFSSL_FIPS)
  if (strncmp(gpg_strerror(err), "Missing item in object", 20) != 0) {
    fail ("gcry_pk_hash_sign failed to detect missing item prime p/q\n");
  }
  goto leave; /* Don't check the signature because it should fail */
  #else
  if (err)
    {
      fail ("gcry_pk_hash_sign failed: %s", gpg_strerror (err));
      goto leave;
    }
  #endif

  s_tmp2 = NULL;
  s_tmp = gcry_sexp_find_token (s_sig, "sig-val", 0);
  if (s_tmp)
    {
      s_tmp2 = s_tmp;
      s_tmp = gcry_sexp_find_token (s_tmp2, "rsa", 0);
      if (s_tmp)
        {
          gcry_sexp_release (s_tmp2);
          s_tmp2 = s_tmp;
          s_tmp = gcry_sexp_find_token (s_tmp2, "s", 0);
          if (s_tmp)
            {
              out = gcry_sexp_nth_buffer (s_tmp, 1, &out_len);
              gcry_sexp_release (s_tmp);
            }
        }
    }
  gcry_sexp_release (s_tmp2);

  sig_string = gcry_xmalloc (2*out_len+1);
  p = sig_string;
  *p = 0;
  for (i=0; i < out_len; i++, p += 2)
    snprintf (p, 3, "%02x", out[i]);
  if (strcmp (sig_string, s))
    {
      fail ("gcry_pk_hash_sign failed: %s",
            "wrong value returned");
      info ("  expected: '%s'", s);
      info ("       got: '%s'", sig_string);
    }

  if (!no_verify)
    {
      err = gcry_pk_hash_verify (s_sig, data_tmpl, s_pk, hd, NULL);
      if (err)
        fail ("gcry_pk_hash_verify failed for test: %s",
              gpg_strerror (err));
    }

 leave:
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_sk);
  gcry_sexp_release (s_pk);
  if (hd)
    gcry_md_close (hd);
  xfree (buffer);
  xfree (buffer2);
  xfree (buffer3);
  xfree (out);
  xfree (sig_string);
}


static void
check_rsa_15 (const char *fname)
{
  FILE *fp;
  int lineno, ntests;
  char *line;
  char *n, *e, *d;
  char *sha_alg, *msg, *s;

  info ("Checking RSA PKCS#1 Ver1.5.\n");

  fp = fopen (fname, "r");
  if (!fp)
    die ("error opening '%s': %s\n", fname, strerror (errno));

  n = e = d = NULL;
  sha_alg = msg = s = NULL;
  lineno = ntests = 0;
  while ((line = read_textline (fp, &lineno)))
    {
      if (!strncmp (line, "[mod", 4))
        /* Skip the annotation for modulus.  */
        ;
      else if (!strncmp (line, "n =", 3))
        copy_data (&n, line, lineno);
      else if (!strncmp (line, "e =", 3))
        copy_data (&e, line, lineno);
      else if (!strncmp (line, "d =", 3))
        copy_data (&d, line, lineno);
      else if (!strncmp (line, "SHAAlg =", 8))
        copy_data (&sha_alg, line, lineno);
      else if (!strncmp (line, "Msg =", 5))
        copy_data (&msg, line, lineno);
      else if (!strncmp (line, "S =", 3))
        copy_data (&s, line, lineno);
      else
        fail ("unknown tag at input line %d", lineno);

      xfree (line);
      if (n && e && d && sha_alg && msg && s)
        {
          one_test_sexp (n, e, d, sha_alg, msg, s);
          ntests++;
          if (!(ntests % 256))
            show_note ("%d of %d tests done\n", ntests, N_TESTS);
          xfree (sha_alg);  sha_alg = NULL;
          xfree (msg); msg = NULL;
          xfree (s); s = NULL;
        }

    }
  xfree (n);
  xfree (e);
  xfree (d);
  xfree (sha_alg);
  xfree (msg);
  xfree (s);

  if (ntests != N_TESTS && !custom_data_file)
    fail ("did %d tests but expected %d", ntests, N_TESTS);
  else if ((ntests % 256))
    show_note ("%d tests done\n", ntests);

  fclose (fp);
}


/* Check that gcry_pk_verify returns an error for a signature that the
   key did not produce, with RIPEMD-160 and SM3 data.  The key is the
   first 2048 bit key of t-rsa-15.inp.  */
static void
check_bad_signature_rmd160_sm3 (void)
{
  static const char pubkey[] =
    "(public-key (rsa (n #"
    "cea80475324c1dc8347827818da58bac069d3419c614a6ea1ac6a3b510dcd72c"
    "c516954905e9fef908d45e13006adf27d467a7d83c111d1a5df15ef293771aef"
    "b920032a5bb989f8e4f5e1b05093d3f130f984c07a772a3683f4dc6fb28a9681"
    "5b32123ccdd13954f19d5b8b24a103e771a34c328755c65ed64e1924ffd04d30"
    "b2142cc262f6e0048fef6dbc652f21479ea1c4b1d66d28f4d46ef7185e390cbf"
    "a2e02380582f3188bb94ebbf05d31487a09aff01fcbb4cd4bfd1f0a833b38c11"
    "813c84360bb53c7d4481031c40bad8713bb6b835cb08098ed15ba31ee4ba728a"
    "8c8e10f7294e1b4163b7aee57277bfd881a6f9d43e02c6925aa3a043fb7fb78d"
    "#) (e #260445#)))";
  static const char *datas[] =
    {
      "(data (flags pkcs1) (hash rmd160 "
      "#000102030405060708090a0b0c0d0e0f10111213#))",
      "(data (flags pkcs1) (hash sm3 "
      "#000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f#))"
    };
  gcry_sexp_t s_pk, s_sig, s_data;
  gpg_error_t err;
  size_t i;

  info ("Checking a wrong signature with RIPEMD-160 and SM3 data.\n");

  err = gcry_sexp_new (&s_pk, pubkey, 0, 1);
  if (!err)
    err = gcry_sexp_new (&s_sig, "(sig-val (rsa (s #01#)))", 0, 1);
  if (err)
    die ("error building SEXP: %s\n", gpg_strerror (err));

  for (i = 0; i < DIM (datas); i++)
    {
      err = gcry_sexp_new (&s_data, datas[i], 0, 1);
      if (err)
        die ("error building SEXP: %s\n", gpg_strerror (err));
      err = gcry_pk_verify (s_sig, s_data, s_pk);
      if (!err)
        fail ("gcry_pk_verify returned success for a wrong signature: %s\n",
              datas[i]);
      gcry_sexp_release (s_data);
    }

  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_pk);
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  char *fname = NULL;

  if (argc)
    { argc--; argv++; }

  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        {
          fputs ("usage: " PGM " [options]\n"
                 "Options:\n"
                 "  --verbose       print timings etc.\n"
                 "  --debug         flyswatter\n"
                 "  --no-verify     skip the verify test\n"
                 "  --data FNAME    take test data from file FNAME\n",
                 stdout);
          exit (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose += 2;
          debug++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--no-verify"))
        {
          no_verify = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--data"))
        {
          argc--; argv++;
          if (argc)
            {
              xfree (fname);
              fname = xstrdup (*argv);
              argc--; argv++;
            }
        }
      else if (!strncmp (*argv, "--", 2))
        die ("unknown option '%s'", *argv);

    }

  if (!fname)
    fname = prepend_srcdir ("t-rsa-15.inp");
  else
    custom_data_file = 1;

  xgcry_control ((GCRYCTL_DISABLE_SECMEM, 0));
  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");
  if (debug)
    xgcry_control ((GCRYCTL_SET_DEBUG_FLAGS, 1u , 0));
  xgcry_control ((GCRYCTL_ENABLE_QUICK_RANDOM, 0));
  xgcry_control ((GCRYCTL_INITIALIZATION_FINISHED, 0));

  if (gcry_fips_mode_active ())
    in_fips_mode = 1;

  start_timer ();
  check_rsa_15 (fname);
  if (!no_verify)
    check_bad_signature_rmd160_sm3 ();
  stop_timer ();

  xfree (fname);

  info ("All tests completed in %s.  Errors: %d\n",
        elapsed_time (1), error_count);
  return !!error_count;
}
