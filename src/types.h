/* types.h - some common typedefs
 *	Copyright (C) 1998, 2000, 2002, 2003 Free Software Foundation, Inc.
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

#ifndef GCRYPT_TYPES_H
#define GCRYPT_TYPES_H

#ifndef _GCRYPT_CONFIG_H_INCLUDED
# error config.h must be included before types.h
#endif

/* The AC_CHECK_SIZEOF() in configure fails for some machines.
 * we provide some fallback values here */
#if !SIZEOF_UNSIGNED_SHORT
# undef SIZEOF_UNSIGNED_SHORT
# define SIZEOF_UNSIGNED_SHORT 2
#endif
#if !SIZEOF_UNSIGNED_INT
# undef SIZEOF_UNSIGNED_INT
# define SIZEOF_UNSIGNED_INT 4
#endif
#if !SIZEOF_UNSIGNED_LONG
# undef SIZEOF_UNSIGNED_LONG
# define SIZEOF_UNSIGNED_LONG 4
#endif


#include <sys/types.h>

/* Provide uintptr_t */
#ifdef HAVE_STDINT_H
# include <stdint.h> /* uintptr_t */
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#else
/* In this case, uintptr_t is provided by config.h. */
#endif



#ifndef HAVE_BYTE
# undef byte	/* In case there is a macro with that name.  */
# if !(defined(_WIN32) && defined(cbNDRContext))
   /* Windows typedefs byte in the rpc headers.  Avoid warning about
      double definition.  */
   typedef unsigned char byte;
# endif
# define HAVE_BYTE
#endif

#ifndef HAVE_USHORT
# undef ushort  /* In case there is a macro with that name.  */
  typedef unsigned short ushort;
# define HAVE_USHORT
#endif

#ifndef HAVE_U16
# undef u16	/* In case there is a macro with that name.  */
# if SIZEOF_UNSIGNED_INT == 2
   typedef unsigned int   u16;
# elif SIZEOF_UNSIGNED_SHORT == 2
   typedef unsigned short u16;
# else
#  error no typedef for u16
# endif
# define HAVE_U16
#endif

#ifndef HAVE_U32
# undef u32	/* In case there is a macro with that name.  */
# if SIZEOF_UNSIGNED_INT == 4
   typedef unsigned int  u32;
# elif SIZEOF_UNSIGNED_LONG == 4
   typedef unsigned long u32;
# else
#  error no typedef for u32
# endif
# define HAVE_U32
#endif

/*
 * Warning: Some systems segfault when this u64 typedef and
 * the dummy code in cipher/md.c is not available.  Examples are
 * Solaris and IRIX.
 */
#ifndef HAVE_U64
# undef u64	/* In case there is a macro with that name.  */
# if SIZEOF_UINT64_T == 8
   typedef uint64_t u64;
#  define U64_C(c) (UINT64_C(c))
#  define HAVE_U64
# elif SIZEOF_UNSIGNED_INT == 8
   typedef unsigned int u64;
#  define U64_C(c) (c ## U)
#  define HAVE_U64
# elif SIZEOF_UNSIGNED_LONG == 8
   typedef unsigned long u64;
#  define U64_C(c) (c ## UL)
#  define HAVE_U64
# elif SIZEOF_UNSIGNED_LONG_LONG == 8
   typedef unsigned long long u64;
#  define U64_C(c) (c ## ULL)
#  define HAVE_U64
# else
#  error No way to declare a 64 bit integer type
# endif
#endif

#ifdef HAVE_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/hmac.h>
#endif

typedef union
{
  int a;
  short b;
  char c[1];
  long d;
  u64 e;
  float f;
  double g;
  #ifdef HAVE_WOLFSSL
  wc_Sha256 h;
  wc_Sha i;
  wc_Sha512 j;
  wc_Sha384 k;
  wc_Sha512_224 l;
  wc_Sha512_256 m;
  wc_Sha3 n;
  Hmac o;
  #endif
} PROPERLY_ALIGNED_TYPE;

#endif /*GCRYPT_TYPES_H*/
