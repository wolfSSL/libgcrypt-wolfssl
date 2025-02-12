/* cipher-wolfcrypt.h - Shim layer for wolfCrypt cipher implementations
 * Copyright (C) 2024 g10 Code GmbH
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

#ifndef GCRY_CIPHER_WOLFCRYPT_H
#define GCRY_CIPHER_WOLFCRYPT_H

#include "g10lib.h"
#include "cipher.h"

/* Check if the algorithm/mode combination is supported by wolfCrypt */
int _gcry_cipher_is_wolfcrypt(int algo, int mode);
int _gcry_cipher_hd_is_wolfcrypt(gcry_cipher_hd_t hd);

/* Core wolfCrypt cipher operations */
gcry_error_t _gcry_cipher_wc_open(gcry_cipher_hd_t *handle,
                                 int algo, int mode, unsigned int flags);

void _gcry_cipher_wc_close(gcry_cipher_hd_t h);

gcry_error_t _gcry_cipher_wc_setkey(gcry_cipher_hd_t h,
                                   const void *key, size_t keylen);

gcry_error_t _gcry_cipher_wc_setiv(gcry_cipher_hd_t h,
                                  const void *iv, size_t ivlen);

gcry_error_t _gcry_cipher_wc_encrypt(gcry_cipher_hd_t h,
                                    void *out, size_t outsize,
                                    const void *in, size_t inlen);

gcry_error_t _gcry_cipher_wc_decrypt(gcry_cipher_hd_t h,
                                    void *out, size_t outsize,
                                    const void *in, size_t inlen);

/* AEAD specific operations */
gcry_error_t _gcry_cipher_wc_authenticate(gcry_cipher_hd_t h,
                                        const void *aadbuf, size_t aadbuflen);

gcry_error_t _gcry_cipher_wc_gettag(gcry_cipher_hd_t h,
                                   void *outtag, size_t taglen);

gcry_error_t _gcry_cipher_wc_checktag(gcry_cipher_hd_t h,
                                     const void *intag, size_t taglen);

#endif /* GCRY_CIPHER_WOLFCRYPT_H */