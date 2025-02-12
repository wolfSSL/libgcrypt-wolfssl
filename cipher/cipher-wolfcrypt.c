/* cipher-wolfcrypt.c - Shim layer for wolfCrypt cipher implementations
 * Copyright (C) 2024 g10 Code GmbH
 *
 * This file is part of Libgcrypt.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "cipher.h"
#include "cipher-internal.h"
#include "cipher-wolfcrypt.h"

#ifndef WOLFSSL_USER_SETTINGS
#include "wolfssl/options.h"
#endif
#include "wolfssl/wolfcrypt/types.h"

#include "wolfssl/wolfcrypt/aes.h"

/* Check if algo/mode should use wolfCrypt */
int _gcry_cipher_is_wolfcrypt(int algo, int mode)
{
    /* For now, only support AES CBC and GCM */
    switch (algo) {
        case GCRY_CIPHER_AES128:
        case GCRY_CIPHER_AES192:
        case GCRY_CIPHER_AES256:
            switch (mode) {
                case GCRY_CIPHER_MODE_CBC:
                case GCRY_CIPHER_MODE_GCM:
                    return 1;
                default:
                    return 0;
            }
        default:
            return 0;
    }
}

/* Check if handle should use wolfCrypt */
int _gcry_cipher_hd_is_wolfcrypt(gcry_cipher_hd_t hd)
{
    return _gcry_cipher_is_wolfcrypt(hd->algo, hd->mode);
}

/* Map libgcrypt algo to wolfCrypt key size */
static int map_algo_to_keybits(int algo)
{
    switch (algo) {
        case GCRY_CIPHER_AES128:
            return 128;
        case GCRY_CIPHER_AES192:
            return 192;
        case GCRY_CIPHER_AES256:
            return 256;
        default:
            return 0;
    }
}

gcry_error_t _gcry_cipher_wc_open(gcry_cipher_hd_t* handle, int algo, int mode,
                                  unsigned int flags)
{
    gcry_error_t     err;
    gcry_cipher_hd_t h;

    /* Allocate handle */
    err = _gcry_cipher_open_internal(handle, algo, mode, flags);
    if (err)
        return err;

    h = *handle;

    /* Clear the entire wolf_aes context */
    memset(&h->u_mode.wolf_aes, 0, sizeof(h->u_mode.wolf_aes));

    /* Initialize wolfCrypt AES context */
    if (wc_AesInit(&h->u_mode.wolf_aes.ctx, NULL, INVALID_DEVID) != 0) {
        _gcry_cipher_close(h);
        *handle = NULL;
        return GPG_ERR_INTERNAL;
    }

    return 0;
}

void _gcry_cipher_wc_close(gcry_cipher_hd_t h)
{
    if (!h)
        return;

    /* Free wolfCrypt context */
    wc_AesFree(&h->u_mode.wolf_aes.ctx);

    /* Free AAD buffer if allocated */
    if (h->u_mode.wolf_aes.aadbuf) {
        _gcry_free(h->u_mode.wolf_aes.aadbuf);
        h->u_mode.wolf_aes.aadbuf = NULL;
    }

    /* Free handle */
    _gcry_cipher_close(h);
}

gcry_error_t _gcry_cipher_wc_setkey(gcry_cipher_hd_t h, const void* key,
                                    size_t keylen)
{
    int ret;
    int keybits = map_algo_to_keybits(h->algo);

    /* Validate key length */
    if (keylen != (keybits / 8)) {
        return GPG_ERR_INV_KEYLEN;
    }

    /* Set the key based on cipher mode */
    switch (h->mode) {
        case GCRY_CIPHER_MODE_CBC:
        case GCRY_CIPHER_MODE_ECB:
        case GCRY_CIPHER_MODE_CTR:
            /* For some modes we need to know the cipher direction when we set
             * the key. Therefore buffer the key and we set it in
             * encrypt/decrypt operation*/
            memcpy(h->u_mode.wolf_aes.key, key, keylen);
            h->u_mode.wolf_aes.flag_setKey = 1;
            ret                            = 0;
            break;

        case GCRY_CIPHER_MODE_GCM:
            ret = wc_AesGcmSetKey(&h->u_mode.wolf_aes.ctx, key, keylen);
            break;

        default:
            return GPG_ERR_INV_CIPHER_MODE;
    }

    if (ret != 0) {
        return GPG_ERR_INTERNAL;
    }

    return 0;
}

gcry_error_t _gcry_cipher_wc_setiv(gcry_cipher_hd_t h, const void* iv,
                                   size_t ivlen)
{
    int ret;
    switch (h->mode) {
        case GCRY_CIPHER_MODE_GCM:
            ret = wc_AesGcmSetExtIV(&h->u_mode.wolf_aes.ctx, iv, ivlen);
            break;

        case GCRY_CIPHER_MODE_CBC:
            ret = wc_AesSetIV(&h->u_mode.wolf_aes.ctx, iv);
            break;

        default:
            return GPG_ERR_INV_CIPHER_MODE;
    }

    return (ret == 0) ? 0 : GPG_ERR_INTERNAL;
}

gcry_error_t _gcry_cipher_wc_authenticate(gcry_cipher_hd_t h,
                                          const void* aadbuf, size_t aadbuflen)
{
    if (h->mode != GCRY_CIPHER_MODE_GCM)
        return GPG_ERR_INV_CIPHER_MODE;

    /* First time initialization */
    if (!h->u_mode.wolf_aes.aadbuf_initialized) {
        h->u_mode.wolf_aes.aadbuf = NULL;
        h->u_mode.wolf_aes.aadlen = 0;
        h->u_mode.wolf_aes.aadbuf_initialized = 1;
    }

    /* Reallocate AAD buffer to fit new data */
    h->u_mode.wolf_aes.aadbuf = _gcry_realloc(h->u_mode.wolf_aes.aadbuf,
                                              h->u_mode.wolf_aes.aadlen + aadbuflen);
    if (!h->u_mode.wolf_aes.aadbuf)
        return GPG_ERR_ENOMEM;

    /* Copy new AAD data to end of buffer */
    memcpy(h->u_mode.wolf_aes.aadbuf + h->u_mode.wolf_aes.aadlen, aadbuf, aadbuflen);
    h->u_mode.wolf_aes.aadlen += aadbuflen;

    return 0;
}

gcry_error_t _gcry_cipher_wc_encrypt(gcry_cipher_hd_t h, void* out,
                                     size_t outsize, const void* in,
                                     size_t inlen)
{
    int ret;

    if (outsize < inlen)
        return GPG_ERR_BUFFER_TOO_SHORT;

    if (!h->u_mode.wolf_aes.flag_setDir)
        return GPG_ERR_INV_CIPHER_MODE;

    /* Set the key based on cipher mode */
    switch (h->mode) {
        case GCRY_CIPHER_MODE_CBC:
            if (h->u_mode.wolf_aes.flag_setKey) {
                int mode = (h->u_mode.wolf_aes.dir == AES_ENCRYPTION) ? AES_ENCRYPTION : AES_DECRYPTION;
                ret = wc_AesSetKey(
                    &h->u_mode.wolf_aes.ctx, h->u_mode.wolf_aes.key,
                    h->u_mode.wolf_aes.keylen, NULL, mode);

                /* WOLF-TODO: Best way to clear? What about secure memory? */
                h->u_mode.wolf_aes.flag_setKey = 0;
                memset(h->u_mode.wolf_aes.key, 0, h->u_mode.wolf_aes.keylen);
                h->u_mode.wolf_aes.keylen = 0;
            }
            ret = wc_AesCbcEncrypt(&h->u_mode.wolf_aes.ctx, out, in, inlen);
            break;

        case GCRY_CIPHER_MODE_GCM:
            ret = wc_AesGcmEncryptUpdate(&h->u_mode.wolf_aes.ctx, out, in,
                                         inlen, h->u_mode.wolf_aes.aadbuf,
                                         h->u_mode.wolf_aes.aadlen);
            /* Free AAD buffer after use */
            if (h->u_mode.wolf_aes.aadbuf) {
                _gcry_free(h->u_mode.wolf_aes.aadbuf);
                h->u_mode.wolf_aes.aadbuf = NULL;
                h->u_mode.wolf_aes.aadlen = 0;
            }
            break;

        default:
            return GPG_ERR_INV_CIPHER_MODE;
    }

    return (ret == 0) ? 0 : GPG_ERR_INTERNAL;
}

gcry_error_t _gcry_cipher_wc_decrypt(gcry_cipher_hd_t h, void* out,
                                     size_t outsize, const void* in,
                                     size_t inlen)
{
    int ret;
    if (outsize < inlen)
        return GPG_ERR_BUFFER_TOO_SHORT;

    switch (h->mode) {
        case GCRY_CIPHER_MODE_CBC:
            ret = wc_AesCbcDecrypt(&h->u_mode.wolf_aes.ctx, out, in, inlen);
            break;
        case GCRY_CIPHER_MODE_GCM:
            ret = wc_AesGcmDecryptUpdate(&h->u_mode.wolf_aes.ctx, out, in,
                                         inlen, h->u_mode.wolf_aes.aadbuf,
                                         h->u_mode.wolf_aes.aadlen);
            /* Free AAD buffer after use */
            if (h->u_mode.wolf_aes.aadbuf) {
                _gcry_free(h->u_mode.wolf_aes.aadbuf);
                h->u_mode.wolf_aes.aadbuf = NULL;
                h->u_mode.wolf_aes.aadlen = 0;
            }
            break;

        default:
            return GPG_ERR_INV_CIPHER_MODE;
    }

    return (ret == 0) ? 0 : GPG_ERR_INTERNAL;
}

gcry_error_t _gcry_cipher_wc_gettag(gcry_cipher_hd_t h, void* outtag,
                                    size_t taglen)
{
    int ret;

    if (h->mode != GCRY_CIPHER_MODE_GCM)
        return GPG_ERR_INV_CIPHER_MODE;

    if (!h->u_mode.wolf_aes.flag_setDir)
        return GPG_ERR_INV_CIPHER_MODE;

    switch (h->mode) {
        case GCRY_CIPHER_MODE_GCM:
            if (h->u_mode.wolf_aes.flag_setDir) {
                ret = wc_AesGcmEncryptFinal(&h->u_mode.wolf_aes.ctx, outtag,
                                            taglen);
            }
            else {
                ret = wc_AesGcmDecryptFinal(&h->u_mode.wolf_aes.ctx, outtag,
                                            taglen);
            }
            break;

        default:
            return GPG_ERR_INV_CIPHER_MODE;
    }

    return (ret == 0) ? 0 : GPG_ERR_INTERNAL;
}

gcry_error_t _gcry_cipher_wc_checktag(gcry_cipher_hd_t h, const void* intag,
                                      size_t taglen)
{
    int ret;

    if (h->mode != GCRY_CIPHER_MODE_GCM)
        return GPG_ERR_INV_CIPHER_MODE;

    switch (h->mode) {
        case GCRY_CIPHER_MODE_GCM:
            ret = wc_AesGcmDecrypt(&h->u_mode.wolf_aes.ctx, NULL, NULL, 0, NULL,
                                   0, intag, taglen, NULL, 0);
            break;

        default:
            return GPG_ERR_INV_CIPHER_MODE;
    }

    return (ret == 0) ? 0 : GPG_ERR_CHECKSUM;
}

gcry_err_code_t
_gcry_cipher_wc_ctl (gcry_cipher_hd_t h, int cmd, void *buffer, size_t buflen)
{
    /* WOLF-TODO: Implement */
    return 0;
}