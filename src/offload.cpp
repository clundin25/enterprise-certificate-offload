// Copyright 2022 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cstddef>
#include <iostream>
#include <memory>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>

struct provider_ctx {
  const OSSL_CORE_HANDLE *core_handle;
  struct proverr_functions *prover_handle;
};

static void provider_ctx_free(struct provider_ctx *ctx) {
  if (ctx) {
    proverr_free_handle(ctx->prover_handle);
  }

  free(ctx);
}

static struct provider_ctx *provider_ctx_new(const OSSL_CORE_HANDLE *core, const OSSL_DISPATCH *in) {
  struct provider_ctx *ctx = (struct provider_ctx *) malloc(sizeof(struct provider_ctx));

  if (ctx == NULL) {
    return NULL;
  }

  ctx->prover_handle = proverr_new_handle(core, in);

  if (ctx->prover_handle == NULL) {
    free(ctx);
    return NULL;
  }

  ctx->core_handle = core;

  return ctx;
}

static OSSL_FUNC_provider_query_operation_fn vigenere_prov_operation;
static OSSL_FUNC_provider_get_params_fn vigenere_prov_get_params;
static OSSL_FUNC_provider_get_reason_strings_fn vigenere_prov_get_reason_strings;

static OSSL_FUNC_cipher_newctx_fn vigenere_newctx;
static OSSL_FUNC_cipher_encrypt_init_fn vigenere_encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn vigenere_decrypt_init;
static OSSL_FUNC_cipher_update_fn vigenere_update;
static OSSL_FUNC_cipher_final_fn vigenere_final;
static OSSL_FUNC_cipher_dupctx_fn vigenere_dupctx;
static OSSL_FUNC_cipher_freectx_fn vigenere_freectx;
static OSSL_FUNC_cipher_get_params_fn vigenere_get_params;
static OSSL_FUNC_cipher_gettable_params_fn vigenere_gettable_params;
static OSSL_FUNC_cipher_set_ctx_params_fn vigenere_set_ctx_params;
static OSSL_FUNC_cipher_get_ctx_params_fn vigenere_get_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn vigenere_settable_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn vigenere_gettable_ctx_params;

#define DEFAULT_KEYLENGTH 16    /* amount of bytes == 128 bits */
#define BLOCKSIZE 1             /* amount of bytes */

/* Helper function to determine the key length */
static size_t keylen()
{
    /*
     * Give the user a chance to decide a default.
     * With 'openssl enc', this is the only viable way for the user
     * to set an arbitrary key length.
     * Note that the length is expressed in bytes.
     */
    const char *user_keyl = getenv("VIGENERE_KEYLEN");
    size_t keyl = DEFAULT_KEYLENGTH;

    if (user_keyl != NULL)
        keyl = strtoul(user_keyl, NULL, 0);
    return keyl;
}

/*
 * The context used throughout all these functions.
 */
struct vigenere_ctx_st {
    struct provider_ctx_st *provctx;

    size_t keyl;                /* The configured length of the key */

    unsigned char *key;         /* A copy of the key */
    size_t keysize;             /* Size of the key currently used */
    size_t keypos;              /* The current position in the key */
    int enc;                    /* 0 = decrypt, 1 = encrypt */
    int ongoing;                /* 1 = operation has started */
};
#define ERR_HANDLE(ctx) ((ctx)->provctx->proverr_handle)

static void *vigenere_newctx(void *vprovctx)
{
    struct vigenere_ctx_st *ctx = malloc(sizeof(*ctx));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->provctx = vprovctx;
        ctx->keyl = keylen();
    }
    return ctx;
}

static void vigenere_cleanctx(void *vctx)
{
    struct vigenere_ctx_st *ctx = vctx;

    if (ctx == NULL)
        return;
    free(ctx->key);
    ctx->key = NULL;
    ctx->keypos = 0;
    ctx->enc = 0;
    ctx->ongoing = 0;
}

static void *vigenere_dupctx(void *vctx)
{
    struct vigenere_ctx_st *src = vctx;
    struct vigenere_ctx_st *dst = NULL;

    if (src == NULL
        || (dst = vigenere_newctx(NULL)) == NULL)

    dst->provctx = src->provctx;
    dst->provctx->proverr_handle =
        proverr_dup_handle(src->provctx->proverr_handle);
    dst->keyl = src->keyl;

    if (src->key != NULL) {
        if ((dst->key = malloc(src->keyl)) == NULL) {
            vigenere_freectx(dst);
            return NULL;
        }
        memcpy(dst->key, src->key, src->keyl);
    }

    dst->keypos = src->keypos;
    dst->enc = src->enc;
    dst->ongoing = src->ongoing;

    return dst;
}

static void vigenere_freectx(void *vctx)
{
    struct vigenere_ctx_st *ctx = vctx;

    ctx->provctx = NULL;
    vigenere_cleanctx(ctx);
    free(ctx);
}

static int vigenere_encrypt_init(void *vctx,
                                 const unsigned char *key,
                                 size_t keyl,
                                 const unsigned char *iv_unused,
                                 size_t ivl_unused,
                                 const OSSL_PARAM params[])
{
    struct vigenere_ctx_st *ctx = vctx;

    if (key != NULL) {
        if (keyl == (size_t)-1 || keyl == 0) {
            ERR_raise(ERR_HANDLE(ctx), VIGENERE_NO_KEYLEN_SET);
            return 0;
        }
        free(ctx->key);
        ctx->key = malloc(keyl);
        memcpy(ctx->key, key, keyl);
        ctx->keysize = keyl;
    }
    ctx->keypos = 0;
    ctx->ongoing = 0;
    return 1;
}

static int vigenere_decrypt_init(void *vctx,
                                 const unsigned char *key,
                                 size_t keyl,
                                 const unsigned char *iv_unused,
                                 size_t ivl_unused,
                                 const OSSL_PARAM params[])
{
    struct vigenere_ctx_st *ctx = vctx;
    size_t i;

    if (key != NULL) {
        if (keyl == (size_t)-1 || keyl == 0) {
            ERR_raise(ERR_HANDLE(ctx), VIGENERE_NO_KEYLEN_SET);
            return 0;
        }
        free(ctx->key);
        ctx->key = malloc(keyl);
        for (i = 0; i < keyl; i++)
            ctx->key[i] = 256 - key[i];
        ctx->keysize = keyl;
    }
    ctx->keypos = 0;
    ctx->ongoing = 0;
    return 1;
}

static int vigenere_update(void *vctx,
                           unsigned char *out, size_t *outl, size_t outsz,
                           const unsigned char *in, size_t inl)
{
    struct vigenere_ctx_st *ctx = vctx;

    assert(outsz >= inl);
    assert(out != NULL);
    assert(outl != NULL);
#if 0
    if (outsz < inl || out == NULL)
        return 0;
#else
    if (out == NULL)
        return 0;
#endif

    ctx->ongoing = 1;
    *outl = 0;
    for (; inl-- > 0; (*outl)++) {
        *out++ = (*in++ + ctx->key[ctx->keypos++]) % 256;
        if (ctx->keypos >= ctx->keysize)
            ctx->keypos = 0;
    }

    return 1;
}

static int vigenere_final(void *vctx,
                          unsigned char *out, size_t *outl, size_t outsz)
{
    struct vigenere_ctx_st *ctx = vctx;

    *outl = 0;
    ctx->ongoing = 0;

    return 1;
}

/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *vigenere_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        { "blocksize", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { "keylen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int vigenere_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++) {
        if (strcasecmp(p->key, "blocksize") == 0)
            if (provnum_set_size_t(p, 1) < 0) {
                ok = 0;
                continue;
            }
        if (strcasecmp(p->key, "keylen") == 0) {
            if (provnum_set_size_t(p, keylen()) < 0) {
                ok = 0;
                continue;
            }
        }
    }
    return ok;
}

static const OSSL_PARAM *vigenere_gettable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        { "keylen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int vigenere_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct vigenere_ctx_st *ctx = vctx;
    int ok = 1;

    if (ctx->keyl > 0) {
        OSSL_PARAM *p;

        for (p = params; p->key != NULL; p++)
            if (strcasecmp(p->key, "keylen") == 0
                && provnum_set_size_t(p, ctx->keyl) < 0) {
                ok = 0;
                continue;
            }
    }
    return ok;
}

/* Parameters that libcrypto can send to this implementation */
static const OSSL_PARAM *vigenere_settable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        { "keylen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int vigenere_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct vigenere_ctx_st *ctx = vctx;
    const OSSL_PARAM *p;
    int ok = 1;

    if (ctx->ongoing) {
        ERR_raise(ERR_HANDLE(ctx), VIGENERE_ONGOING_OPERATION);
        return 0;
    }

    for (p = params; p->key != NULL; p++)
        if (strcasecmp(p->key, "keylen") == 0) {
            size_t keyl = 0;

            if (provnum_get_size_t(&keyl, p) < 0) {
                ok = 0;
                continue;
            }
            ctx->keyl = keyl;
        }
    return ok;
}


/*********************************************************************
 *
 *  Setup
 *
 *****/

typedef void (*funcptr_t)(void);

/* The Vigenere dispatch table */
static const OSSL_DISPATCH vigenere_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (funcptr_t)vigenere_newctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (funcptr_t)vigenere_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (funcptr_t)vigenere_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (funcptr_t)vigenere_update },
    { OSSL_FUNC_CIPHER_FINAL, (funcptr_t)vigenere_final },
    { OSSL_FUNC_CIPHER_DUPCTX, (funcptr_t)vigenere_dupctx },
    { OSSL_FUNC_CIPHER_FREECTX, (funcptr_t)vigenere_freectx },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (funcptr_t)vigenere_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (funcptr_t)vigenere_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (funcptr_t)vigenere_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
      (funcptr_t)vigenere_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (funcptr_t)vigenere_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
      (funcptr_t)vigenere_settable_ctx_params },
    { 0, NULL }
};

/* The table of ciphers this provider offers */
static const OSSL_ALGORITHM vigenere_ciphers[] = {
    { "vigenere:1.3.6.1.4.1.5168.4711.22087.1", NULL, vigenere_functions },
    { NULL , NULL, NULL }
};

/* The function that returns the appropriate algorithm table per operation */
static const OSSL_ALGORITHM *vigenere_prov_operation(void *vprovctx,
                                                     int operation_id,
                                                     int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_CIPHER:
        return vigenere_ciphers;
    }
    return NULL;
}

static const OSSL_ITEM *vigenere_prov_get_reason_strings(void *provctx)
{
    return reason_strings;
}

static int vigenere_prov_get_params(void *provctx, OSSL_PARAM *params)
{
    OSSL_PARAM *p;
    int ok = 1;

    for(p = params; p->key != NULL; p++)
        if (strcasecmp(p->key, "version") == 0) {
            *(const void **)p->data = VERSION;
            p->return_size = strlen(VERSION);
        } else if (strcasecmp(p->key, "buildinfo") == 0
                 && BUILDTYPE[0] != '\0') {
            *(const void **)p->data = BUILDTYPE;
            p->return_size = strlen(BUILDTYPE);
        }
    return ok;
}

/* The function that tears down this provider */
static void vigenere_prov_teardown(void *vprovctx)
{
    provider_ctx_free(vprovctx);
}

/* The base dispatch table */
static const OSSL_DISPATCH provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (funcptr_t)vigenere_prov_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (funcptr_t)vigenere_prov_operation },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
      (funcptr_t)vigenere_prov_get_reason_strings },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,
      (funcptr_t)vigenere_prov_get_params },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **vprovctx)
{
    if ((*vprovctx = provider_ctx_new(core, in)) == NULL)
        return 0;
    *out = provider_functions;
    return 1;
} 




namespace {

using SignFunc = int (*)(unsigned char *sig, size_t *sig_len,
                         const unsigned char *tbs, size_t tbs_len);

class CustomKey {
 public:
  explicit CustomKey(SignFunc sign_func) : sign_func_(sign_func) {}

  bool Sign(unsigned char *sig, size_t *sig_len, const unsigned char *tbs,
            size_t tbs_len) {
    return sign_func_(sig, sig_len, tbs, tbs_len);
  }

 public:
  SignFunc sign_func_;
};

template <typename T, typename Ret, Ret (*Deleter)(T *)>
struct OpenSSLDeleter {
  void operator()(T *t) const { Deleter(t); }
};
struct OpenSSLFreeDeleter {
  void operator()(unsigned char *buf) const { OPENSSL_free(buf); }
};
template <typename T, void (*Deleter)(T *)>
using OwnedOpenSSLPtr = std::unique_ptr<T, OpenSSLDeleter<T, void, Deleter>>;
template <typename T, int (*Deleter)(T *)>
using OwnedOpenSSLPtrIntRet =
    std::unique_ptr<T, OpenSSLDeleter<T, int, Deleter>>;
using OwnedBIO = OwnedOpenSSLPtrIntRet<BIO, BIO_free>;
using OwnedENGINE = OwnedOpenSSLPtrIntRet<ENGINE, ENGINE_free>;
using OwnedEVP_MD_CTX = OwnedOpenSSLPtr<EVP_MD_CTX, EVP_MD_CTX_free>;
using OwnedEVP_PKEY = OwnedOpenSSLPtr<EVP_PKEY, EVP_PKEY_free>;
using OwnedEVP_PKEY_METHOD =
    OwnedOpenSSLPtr<EVP_PKEY_METHOD, EVP_PKEY_meth_free>;
using OwnedSSL_CTX = OwnedOpenSSLPtr<SSL_CTX, SSL_CTX_free>;
using OwnedSSL = OwnedOpenSSLPtr<SSL, SSL_free>;
using OwnedX509_PUBKEY = OwnedOpenSSLPtr<X509_PUBKEY, X509_PUBKEY_free>;
using OwnedX509 = OwnedOpenSSLPtr<X509, X509_free>;
using OwnedOpenSSLBuffer = std::unique_ptr<uint8_t, OpenSSLFreeDeleter>;

// Logging utils.
bool g_enable_logging = false;
void LogInfo(const std::string &message) {
  if (g_enable_logging) {
    std::cout << "tls_offload.cpp: " << message << "...." << std::endl;
  }
}

// Part 1. First we need a way to attach `CustomKey` to `EVP_PKEY`s that we will
// hand to OpenSSL. OpenSSL does this with "ex data". The following
// `SetCustomKey` and `GetCustomKey` provide the setter and getter methods.

// "ex data" will be allocated once globally by `CreateEngineOnceGlobally`
// method.
int g_rsa_ex_index = -1, g_ec_ex_index = -1;

void FreeExData(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl,
                void *argp) {
  // CustomKey is created by ConfigureSslContext, so we need to delete the
  // CustomKey stored in ex_data.
  if (g_enable_logging) {
    std::cout << "deleting custom_key at: " << ptr << std::endl;
  }
  delete static_cast<CustomKey *>(ptr);
}

bool SetCustomKey(EVP_PKEY *pkey, CustomKey *key) {
  if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
    LogInfo("setting RSA custom key");
    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    return rsa && RSA_set_ex_data(rsa, g_rsa_ex_index, key);
  }
  if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
    LogInfo("setting EC custom key");
    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    return ec_key && EC_KEY_set_ex_data(ec_key, g_ec_ex_index, key);
  }
  return false;
}

CustomKey *GetCustomKey(EVP_PKEY *pkey) {
  if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
    const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    return rsa ? static_cast<CustomKey *>(RSA_get_ex_data(rsa, g_rsa_ex_index))
               : nullptr;
  }
  if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
    const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    return ec_key ? static_cast<CustomKey *>(
                        EC_KEY_get_ex_data(ec_key, g_ec_ex_index))
                  : nullptr;
  }
  return nullptr;
}

// Part 2. Next we make an `EVP_PKEY_METHOD` that can call `CustomKey::Sign`.

// As OpenSSL sets up an `EVP_PKEY_CTX`, it will configure it with
// `EVP_PKEY_CTRL_*` calls. This structure collects all the values.
struct OpenSSLParams {
  const EVP_MD *md = nullptr;
  int rsa_padding = RSA_PKCS1_PADDING;
  int rsa_pss_salt_len = -2;
  const EVP_MD *rsa_pss_mgf1_md = nullptr;
};

int CustomInit(EVP_PKEY_CTX *ctx) {
  EVP_PKEY_CTX_set_data(ctx, new OpenSSLParams);
  return 1;
}

void CustomCleanup(EVP_PKEY_CTX *ctx) {
  OpenSSLParams *params =
      static_cast<OpenSSLParams *>(EVP_PKEY_CTX_get_data(ctx));
  delete params;
}

int CustomCtrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
  OpenSSLParams *params =
      static_cast<OpenSSLParams *>(EVP_PKEY_CTX_get_data(ctx));
  // `EVP_PKEY_CTRL_*` values correspond to `EVP_PKEY_CTX` APIs. See
  // https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_CTX_get_signature_md.html
  switch (type) {
    case EVP_PKEY_CTRL_MD:  // EVP_PKEY_CTX_set_signature_md
      params->md = static_cast<const EVP_MD *>(p2);
      return 1;
    case EVP_PKEY_CTRL_GET_MD:  // EVP_PKEY_CTX_get_signature_md
      *static_cast<const EVP_MD **>(p2) = params->md;
      return 1;
    case EVP_PKEY_CTRL_RSA_PADDING:  // EVP_PKEY_CTX_set_rsa_padding
      params->rsa_padding = p1;
      return 1;
    case EVP_PKEY_CTRL_GET_RSA_PADDING:  // EVP_PKEY_CTX_get_rsa_padding
      *static_cast<int *>(p2) = params->rsa_padding;
      return 1;
    case EVP_PKEY_CTRL_RSA_PSS_SALTLEN:  // EVP_PKEY_CTX_set_rsa_pss_saltlen
      params->rsa_pss_salt_len = p1;
      return 1;
    case EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN:  // EVP_PKEY_CTX_get_rsa_pss_saltlen
      *static_cast<int *>(p2) = params->rsa_pss_salt_len;
      return 1;
    case EVP_PKEY_CTRL_RSA_MGF1_MD:  // EVP_PKEY_CTX_set_rsa_mgf1_md
      // OpenSSL never actually configures this and relies on the default, but
      // it is, in theory, part of the PSS API.
      params->rsa_pss_mgf1_md = static_cast<const EVP_MD *>(p2);
      return 1;
    case EVP_PKEY_CTRL_GET_RSA_MGF1_MD:  // EVP_PKEY_CTX_get_rsa_mgf1_md
      // If unspecified, the MGF-1 digest defaults to the signing digest.
      *static_cast<const EVP_MD **>(p2) =
          params->rsa_pss_mgf1_md ? params->rsa_pss_mgf1_md : params->md;
      return 1;
  }
  if (g_enable_logging) {
    std::cout << "unrecognized EVP ctrl value:" << type << std::endl;
  }
  return 0;
}

// This function will call CustomKey::Sign to sign the digest of tbs (the bytes
// to be signed) and write back to sig (the signature holder). The supported
// algorithms are:
// (1) ECDSA with SHA256
// (2) RSAPSS with SHA256, MGF-1, salt length = digest length
int CustomDigestSign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *sig_len,
                     const unsigned char *tbs, size_t tbs_len) {
  EVP_PKEY_CTX *pctx = EVP_MD_CTX_pkey_ctx(ctx);

  // Grab the custom key.
  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(pctx);
  if (!pkey) {
    LogInfo("Could not get EVP_PKEY");
    return 0;
  }
  CustomKey *key =
      GetCustomKey(EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_pkey_ctx(ctx)));
  if (!key) {
    LogInfo("Could not get CustomKey from EVP_PKEY");
    return 0;
  }

  // For signature scheme, we only support
  // (1) ECDSA with SHA256
  // (2) RSAPSS with SHA256, MGF-1, salt length = digest length
  if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
    const EVP_MD *md;
    if (EVP_PKEY_CTX_get_signature_md(pctx, &md) != 1 ||
        EVP_MD_nid(md) != NID_sha256) {
      LogInfo("Unsupported ECDSA hash");
      return 0;
    }
  } else if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
    const EVP_MD *md;
    if (EVP_PKEY_CTX_get_signature_md(pctx, &md) != 1 ||
        EVP_MD_nid(md) != NID_sha256) {
      LogInfo("Unsupported ECDSA hash");
      return 0;
    }
    int val;
    if (EVP_PKEY_CTX_get_rsa_padding(pctx, &val) != 1 ||
        val != RSA_PKCS1_PSS_PADDING) {
      LogInfo("Unsupported RSA padding");
      return 0;
    }
    if (EVP_PKEY_CTX_get_rsa_mgf1_md(pctx, &md) != 1 ||
        EVP_MD_nid(md) != NID_sha256) {
      LogInfo("Unsupported RSA-PSS MGF-1 hash");
      return 0;
    }
    // The salt length could either be specified explicitly, or as -1.
    if (EVP_PKEY_CTX_get_rsa_pss_saltlen(pctx, &val) != 1 ||
        (val != EVP_MD_size(md) && val != -1)) {
      LogInfo("Unsupported RSA-PSS salt length");
      return 0;
    }
  } else {
    LogInfo("Unsupported key");
    return 0;
  }

  if (g_enable_logging) {
    std::cout << "before calling key->Sign, sig len: " << *sig_len << std::endl;
  }
  int res = key->Sign(sig, sig_len, tbs, tbs_len);
  if (g_enable_logging) {
    std::cout << "after calling key->Sign, sig len: " << *sig_len
              << ", result: " << res << std::endl;
  }
  return res;
}

// Each `EVP_PKEY_METHOD` is associated with a key type, so we must make a
// separate one for each.
OwnedEVP_PKEY_METHOD MakeCustomMethod(int nid) {
  OwnedEVP_PKEY_METHOD method(EVP_PKEY_meth_new(
      nid, EVP_PKEY_FLAG_SIGCTX_CUSTOM | EVP_PKEY_FLAG_AUTOARGLEN));
  if (!method) {
    return nullptr;
  }

  EVP_PKEY_meth_set_init(method.get(), CustomInit);
  EVP_PKEY_meth_set_cleanup(method.get(), CustomCleanup);
  EVP_PKEY_meth_set_ctrl(method.get(), CustomCtrl, nullptr);
  EVP_PKEY_meth_set_digestsign(method.get(), CustomDigestSign);
  return method;
}

// Part 3. OpenSSL doesn't pick up our `EVP_PKEY_METHOD` unless it is wrapped in
// an `ENGINE`. We don't `ENGINE_add` this engine, to avoid it accidentally
// overriding normal keys.

// These variables will be created once globally by `CreateEngineOnceGlobally`.
EVP_PKEY_METHOD *g_custom_rsa_pkey_method, *g_custom_ec_pkey_method;

int EngineGetMethods(ENGINE *e, EVP_PKEY_METHOD **out_method,
                     const int **out_nids, int nid) {
  if (!out_method) {
    static const int kNIDs[] = {EVP_PKEY_EC, EVP_PKEY_RSA};
    *out_nids = kNIDs;
    return sizeof(kNIDs) / sizeof(kNIDs[0]);
  }

  switch (nid) {
    case EVP_PKEY_EC:
      *out_method = g_custom_ec_pkey_method;
      return 1;
    case EVP_PKEY_RSA:
      *out_method = g_custom_rsa_pkey_method;
      return 1;
  }
  return 0;
}

// Part 4. Now we can make custom `EVP_PKEY`s that wrap our `CustomKey` objects.
// Note we require the caller provide the public key, here in a certificate.
// This is necessary so OpenSSL knows how much to size its various buffers.

OwnedEVP_PKEY MakeCustomEvpPkey(CustomKey *custom_key, X509 *cert,
                                ENGINE *custom_engine) {
  unsigned char *spki = nullptr;
  int spki_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &spki);
  if (spki_len < 0) {
    return nullptr;
  }
  OwnedOpenSSLBuffer owned_spki(spki);

  const unsigned char *ptr = spki;
  OwnedX509_PUBKEY pubkey(d2i_X509_PUBKEY(nullptr, &ptr, spki_len));
  if (!pubkey) {
    return nullptr;
  }

  OwnedEVP_PKEY wrapped(X509_PUBKEY_get(pubkey.get()));
  if (!wrapped || !EVP_PKEY_set1_engine(wrapped.get(), custom_engine) ||
      !SetCustomKey(wrapped.get(), custom_key)) {
    return nullptr;
  }
  return wrapped;
}

// Part 5. Now we can attach the CustomKey and cert to SSL context.

bool AttachKeyCertToSslContext(CustomKey *custom_key, const char *cert,
                               SSL_CTX *ctx, ENGINE *custom_engine) {
  OwnedBIO bio(BIO_new_mem_buf(cert, strlen(cert)));
  if (!bio) {
    LogInfo("failed to read cert into bio");
    return false;
  }
  OwnedX509 x509 =
      OwnedX509(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));

  OwnedEVP_PKEY wrapped_key =
      MakeCustomEvpPkey(custom_key, x509.get(), custom_engine);
  if (!wrapped_key) {
    LogInfo("failed to create custom key");
    return false;
  }

  static const char *sig_algs_list = "RSA-PSS+SHA256:ECDSA+SHA256";
  if (!SSL_CTX_set1_sigalgs_list(ctx, sig_algs_list)) {
    LogInfo("failed to call SSL_CTX_set1_sigalgs_list");
    return false;
  }
  if (!SSL_CTX_use_PrivateKey(ctx, wrapped_key.get())) {
    LogInfo("SSL_CTX_use_PrivateKey failed");
    return false;
  }
  if (!SSL_CTX_use_certificate(ctx, x509.get())) {
    LogInfo("SSL_CTX_use_certificate failed");
    return false;
  }
  if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
    LogInfo("SSL_CTX_set_min_proto_version failed");
    return false;
  }
  LogInfo("AttachKeyCertToSslContext is successful");
  return true;
}

// Part 6. The following functions create a OpenSSL engine, during which all the
// `g_*` global variables such as `g_rsa/ec_ex_index`,
// `g_custom_rsa/ec_pkey_method` etc will be initialized. Note that
// `CreateEngineOnceGlobally` should be used because it creates all these global
// variables and the engine only once, and it is thread safe.

ENGINE *CreateEngineHelper() {
  g_enable_logging =
      static_cast<bool>(getenv("ENABLE_ENTERPRISE_CERTIFICATE_LOGS"));
  LogInfo("Creating engine...");

  // Allocate "ex data". We need a way to attach `CustomKey` to `EVP_PKEY`s that
  // we will hand to OpenSSL. OpenSSL does this with "ex data"
  g_rsa_ex_index =
      RSA_get_ex_new_index(0, nullptr, nullptr, nullptr, FreeExData);
  g_ec_ex_index =
      EC_KEY_get_ex_new_index(0, nullptr, nullptr, nullptr, FreeExData);
  if (g_rsa_ex_index < 0 || g_ec_ex_index < 0) {
    LogInfo("Error allocating ex data");
    return nullptr;
  }

  // Create custom method
  g_custom_rsa_pkey_method = MakeCustomMethod(EVP_PKEY_RSA).release();
  g_custom_ec_pkey_method = MakeCustomMethod(EVP_PKEY_EC).release();
  if (!g_custom_rsa_pkey_method || !g_custom_ec_pkey_method) {
    LogInfo("failed to make custom methods");
    return nullptr;
  }

  // Ceate a custom engine
  OwnedENGINE engine(ENGINE_new());
  if (!engine || !ENGINE_set_pkey_meths(engine.get(), EngineGetMethods)) {
    LogInfo("failed to init engine");
    return nullptr;
  }
  return engine.release();
}

ENGINE *CreateEngineOnceGlobally() {
  static ENGINE *custom_engine = CreateEngineHelper();
  return custom_engine;
}

}  // namespace

// Part 7. The function below is exported to the compiled shared library
// binary. For all these function, we need to add `extern "C"` to avoid name
// mangling, and `__declspec(dllexport)` for Windows.
// Note that the caller owns the memory for all the pointers passed in as a
// parameter, and caller is responsible for freeing these memories.

// Configure the SSL context to use the provide client side cert and custom key.
extern "C"
#ifdef _WIN32
    __declspec(dllexport)
#endif
        int ConfigureSslContext(SignFunc sign_func, const char *cert,
                                SSL_CTX *ctx) {
  if (!sign_func) {
    return 0;
  }

  if (!cert) {
    return 0;
  }

  if (!ctx) {
    return 0;
  }

  ENGINE *custom_engine = CreateEngineOnceGlobally();
  if (!custom_engine) {
    LogInfo("failed to create engine");
    return 0;
  }

  // The created custom_key will be deleted by FreeExData.
  CustomKey *custom_key = new CustomKey(sign_func);
  if (g_enable_logging) {
    std::cout << "created custom_key at: " << custom_key << std::endl;
  }

  if (!AttachKeyCertToSslContext(custom_key, cert, ctx, custom_engine)) {
    return 0;
  }
  LogInfo("ConfigureSslContext is successful");
  return 1;
}
