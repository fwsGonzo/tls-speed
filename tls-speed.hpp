#include <string>
#include <memory>
#include <cstddef>
#include <climits>
#include <iostream>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>

#ifndef tls_speed_hpp
#define tls_speed_hpp

const size_t KILOBYTE = 1024;
const size_t MEGABYTE = KILOBYTE * 1024;
const size_t GIGABYTE = MEGABYTE * 1024;
const size_t TERABYTE = GIGABYTE * 1024;

const uint_fast8_t GCM_NONCE_EXPLICIT_LEN = 8;
const uint_fast8_t GCM_SALT_LEN = 4;
const uint_fast8_t GCM_IV_LEN = GCM_NONCE_EXPLICIT_LEN + GCM_SALT_LEN;
const uint_fast8_t GCM_TAG_LEN = 16;

enum PFS_TYPE {
    none = 0,
    dhe,
    ecdhe
};

struct tls_config {
    std::string cipher_key;
    EVP_PKEY *mac_key;
    std::string iv;
    bool gcm_random_iv;
    size_t pkey_bits;
    int pkey_algo;
    enum PFS_TYPE pfs_type;
    const EVP_CIPHER *cipher_algo;
    const EVP_MD *mac_algo;
    const EVP_MD *prf_algo;
    int ec_curve;
};

struct user_args {
    size_t tls_record_size;
    size_t transfer_size;
    size_t tx_count;
    size_t pkey_bits;
    size_t tx_size_base;
    std::string cipher_name;
    std::string mac_name;
    std::string prf_name;
    std::string pfs_type_name;
    std::string tx_scale_name;
    std::string ec_curve_name;
    std::string pkey_type_name;
};

class openssl_hmac_ctx {
public:
    openssl_hmac_ctx();
    ~openssl_hmac_ctx();
    HMAC_CTX ctx;
};

openssl_hmac_ctx::openssl_hmac_ctx() {
    HMAC_CTX_init(&this->ctx);
}

openssl_hmac_ctx::~openssl_hmac_ctx() {
    HMAC_CTX_cleanup(&this->ctx);
}

class openssl_md_ctx {
public:
    openssl_md_ctx();
    ~openssl_md_ctx();
    EVP_MD_CTX ctx;
};

openssl_md_ctx::openssl_md_ctx() {
    EVP_MD_CTX_init(&this->ctx);
}

openssl_md_ctx::~openssl_md_ctx() {
    EVP_MD_CTX_cleanup(&this->ctx);
}

class openssl_cipher_ctx {
public:
    openssl_cipher_ctx();
    ~openssl_cipher_ctx();
    EVP_CIPHER_CTX ctx;
};

openssl_cipher_ctx::openssl_cipher_ctx() {
    EVP_CIPHER_CTX_init(&this->ctx);
}

openssl_cipher_ctx::~openssl_cipher_ctx() {
    EVP_CIPHER_CTX_cleanup(&this->ctx);
}

class openssl_pkey_ctx {
public:
    openssl_pkey_ctx(int);
    openssl_pkey_ctx(EVP_PKEY *);
    ~openssl_pkey_ctx();
    EVP_PKEY_CTX *ctx;
};

openssl_pkey_ctx::openssl_pkey_ctx(int id) {
    ctx = EVP_PKEY_CTX_new_id(id, NULL);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id");
}

openssl_pkey_ctx::openssl_pkey_ctx(EVP_PKEY *pkey) {
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id");
}

openssl_pkey_ctx::~openssl_pkey_ctx() {
    EVP_PKEY_CTX_free(ctx);
}

class openssl_rsa {
    public:
    openssl_rsa(RSA *);
    ~openssl_rsa();
    RSA *rsa;
};

openssl_rsa::openssl_rsa(RSA *r) {
    rsa = r;
}

openssl_rsa::~openssl_rsa() {
    if (rsa) RSA_free(rsa);
}

class openssl_pkey {
public:
    openssl_pkey(EVP_PKEY *);
    openssl_pkey(void);
    ~openssl_pkey();
    EVP_PKEY *pkey;
};

openssl_pkey::openssl_pkey(void) {
    pkey = EVP_PKEY_new();
}

openssl_pkey::openssl_pkey(EVP_PKEY *p) {
    pkey = p;
}

openssl_pkey::~openssl_pkey() {
    if (pkey) EVP_PKEY_free(pkey);
}

class openssl_dh {
public:
    openssl_dh();
    ~openssl_dh();
    DH *dh;
};

openssl_dh::openssl_dh() {
    dh = DH_new();
}

openssl_dh::~openssl_dh() {
    DH_free(dh);
}

#endif
