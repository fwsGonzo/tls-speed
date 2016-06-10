#include "tls-speed.hpp"
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/conf.h>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <getopt.h>

/*
 * The keys for each block are generally generated via a PRF run over data
 * already generated/part of the protocol. Since we're just pretending to be a
 * TLS server, what the data is doesn't matter, only the length.
 * That said I'm not sure how much data is fed into the PRF, so I guessed.
 */
std::string sixty_four_bytes("1234567890123456123456789012345612345678901234561234567890123456");

std::string get_random(size_t size)
{
    char random[size];
    static std::ifstream urand("/dev/urandom", std::ifstream::in | std::ios::binary);

    urand.read(random, size);

    return std::string(random, size);
}

void openssl_seed_rand(void)
{
    std::string rand = get_random(16);
    RAND_seed(rand.c_str(), static_cast<unsigned int>(rand.length()));
}

void throw_openssl_error(std::string call)
{
    std::string msg(ERR_error_string(ERR_get_error(), NULL));
    throw std::runtime_error("openssl error: " + call + "\n" + msg);
}

/* Build 2048-bit MODP Group with 256-bit Prime Order Subgroup from RFC 5114 */
std::shared_ptr<openssl_dh> get_dh_params(void)
{
    static const unsigned char dh2048_p[] = {
        0x87, 0xA8, 0xE6, 0x1D, 0xB4, 0xB6, 0x66, 0x3C, 0xFF, 0xBB, 0xD1, 0x9C,
        0x65, 0x19, 0x59, 0x99, 0x8C, 0xEE, 0xF6, 0x08, 0x66, 0x0D, 0xD0, 0xF2,
        0x5D, 0x2C, 0xEE, 0xD4, 0x43, 0x5E, 0x3B, 0x00, 0xE0, 0x0D, 0xF8, 0xF1,
        0xD6, 0x19, 0x57, 0xD4, 0xFA, 0xF7, 0xDF, 0x45, 0x61, 0xB2, 0xAA, 0x30,
        0x16, 0xC3, 0xD9, 0x11, 0x34, 0x09, 0x6F, 0xAA, 0x3B, 0xF4, 0x29, 0x6D,
        0x83, 0x0E, 0x9A, 0x7C, 0x20, 0x9E, 0x0C, 0x64, 0x97, 0x51, 0x7A, 0xBD,
        0x5A, 0x8A, 0x9D, 0x30, 0x6B, 0xCF, 0x67, 0xED, 0x91, 0xF9, 0xE6, 0x72,
        0x5B, 0x47, 0x58, 0xC0, 0x22, 0xE0, 0xB1, 0xEF, 0x42, 0x75, 0xBF, 0x7B,
        0x6C, 0x5B, 0xFC, 0x11, 0xD4, 0x5F, 0x90, 0x88, 0xB9, 0x41, 0xF5, 0x4E,
        0xB1, 0xE5, 0x9B, 0xB8, 0xBC, 0x39, 0xA0, 0xBF, 0x12, 0x30, 0x7F, 0x5C,
        0x4F, 0xDB, 0x70, 0xC5, 0x81, 0xB2, 0x3F, 0x76, 0xB6, 0x3A, 0xCA, 0xE1,
        0xCA, 0xA6, 0xB7, 0x90, 0x2D, 0x52, 0x52, 0x67, 0x35, 0x48, 0x8A, 0x0E,
        0xF1, 0x3C, 0x6D, 0x9A, 0x51, 0xBF, 0xA4, 0xAB, 0x3A, 0xD8, 0x34, 0x77,
        0x96, 0x52, 0x4D, 0x8E, 0xF6, 0xA1, 0x67, 0xB5, 0xA4, 0x18, 0x25, 0xD9,
        0x67, 0xE1, 0x44, 0xE5, 0x14, 0x05, 0x64, 0x25, 0x1C, 0xCA, 0xCB, 0x83,
        0xE6, 0xB4, 0x86, 0xF6, 0xB3, 0xCA, 0x3F, 0x79, 0x71, 0x50, 0x60, 0x26,
        0xC0, 0xB8, 0x57, 0xF6, 0x89, 0x96, 0x28, 0x56, 0xDE, 0xD4, 0x01, 0x0A,
        0xBD, 0x0B, 0xE6, 0x21, 0xC3, 0xA3, 0x96, 0x0A, 0x54, 0xE7, 0x10, 0xC3,
        0x75, 0xF2, 0x63, 0x75, 0xD7, 0x01, 0x41, 0x03, 0xA4, 0xB5, 0x43, 0x30,
        0xC1, 0x98, 0xAF, 0x12, 0x61, 0x16, 0xD2, 0x27, 0x6E, 0x11, 0x71, 0x5F,
        0x69, 0x38, 0x77, 0xFA, 0xD7, 0xEF, 0x09, 0xCA, 0xDB, 0x09, 0x4A, 0xE9,
        0x1E, 0x1A, 0x15, 0x97
    };
    static const unsigned char dh2048_g[] = {
        0x3F, 0xB3, 0x2C, 0x9B, 0x73, 0x13, 0x4D, 0x0B, 0x2E, 0x77, 0x50, 0x66,
        0x60, 0xED, 0xBD, 0x48, 0x4C, 0xA7, 0xB1, 0x8F, 0x21, 0xEF, 0x20, 0x54,
        0x07, 0xF4, 0x79, 0x3A, 0x1A, 0x0B, 0xA1, 0x25, 0x10, 0xDB, 0xC1, 0x50,
        0x77, 0xBE, 0x46, 0x3F, 0xFF, 0x4F, 0xED, 0x4A, 0xAC, 0x0B, 0xB5, 0x55,
        0xBE, 0x3A, 0x6C, 0x1B, 0x0C, 0x6B, 0x47, 0xB1, 0xBC, 0x37, 0x73, 0xBF,
        0x7E, 0x8C, 0x6F, 0x62, 0x90, 0x12, 0x28, 0xF8, 0xC2, 0x8C, 0xBB, 0x18,
        0xA5, 0x5A, 0xE3, 0x13, 0x41, 0x00, 0x0A, 0x65, 0x01, 0x96, 0xF9, 0x31,
        0xC7, 0x7A, 0x57, 0xF2, 0xDD, 0xF4, 0x63, 0xE5, 0xE9, 0xEC, 0x14, 0x4B,
        0x77, 0x7D, 0xE6, 0x2A, 0xAA, 0xB8, 0xA8, 0x62, 0x8A, 0xC3, 0x76, 0xD2,
        0x82, 0xD6, 0xED, 0x38, 0x64, 0xE6, 0x79, 0x82, 0x42, 0x8E, 0xBC, 0x83,
        0x1D, 0x14, 0x34, 0x8F, 0x6F, 0x2F, 0x91, 0x93, 0xB5, 0x04, 0x5A, 0xF2,
        0x76, 0x71, 0x64, 0xE1, 0xDF, 0xC9, 0x67, 0xC1, 0xFB, 0x3F, 0x2E, 0x55,
        0xA4, 0xBD, 0x1B, 0xFF, 0xE8, 0x3B, 0x9C, 0x80, 0xD0, 0x52, 0xB9, 0x85,
        0xD1, 0x82, 0xEA, 0x0A, 0xDB, 0x2A, 0x3B, 0x73, 0x13, 0xD3, 0xFE, 0x14,
        0xC8, 0x48, 0x4B, 0x1E, 0x05, 0x25, 0x88, 0xB9, 0xB7, 0xD2, 0xBB, 0xD2,
        0xDF, 0x01, 0x61, 0x99, 0xEC, 0xD0, 0x6E, 0x15, 0x57, 0xCD, 0x09, 0x15,
        0xB3, 0x35, 0x3B, 0xBB, 0x64, 0xE0, 0xEC, 0x37, 0x7F, 0xD0, 0x28, 0x37,
        0x0D, 0xF9, 0x2B, 0x52, 0xC7, 0x89, 0x14, 0x28, 0xCD, 0xC6, 0x7E, 0xB6,
        0x18, 0x4B, 0x52, 0x3D, 0x1D, 0xB2, 0x46, 0xC3, 0x2F, 0x63, 0x07, 0x84,
        0x90, 0xF0, 0x0E, 0xF8, 0xD6, 0x47, 0xD1, 0x48, 0xD4, 0x79, 0x54, 0x51,
        0x5E, 0x23, 0x27, 0xCF, 0xEF, 0x98, 0xC5, 0x82, 0x66, 0x4B, 0x4C, 0x0F,
        0x6C, 0xC4, 0x16, 0x59
    };
    auto dh = std::make_shared<openssl_dh>();

    dh->dh->p = BN_bin2bn(dh2048_p, sizeof(dh2048_p), NULL);
    if (!dh->dh->p) throw_openssl_error("BN_bin2bn");
    dh->dh->g = BN_bin2bn(dh2048_g, sizeof(dh2048_g), NULL);
    if (!dh->dh->p) throw_openssl_error("BN_bin2bn 2");
    return dh;
}

std::shared_ptr<openssl_pkey> gen_pkey(struct tls_config *tconfig)
{
    int r;
    openssl_pkey_ctx pctx(tconfig->pkey_algo);
    EVP_PKEY *temp_pkey = NULL;

    r = EVP_PKEY_keygen_init(pctx.ctx);
    if (r != 1) throw_openssl_error("EVP_PKEY_keygen_init");

    if (tconfig->pkey_algo == EVP_PKEY_RSA) {
        r = EVP_PKEY_CTX_set_rsa_keygen_bits(pctx.ctx, static_cast<int>(tconfig->pkey_bits));
    } else {
        throw std::runtime_error("Unknown pkey algo!");
    }
    if (r != 1) throw_openssl_error("Setting pkey bits");

    r = EVP_PKEY_keygen(pctx.ctx, &temp_pkey);
    if (r != 1) throw_openssl_error("EVP_PKEY_keygen");

    return std::make_shared<openssl_pkey>(temp_pkey);
}

std::string rsa_public_encrypt(EVP_PKEY *public_key, std::string data)
{
    int r;
    size_t outlen;

    /* Don't be safe, be fast and reckless.
    if (data.length() > INT_MAX) throw std::runtime_error("data is too large");
    */

    openssl_pkey_ctx ctx(public_key);

    r = EVP_PKEY_encrypt_init(ctx.ctx);
    if (r == -1) throw_openssl_error("EVP_PKEY_encrypt_init");

    r = EVP_PKEY_CTX_set_rsa_padding(ctx.ctx, RSA_PKCS1_PADDING);
    if (r == -1) throw_openssl_error("EVP_PKEY_CTX_set_rsa_padding");

    r = EVP_PKEY_encrypt(
        ctx.ctx,
        NULL,
        &outlen,
        const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(data.c_str())),
        static_cast<int>(data.length())
    );
    if (r == -1) throw_openssl_error("EVP_PKEY_encrypt");

    char outbuf[outlen];
    r = EVP_PKEY_encrypt(
        ctx.ctx,
        reinterpret_cast<unsigned char *>(outbuf),
        &outlen,
        const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(data.c_str())),
        static_cast<int>(data.length())
    );
    if (r == -1) throw_openssl_error("EVP_PKEY_encrypt 2");

    return std::string(outbuf, outlen);
}

std::string rsa_private_decrypt(EVP_PKEY *public_key, std::string data)
{
    int r;
    size_t outlen;

    /* Don't be safe, be fast and reckless.
    if (data.length() > INT_MAX) throw std::runtime_error("data is too large");
    */

    openssl_pkey_ctx ctx(public_key);

    r = EVP_PKEY_decrypt_init(ctx.ctx);
    if (r == -1) throw_openssl_error("EVP_PKEY_decrypt_init");

    r = EVP_PKEY_CTX_set_rsa_padding(ctx.ctx, RSA_PKCS1_PADDING);
    if (r == -1) throw_openssl_error("EVP_PKEY_CTX_set_rsa_padding");

    r = EVP_PKEY_decrypt(
        ctx.ctx,
        NULL,
        &outlen,
        const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(data.c_str())),
        static_cast<int>(data.length())
    );
    if (r == -1) throw_openssl_error("EVP_PKEY_decrypt");

    char outbuf[outlen];
    r = EVP_PKEY_decrypt(
        ctx.ctx,
        reinterpret_cast<unsigned char *>(outbuf),
        &outlen,
        const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(data.c_str())),
        static_cast<int>(data.length())
    );
    if (r == -1) throw_openssl_error("EVP_PKEY_decrypt 2");

    return std::string(outbuf, outlen);
}

uint64_t pkey_sign(struct tls_config *tconfig, EVP_PKEY *public_key, std::string data)
{
    int r;
    size_t siglen;
    openssl_md_ctx md;

    /* Don't be safe, be fast and reckless.
    if (data.length() > UINT_MAX) throw std::runtime_error("data is too large");
    */

    r = EVP_DigestInit_ex(&md.ctx, tconfig->mac_algo, NULL);
    if (r != 1) throw_openssl_error("EVP_DigestInit_ex");

    r = EVP_DigestSignInit(&md.ctx, NULL, tconfig->mac_algo, NULL, public_key);
    if (r != 1) throw_openssl_error("EVP_DigestSignInit");

    r = EVP_DigestSignUpdate(&md.ctx,
                             reinterpret_cast<const void *>(data.c_str()),
                             static_cast<unsigned int>(data.length())
    );
    if (r != 1) throw_openssl_error("EVP_DigestSignUpdate");

    r = EVP_DigestSignFinal(&md.ctx, NULL, &siglen);
    if (r != 1) throw_openssl_error("EVP_DigestSignFinal");

    unsigned char outbuf[siglen];
    r = EVP_DigestSignFinal(&md.ctx, outbuf, &siglen);
    if (r != 1) throw_openssl_error("EVP_DigestSignFinal 2");

    return siglen;
}

uint64_t hmac_block(struct tls_config *tconfig, std::string data)
{
    return pkey_sign(tconfig, tconfig->mac_key, data);
}

std::string hash_block(const EVP_MD *md, std::string data)
{
    char computed_hash[EVP_MAX_MD_SIZE];
    int r;
    unsigned int computed_len;
    openssl_md_ctx ctx;

    /*
    if (data.length() > INT_MAX) throw std::runtime_error("data is too large");
    */

    r = EVP_DigestInit_ex(&ctx.ctx, md, NULL);
    if (r != 1) throw_openssl_error("EVP_DigestInit_ex");

    r = EVP_DigestUpdate(&ctx.ctx,
                    reinterpret_cast<const unsigned char *>(data.c_str()),
                    static_cast<int>(data.length())
                    );
    if (r != 1) throw_openssl_error("EVP_DigestUpdate");

    r = EVP_DigestFinal_ex(&ctx.ctx, reinterpret_cast<unsigned char *>(computed_hash), &computed_len);
    if (r != 1) throw_openssl_error("EVP_DigestFinal_ex");

    return std::string(computed_hash, computed_len);
}

/* Do the TLS 1.1 thing and get a new IV per record. */
uint64_t encrypt_block(struct tls_config *tconfig, std::string data)
{
    int r, encrypted_size, final_encrypted_size;
    openssl_cipher_ctx ctx;
    unsigned char outbuf[data.length() + EVP_CIPHER_block_size(tconfig->cipher_algo)];
    std::string iv = hash_block(tconfig->prf_algo, sixty_four_bytes);

    /*
    if (data.length() > INT_MAX) throw std::runtime_error("key is too large");

    if (data.length() % EVP_CIPHER_block_size(tconfig->cipher_algo) != 0) {
        throw std::runtime_error("Data length not a multiple of cipher block size");
    }
    */

    r = EVP_EncryptInit_ex(&ctx.ctx,
                           tconfig->cipher_algo,
                           NULL,
                           reinterpret_cast<const unsigned char *>(tconfig->cipher_key.c_str()),
                           reinterpret_cast<const unsigned char *>(iv.c_str())
                           );
    if (r != 1) throw_openssl_error("EVP_EncryptInit_ex");

    r = EVP_EncryptUpdate(&ctx.ctx,
                          outbuf,
                          &encrypted_size,
                          reinterpret_cast<const unsigned char *>(data.c_str()),
                          static_cast<int>(data.length())
                          );
    if (r != 1) throw_openssl_error("EVP_EncryptUpdate");

    r = EVP_EncryptFinal_ex(&ctx.ctx,
                            outbuf + encrypted_size,
                            &final_encrypted_size
                            );
    if (r != 1) throw_openssl_error("EVP_EncryptFinal_ex");

    return encrypted_size + final_encrypted_size;
}

uint64_t encrypt_block_gcm(struct tls_config *tconfig, std::string iv, std::string data, uint64_t *macd)
{
    int r, encrypted_size, final_encrypted_size;
    openssl_cipher_ctx ctx;
    unsigned char outbuf[data.length() + EVP_CIPHER_block_size(tconfig->cipher_algo)];
    unsigned char tag[GCM_TAG_LEN];

    /*
    if (data.length() > INT_MAX) throw std::runtime_error("key is too large");

    if (data.length() % EVP_CIPHER_block_size(tconfig->cipher_algo) != 0) {
        throw std::runtime_error("Data length not a multiple of cipher block size");
    }
    */

    iv += hash_block(tconfig->prf_algo, sixty_four_bytes);
    r = EVP_EncryptInit_ex(&ctx.ctx,
                           tconfig->cipher_algo,
                           NULL,
                           NULL,
                           NULL
                           );
    if (r != 1) throw_openssl_error("EVP_EncryptInit_ex");

    r = EVP_CIPHER_CTX_ctrl(&ctx.ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL);
    if (r != 1) throw_openssl_error("EVP_CIPHER_CTX_ctrl");

    r = EVP_EncryptInit_ex(&ctx.ctx,
                           NULL,
                           NULL,
                           reinterpret_cast<const unsigned char *>(tconfig->cipher_key.c_str()),
                           reinterpret_cast<const unsigned char *>(iv.c_str())
                           );
    if (r != 1) throw_openssl_error("EVP_EncryptInit_ex 2");

    r = EVP_EncryptUpdate(&ctx.ctx,
                          NULL,
                          &encrypted_size,
                          reinterpret_cast<const unsigned char *>(iv.c_str()),
                          static_cast<int>(iv.length())
                          );
    if (r != 1) throw_openssl_error("EVP_EncryptUpdate");

    r = EVP_EncryptUpdate(&ctx.ctx,
                          outbuf,
                          &encrypted_size,
                          reinterpret_cast<const unsigned char *>(data.c_str()),
                          static_cast<int>(data.length())
                          );
    if (r != 1) throw_openssl_error("EVP_EncryptUpdate 2");

    r = EVP_EncryptFinal_ex(&ctx.ctx,
                            outbuf + encrypted_size,
                            &final_encrypted_size
                            );
    if (r != 1) throw_openssl_error("EVP_EncryptFinal_ex");

    r = EVP_CIPHER_CTX_ctrl(&ctx.ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag);
    if (r == 0) throw_openssl_error("EVP_CIPHER_CTX_ctrl");

    *macd += GCM_TAG_LEN;
    return encrypted_size + final_encrypted_size;
}

/* PKEY types must be DH or ECDH */
std::string pfs_derive(EVP_PKEY *our_key, EVP_PKEY *their_key, const EVP_MD *md)
{
    int r;
    size_t skeylen;
    openssl_pkey_ctx ctx(our_key);

    r = EVP_PKEY_derive_init(ctx.ctx);
    if (r != 1) throw_openssl_error("EVP_PKEY_derive_init");

    r = EVP_PKEY_derive_set_peer(ctx.ctx, their_key);
    if (r != 1) throw_openssl_error("EVP_PKEY_derive_set_peer");

    r = EVP_PKEY_derive(ctx.ctx, NULL, &skeylen);
    if (r != 1) throw_openssl_error("EVP_PKEY_derive");

    char skey[skeylen];
    r = EVP_PKEY_derive(ctx.ctx, reinterpret_cast<unsigned char *>(skey), &skeylen);
    if (r != 1) throw_openssl_error("EVP_PKEY_derive 2");

    std::string derived(skey, skeylen);
    return hash_block(md, derived);
}

std::shared_ptr<openssl_pkey> gen_ec_key(const struct tls_config *tconfig)
{
    int r;
    openssl_pkey_ctx ctx(EVP_PKEY_EC);
    openssl_pkey params(NULL);
    EVP_PKEY *pkey = NULL;

    r = EVP_PKEY_paramgen_init(ctx.ctx);
    if (r != 1) throw_openssl_error("EVP_PKEY_paramgen_init");

    r = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.ctx, tconfig->ec_curve);
    if (r != 1) throw_openssl_error("EVP_PKEY_CTX_set_ec_paramgen_curve_nid");

    r = EVP_PKEY_paramgen(ctx.ctx, &params.pkey);
    if (r != 1) throw_openssl_error("EVP_PKEY_paramgen");

    openssl_pkey_ctx kctx(params.pkey);

    r = EVP_PKEY_keygen_init(kctx.ctx);
    if (r != 1) throw_openssl_error("EVP_PKEY_keygen_init");
        
    r = EVP_PKEY_keygen(kctx.ctx, &pkey);
    if (r != 1) throw_openssl_error("EVP_PKEY_keygen");

    return std::make_shared<openssl_pkey>(pkey);
}

std::shared_ptr<openssl_pkey> gen_dhe_key(void)
{
    int r;
    openssl_pkey params;
    EVP_PKEY *pkey = NULL;
    auto dh_params = get_dh_params();

    r = EVP_PKEY_set1_DH(params.pkey, dh_params->dh);
    if (r != 1) throw_openssl_error("EVP_PKEY_set1_DH");

    openssl_pkey_ctx kctx(params.pkey);

    r = EVP_PKEY_keygen_init(kctx.ctx);
    if (r != 1) throw_openssl_error("EVP_PKEY_keygen_init");

    r = EVP_PKEY_keygen(kctx.ctx, &pkey);
    if (r != 1) throw_openssl_error("EVP_PKEY_keygen");

    return std::make_shared<openssl_pkey>(pkey);
}

const EVP_CIPHER *cipher_by_name(std::string name)
{
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(name.c_str());
    if (cipher == NULL) {
        throw std::runtime_error("Unknown cipher");
    }
    return cipher;
}

const EVP_MD *md_by_name(std::string name)
{
    const EVP_MD *md = EVP_get_digestbyname(name.c_str());
    if (md == NULL) {
        throw std::runtime_error("Unknown md");
    }
    return md;
}

enum PFS_TYPE pfs_type_by_name(std::string name)
{
    if (name == "none") return none;
    if (name == "dhe") return dhe;
    if (name == "ecdhe") return ecdhe;
    throw std::runtime_error("Unknown PFS type!");
}

size_t to_int(std::string name, std::istringstream &sstr)
{
    size_t r;
    if (!(sstr >> r)) throw std::runtime_error("Invalid value for " + name);
    return r;
}

size_t scale_from_name(std::string name)
{
    if (name == "byte" || name == "b") return 1L;
    if (name == "kilobyte" || name == "kb") return 1024L;
    if (name == "megabyte" || name == "mb") return 1024L*1024;
    if (name == "gigabyte" || name == "gb") return 1024L*1024*1024;
    if (name == "terabyte" || name == "tb") return 1024L*1024*1024*1024;
    throw std::runtime_error("Unknown scale type!");
}

int curve_by_name(std::string name)
{
    int r = 0;
    if (name == "secp192r1") r = NID_X9_62_prime192v1;
    else if (name == "secp256r1") r = NID_X9_62_prime256v1;
    else r = OBJ_sn2nid(name.c_str());

    if (r == 0) throw std::runtime_error("Unknown curve name!");
    return r;
}

int pkey_algo_by_name(std::string name)
{
    if (name == "rsa") return EVP_PKEY_RSA;
    if (name == "ec") return EVP_PKEY_EC;
    if (name == "none") return EVP_PKEY_NONE;
    throw std::runtime_error("Unknown public key type!");
}

void do_usage(void)
{
    std::cout << R"(
tls-speed - Test TLS speed with OpenSSL via simulated TLS server.

Options:
    --help|-h      This message.
    --cipher       TLS cipher to use, see "openssl enc --help".
                     Ex: "aes-128-cbc".
    --mac          (H)MAC to use, ignored for GCM ciphers. See
                     "openssl dgst --help". Ex: "sha256".
    --pfs          PFS protocol: "none", "dhe", or "ecdhe".
                     Uses 2048-bit dhe and 256-bit ecdhe.
    --ec-curve     Name of the EC curve to use. Ex: "secp256r1".
    --pkey-type    Public key type, "rsa", "ec", or "none".
    --pkey-bits    Number of bits in the RSA key used.
    --tx-count     Number of transactions to perform.
    --tx-size      Object size to simulate.
    --rx-scale     Scale size by this amount: "byte|b", "kilobyte|kb",
                     "megabyte|mb", "gigabyte|gb", "terabyte|tb".

Options you should probably leave alone:
    --prf          PRF to use, should be SHA1 or SHA256.
    --record-size  TLS record size. Must be a multiple of the cipher
                   block size.

If an option is unset a default is used. To see the defaults, run with no
arguments.

)";
    exit(0);
}
//123456789012345678901234567890123456789012345678901234567890123456789012345678

void get_arguments(int argc, char *argv[], struct tls_config *tconfig, struct user_args *ua)
{

    int c;
    //int digit_optind = 0;

    // Defaults
    ua->tls_record_size = 16384; // 16384 is the max.
    ua->transfer_size = 0; // Calculated below. Always rounded up to the nearest tls_record_size.
    ua->tx_count = 10;
    ua->pkey_bits = 2048;
    ua->cipher_name = "aes-128-cbc";
    ua->mac_name = "sha256";
    ua->prf_name = "sha256"; // per RFC 5246
    ua->pfs_type_name = "ecdhe";
    ua->tx_scale_name = "byte";
    ua->tx_size_base = 104857600;
    ua->ec_curve_name = "secp256r1";
    ua->pkey_type_name = "rsa";

    while (1) {
        //int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        static struct option long_options[] = {
            {"help", 0, 0, 0},
            {"cipher", 1, 0, 0},
            {"mac", 1, 0, 0},
            {"prf", 1, 0, 0},
            {"pfs", 1, 0, 0},
            {"ec-curve", 1, 0, 0},
            {"pkey-type", 1, 0, 0},
            {"pkey-bits", 1, 0, 0},
            {"tx-count", 1, 0, 0},
            {"tx-size", 1, 0, 0},
            {"record-size", 1, 0, 0},
            {"tx-scale", 1, 0, 0},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "+h", long_options, &option_index);
        if (c == -1) break;

        std::string argname = long_options[option_index].name;
        switch (c) {
            case 0:
                if (argname == "help") {
                    do_usage();
                } else if (argname == "cipher") {
                    ua->cipher_name = optarg;
                } else if (argname == "mac" ) {
                    ua->mac_name = optarg;
                } else if (argname == "prf") {
                    ua->prf_name = optarg;
                } else if (argname == "pfs") {
                    ua->pfs_type_name = optarg;
                } else if (argname == "tx-scale") {
                    ua->tx_scale_name = optarg;
                } else if (argname == "ec-curve") {
                    ua->ec_curve_name = optarg;
                } else if (argname == "pkey-type") {
                    ua->pkey_type_name = optarg;
                } else {
                    std::istringstream convert((std::string(optarg)));
                    if (argname == "pkey-bits") {
                        ua->pkey_bits = to_int("pkey-bits", convert);
                    } else if (argname == "tx-count") {
                        ua->tx_count = to_int("tx-count", convert);
                    } else if (argname == "tx-size") {
                        ua->tx_size_base = to_int("tx-size", convert);
                    } else if (argname == "record-size") {
                        ua->tls_record_size = to_int("record-size", convert);
                    } else {
                        throw std::runtime_error("Unknown argument");
                    }
                }
                break;

            case 'h':
                do_usage();
                break;

            default:
                throw std::runtime_error("Unexpected result from getopt");
        }
    }

    if (optind < argc) {
        std::string err = "non-option ARGV-elements:";
        while (optind < argc) {
            err += " ";
            err += argv[optind++];
        }
        throw std::runtime_error(err);
    }

    ua->transfer_size = ua->tx_size_base * scale_from_name(ua->tx_scale_name);

    tconfig->pkey_bits = ua->pkey_bits;
    tconfig->cipher_algo = cipher_by_name(ua->cipher_name);
    tconfig->mac_algo = md_by_name(ua->mac_name);
    tconfig->prf_algo = md_by_name(ua->prf_name);
    tconfig->cipher_key = get_random(EVP_CIPHER_key_length(tconfig->cipher_algo));
    tconfig->pfs_type = pfs_type_by_name(ua->pfs_type_name);
    tconfig->ec_curve = curve_by_name(ua->ec_curve_name);
    tconfig->pkey_algo = pkey_algo_by_name(ua->pkey_type_name);
    tconfig->gcm_random_iv = true;

    std::string mac_key_str = get_random(EVP_CIPHER_key_length(tconfig->cipher_algo));
    tconfig->mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, reinterpret_cast<const unsigned char *>(mac_key_str.c_str()), mac_key_str.length());

    if (tconfig->pkey_algo != EVP_PKEY_NONE && tconfig->pkey_algo != EVP_PKEY_RSA && tconfig->pfs_type == none) {
        throw std::runtime_error("Invalid config specified, non-RSA public key types need PFS.");
    }

    if (tconfig->pkey_algo == EVP_PKEY_NONE && tconfig->pfs_type != none) {
        throw std::runtime_error("Invalid config specified, PFS tests require a public key algorithm.");
    }
}

int main(int argv, char *argc[])
{
    try {
        struct tls_config tconfig;
        struct user_args ua;

        OPENSSL_add_all_algorithms_noconf();
        ERR_load_crypto_strings();
        OPENSSL_config(NULL);

        get_arguments(argv, argc, &tconfig, &ua);

        std::string tls_record_data = get_random(ua.tls_record_size);
        std::string pkey_record_data = get_random(EVP_MD_size(tconfig.mac_algo));
        std::string iv_sized_data = get_random(EVP_MD_size(tconfig.mac_algo));
        std::shared_ptr<openssl_pkey> our_pfs_key(NULL);
        std::shared_ptr<openssl_pkey> their_pfs_key(NULL);
        std::shared_ptr<openssl_pkey> public_key(NULL);

        bool do_aead = ua.cipher_name.compare(ua.cipher_name.length() - 4, 4, "-gcm") == 0;
        std::string public_encrypted;
        uint64_t encrypted = 0;
        uint64_t macd = 0;
        uint64_t siglen = 0;

        uint64_t blocks = (ua.transfer_size / ua.tls_record_size) + (ua.transfer_size % ua.tls_record_size ? 1 : 0);

        std::cout << "Starting TLS performance test using:\n";
        std::cout << "\tPublic key algorithm: " << ua.pkey_type_name << "\n";
        if (tconfig.pkey_algo == EVP_PKEY_RSA) std::cout << "\tPublic key size: " << ua.pkey_bits << " bits\n";
        else if (tconfig.pkey_algo == EVP_PKEY_EC) std::cout << "\tPublic key curve: " << ua.ec_curve_name << "\n";
        std::cout << "\tCipher: " << ua.cipher_name << "\n";
        if (do_aead) std::cout << "\tMAC: gcm\n";
        else std::cout << "\tMAC: " << ua.mac_name << "\n";
        if (tconfig.pfs_type == none) std::cout << "\tPFS: none\n";
        else if (tconfig.pfs_type == dhe) std::cout << "\tPFS: dhe\n";
        else if (tconfig.pfs_type == ecdhe) {
            std::cout << "\tPFS: ecdhe\n";
            std::cout << "\tPFS ec curve: " << ua.ec_curve_name << "\n";
        }
        std::cout << "\tPRF: " << ua.prf_name << "\n";
        std::cout << "\tObject size: " << ua.transfer_size << " bytes\n";
        std::cout << "\tTLS record size: " << ua.tls_record_size << "\n";
        std::cout << "\tTLS records per object: " << blocks << "\n";
        std::cout << "\tTransactions: " << ua.tx_count << "\n";
        std::cout << "\n";

        // The docs for RSA_*_encrypt say you must seed the rng first.
        openssl_seed_rand();

        if (tconfig.pkey_algo == EVP_PKEY_RSA) {
            std::cout << "Generating " << tconfig.pkey_bits << " bit rsa key...\n";
            public_key = gen_pkey(&tconfig);
        } else if (tconfig.pkey_algo == EVP_PKEY_EC) {
            std::cout << "Generating ec key on curve " << ua.ec_curve_name << "...\n";
            public_key = gen_ec_key(&tconfig);
        }

        std::cout << "Generating key exchange data...\n";
        if (tconfig.pfs_type == none && tconfig.pkey_algo == EVP_PKEY_RSA) {
            public_encrypted = rsa_public_encrypt(public_key->pkey, tconfig.cipher_key);
        } else if (tconfig.pfs_type == dhe) {
            our_pfs_key = gen_dhe_key();
            their_pfs_key = gen_dhe_key();
        } else if (tconfig.pfs_type == ecdhe) {
            our_pfs_key = gen_ec_key(&tconfig);
            their_pfs_key = gen_ec_key(&tconfig);
        }

        std::cout << "Done, starting test.\n";

        std::chrono::time_point<std::chrono::steady_clock> tstart = std::chrono::steady_clock::now();
        if (do_aead) {
            for(uint_fast32_t tx = 0; tx < ua.tx_count; tx++) {
                if (tconfig.pkey_algo == EVP_PKEY_NONE) {
                    ;
                } else if (tconfig.pfs_type == none) {
                    std::string session_key = get_random(tconfig.cipher_key.length());
                    siglen += rsa_private_decrypt(public_key->pkey, public_encrypted).length() + session_key.length();
                } else {
                    std::string r = pfs_derive(our_pfs_key->pkey, their_pfs_key->pkey, tconfig.prf_algo);
                    siglen += pkey_sign(&tconfig, public_key->pkey, r);
                }
                std::string explicit_iv;
                if (tconfig.gcm_random_iv) {
                    explicit_iv = hash_block(tconfig.prf_algo, sixty_four_bytes);
                } else {
                    explicit_iv = "12345678";
                }
                for(uint_fast32_t x = 0; x < blocks; x++) {
                    // encrypt_block_gcm increments macd for us! So nice.
                    encrypted += encrypt_block_gcm(&tconfig, explicit_iv, tls_record_data, &macd);
                }
            }
        } else {
            for(uint_fast32_t tx = 0; tx < ua.tx_count; tx++) {
                if (tconfig.pkey_algo == EVP_PKEY_NONE) {
                    ;
                } else if (tconfig.pfs_type == none) {
                    std::string session_key = get_random(tconfig.cipher_key.length());
                    siglen += rsa_private_decrypt(public_key->pkey, public_encrypted).length() + session_key.length();
                } else {
                    std::string r = pfs_derive(our_pfs_key->pkey, their_pfs_key->pkey, tconfig.prf_algo);
                    siglen += pkey_sign(&tconfig, public_key->pkey, r);
                }
                for(uint_fast32_t x = 0; x < blocks; x++) {
                    encrypted += encrypt_block(&tconfig, tls_record_data);
                    macd += hmac_block(&tconfig, tls_record_data + iv_sized_data);
                }
            }
        }

        std::chrono::time_point<std::chrono::steady_clock> tstop = std::chrono::steady_clock::now();
        std::chrono::duration<double> tdiff = tstop - tstart;

        uint64_t sent = encrypted + macd;
        /*
         * This is a wild guess. There's ~5 bytes of overhead per TLS record,
         * plus, say, 4k of handshakes including certs, which is on the high
         * end.
         */
        uint64_t tls_overhead_estimate = (blocks * 5) + 4096;

        std::cout << std::fixed << std::setprecision(3); // Disable scientific notation, just print 3 decimal places.
        std::cout.imbue(std::locale("")); // Put commas or whatever in numbers.
        std::cout << "Test complete! Nothing crashed!\n\n";
        std::cout << "Data processed:\n";
        std::cout << "\t" << siglen << " bytes of public key stuff\n";
        std::cout << "\t" << encrypted << " bytes encrypted\n";
        std::cout << "\t" << macd << " total MAC bytes\n";
        std::cout << "Duration:\n";
        std::cout << "\t" << tdiff.count() << " seconds\n";
        std::cout << "Approximate bytes that would be sent:\n";
        std::cout << "\t" << sent << " (bytes encrypted + MACs)\n";
        std::cout << "\t" << (sent + tls_overhead_estimate) << " (bytes encrypted + MACs + TLS overhead estimate)\n";
        std::cout << "Approximate transfer rate (based on (bytes encrypted + MACs)/duration):\n";
        std::cout << "\t" << sent/tdiff.count() << " bytes/sec\n";
        std::cout << "\t" << sent*8/tdiff.count() << " bits/sec\n";
        std::cout << "\t" << sent*8/tdiff.count()/1000 << " kilobits/sec\n";
        std::cout << "\t" << sent*8/tdiff.count()/1000/1000 << " megabits/sec\n";
        std::cout << "\t" << sent*8/tdiff.count()/1000/1000/1000 << " gigabits/sec\n";
        std::cout << "Approximate transfer timing:\n";
        std::cout << "\t" << ua.tx_count/tdiff.count() << " transactions/second\n";
        std::cout << "\t" << tdiff.count()/ua.tx_count << " seconds/transfer\n";
        std::cout << "\n";

        ERR_free_strings();
        return 0;
    } catch(const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
}

