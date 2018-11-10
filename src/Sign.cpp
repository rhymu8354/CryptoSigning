/**
 * @file Sign.cpp
 *
 * This module contains the implementation of the
 * CryptoSigning::Sign class.
 *
 * © 2018 by Richard Walters
 */

#include <CryptoSigning/Sign.hpp>
#include <functional>
#include <memory>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <string>

namespace CryptoSigning {

    /**
     * This contains the private properties of a Sign instance.
     */
    struct Sign::Impl {
        /**
         * This is the private key, in PEM format, to use in making
         * cryptographic signatures.
         */
        std::unique_ptr< EVP_PKEY, std::function< void(EVP_PKEY*) > > key;
    };

    Sign::~Sign() noexcept = default;
    Sign::Sign(Sign&&) noexcept = default;
    Sign& Sign::operator=(Sign&&) noexcept = default;

    Sign::Sign()
        : impl_(new Impl())
    {
    }

    bool Sign::Configure(
        const std::string& keyPem,
        const std::string& passphrase
    ) {
        std::unique_ptr< BIO, std::function< void(BIO*) > > keyInput(
            BIO_new_mem_buf(
                keyPem.data(),
                (int)keyPem.size()
            ),
            [](BIO* p){
                BIO_free_all(p);
            }
        );
        std::unique_ptr< EVP_PKEY, std::function< void(EVP_PKEY*) > > key(
            PEM_read_bio_PrivateKey(
                keyInput.get(),
                NULL,
                NULL,
                (void*)passphrase.c_str()
            ),
            [](EVP_PKEY* p){
                EVP_PKEY_free(p);
            }
        );
        if (key == NULL) {
            return false;
        }
        impl_->key = std::move(key);
        return true;
    }

    std::vector< uint8_t > Sign::operator()(const std::vector< uint8_t >& data) {
        if (impl_->key == nullptr) {
            return {};
        }
        std::unique_ptr< EVP_MD_CTX, std::function< void(EVP_MD_CTX*) > > ctx(
            EVP_MD_CTX_create(),
            [](EVP_MD_CTX* p) {
                EVP_MD_CTX_free(p);
            }
        );
        if (
            EVP_DigestSignInit(
                ctx.get(),
                NULL,
                EVP_sha256(),
                NULL,
                impl_->key.get()
            ) <= 0
        ) {
            return {};
        }
        if (
            EVP_DigestSignUpdate(
                ctx.get(),
                data.data(),
                data.size()
            ) <= 0
        ) {
            return {};
        }
        size_t signatureLength;
        if (
            EVP_DigestSignFinal(
                ctx.get(),
                NULL,
                &signatureLength
            ) <= 0
        ) {
            return {};
        }
        std::vector< uint8_t > signature(signatureLength);
        if (
            EVP_DigestSignFinal(
                ctx.get(),
                signature.data(),
                &signatureLength
            ) <= 0
        ) {
            return {};
        }
        return signature;
    }

}
