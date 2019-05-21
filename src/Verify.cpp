/**
 * @file Verify.cpp
 *
 * This module contains the implementation of the
 * CryptoSigning::Verify class.
 *
 * © 2018 by Richard Walters
 */

#include <CryptoSigning/Verify.hpp>
#include <functional>
#include <memory>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <string>

namespace CryptoSigning {

    /**
     * This contains the private properties of a Verify instance.
     */
    struct Verify::Impl {
        /**
         * This is the public or private key, in PEM format, to use in
         * verifying cryptographic signatures.
         */
        std::unique_ptr< EVP_PKEY, std::function< void(EVP_PKEY*) > > key;
    };

    Verify::~Verify() noexcept = default;
    Verify::Verify(Verify&&) noexcept = default;
    Verify& Verify::operator=(Verify&&) noexcept = default;

    Verify::Verify()
        : impl_(new Impl())
    {
    }

    bool Verify::Configure(const std::string& keyPem) {
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
            PEM_read_bio_PUBKEY(
                keyInput.get(),
                NULL,
                NULL,
                NULL
            ),
            [](EVP_PKEY* p){
                EVP_PKEY_free(p);
            }
        );
        if (key == NULL) {
            keyInput.reset(
                BIO_new_mem_buf(
                    keyPem.data(),
                    (int)keyPem.size()
                )
            );
            key.reset(
                PEM_read_bio_PrivateKey(
                    keyInput.get(),
                    NULL,
                    NULL,
                    NULL
                )
            );
        }
        if (key == NULL) {
            return false;
        }
        impl_->key = std::move(key);
        return true;
    }

    bool Verify::operator()(
        const std::vector< uint8_t >& data,
        const std::vector< uint8_t >& signature
    ) {
        if (impl_->key == nullptr) {
            return false;
        }
        std::unique_ptr< EVP_MD_CTX, std::function< void(EVP_MD_CTX*) > > ctx(
            EVP_MD_CTX_create(),
            [](EVP_MD_CTX* p) {
                EVP_MD_CTX_free(p);
            }
        );
        if (
            EVP_DigestVerifyInit(
                ctx.get(),
                NULL,
                EVP_sha256(),
                NULL,
                impl_->key.get()
            ) <= 0
        ) {
            return false;
        }
        if (
            EVP_DigestVerifyUpdate(
                ctx.get(),
                data.data(),
                data.size()
            ) <= 0
        ) {
            return false;
        }
        return (
            EVP_DigestVerifyFinal(
                ctx.get(),
                signature.data(),
                signature.size()
            ) == 1
        );
    }

}
