#ifndef CRYPTO_SIGNING_SIGN_HPP
#define CRYPTO_SIGNING_SIGN_HPP

/**
 * @file CryptoSigning.hpp
 *
 * This module declares the CryptoSigning::Sign class.
 *
 * © 2018 by Richard Walters
 */

#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

namespace CryptoSigning {

    /**
     * This class is used to generate a cryptographic signature for a chunk of
     * data, using a private key in PEM format.
     */
    class Sign {
        // Lifecycle management
    public:
        ~Sign() noexcept;
        Sign(const Sign&) = delete;
        Sign(Sign&&) noexcept;
        Sign& operator=(const Sign&) = delete;
        Sign& operator=(Sign&&) noexcept;

        // Public Methods
    public:
        /**
         * This is the default constructor.
         */
        Sign();

        /**
         * This method sets up the instance to sign data chunks
         * cryptographically using the given private key.
         *
         * @param[in] keyPem
         *     This is the private key, in PEM format, to use in signing
         *     data chunks cryptographically.
         *
         * @param[in] passphrase
         *     This is the passphrase to use to decrypt the private key.
         *
         * @return
         *     An indication of whether or not the instance was successfully
         *     configured is returned.
         */
        bool Configure(
            const std::string& keyPem,
            const std::string& passphrase = ""
        );

        /**
         * This method cryptographically signs the given data chunk using the
         * configured key.
         *
         * @param[in] data
         *     This is the data chunk to cryptographically sign.
         *
         * @return
         *     The raw binary cryptographic signature is returned.
         */
        std::vector< uint8_t > operator()(const std::vector< uint8_t >& data);

        // Private Properties
    private:
        /**
         * This is the type of structure that contains the private
         * properties of the instance.  It is defined in the implementation
         * and declared here to ensure that it is scoped inside the class.
         */
        struct Impl;

        /**
         * This contains the private properties of the instance.
         */
        std::unique_ptr< Impl > impl_;
    };

}

#endif /* CRYPTO_SIGNING_SIGN_HPP */
