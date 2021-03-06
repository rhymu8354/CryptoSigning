#ifndef CRYPTO_SIGNING_VERIFY_HPP
#define CRYPTO_SIGNING_VERIFY_HPP

/**
 * @file CryptoSigning.hpp
 *
 * This module declares the CryptoSigning::Verify class.
 *
 * © 2018 by Richard Walters
 */

#include <memory>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace CryptoSigning {

    /**
     * This class is used to verify a cryptographic signature for a chunk of
     * data, using a public or private key in PEM format.
     */
    class Verify {
        // Lifecycle management
    public:
        ~Verify() noexcept;
        Verify(const Verify&) = delete;
        Verify(Verify&&) noexcept;
        Verify& operator=(const Verify&) = delete;
        Verify& operator=(Verify&&) noexcept;

        // Public Methods
    public:
        /**
         * This is the default constructor.
         */
        Verify();

        /**
         * This method sets up the instance to verify cryptographic signatures
         * made with the private key that corresponds to the given public key,
         * or by using the same private key directly.
         *
         * @param[in] keyPem
         *     This is the public or private key, in PEM format, to use in
         *     verifying cryptographic signatures.
         *
         * @return
         *     An indication of whether or not the instance was successfully
         *     configured is returned.
         */
        bool Configure(const std::string& keyPem);

        /**
         * This method sets up the instance to verify cryptographic signatures
         * made with the private key that corresponds to the given public key,
         * or by using the same private key directly.
         *
         * @param[in] keyModulus
         *     This points to the memory containing the modulus
         *     of the public key to use in verifying cryptographic signatures.
         *
         * @param[in] keyModulusLength
         *     This is the length, in bytes, of the modulus
         *     of the public key to use in verifying cryptographic signatures.
         *
         * @param[in] keyExponentModulus
         *     This points to the memory containing the public exponent
         *     of the public key to use in verifying cryptographic signatures.
         *
         * @param[in] keyExponentModulusLength
         *     This is the length, in bytes, of the public exponent
         *     of the public key to use in verifying cryptographic signatures.
         */
        void Configure(
            const uint8_t* keyModulus,
            size_t keyModulusLength,
            const uint8_t* keyExponent,
            size_t keyExponentLength
        );

        /**
         * This method verifies that the given cryptographic signature matches
         * the configured key and the given data chunk.
         *
         * @param[in] data
         *     This is the data chunk whose signature is to be verified.
         *
         * @param[in] signature
         *     This is the raw binary cryptographic signature to verify.
         *
         * @return
         *     An indication of whether or not the given cryptographic
         *     signature matches the configured key and the given data chunk
         *     is returned.
         */
        bool operator()(
            const std::vector< uint8_t >& data,
            const std::vector< uint8_t >& signature
        );

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

#endif /* CRYPTO_SIGNING_VERIFY_HPP */
