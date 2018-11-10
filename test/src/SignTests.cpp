/**
 * @file SignTests.cpp
 *
 * This module contains the unit tests of the CryptoSigning::Sign class.
 *
 * © 2018 by Richard Walters
 */

#include <CryptoSigning/Sign.hpp>
#include <gtest/gtest.h>
#include <stdint.h>
#include <string>
#include <vector>

/**
 * This is the test fixture for these tests, providing common
 * setup and teardown for each test.
 */
struct SignTests
    : public ::testing::Test
{
    // Properties

    /**
     * This is the private key, not encrypted, to use to sign the test data,
     * in PEM format.
     */
    const std::string unencryptedKey = (
        "-----BEGIN PRIVATE KEY-----\r\n"
        "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\r\n"
        "vRePIbo+jLVud6N90g1eqj6z/lFfgQ==\r\n"
        "-----END PRIVATE KEY-----\r\n"
    );

    /**
     * This is the private key, encrypted with a passphrase, to use to sign the
     * test data, in PEM format.
     */
    const std::string encryptedKey = (
        "-----BEGIN RSA PRIVATE KEY-----\r\n"
        "Proc-Type: 4,ENCRYPTED\r\n"
        "DEK-Info: AES-256-CBC,61D3DC36BA34F2CE9282B0A0C31DCB90\r\n"
        "\r\n"
        "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\r\n"
        "-----END RSA PRIVATE KEY-----\r\n"
    );

    /**
     * This is the passphrase used to encrypt the encrypted private key
     * used by these tests.
     */
    const std::string correctPassphrase = "password";

    /**
     * This is the test data for which a signature will be verified.
     */
    std::vector< uint8_t > dataChunk;

    /**
     * This is the cryptographic signature that matches the test data and
     * public key.
     */
    const std::vector< uint8_t > validSignature{
        0x98, 0x48, 0x3a, 0xb3, 0x7b, 0x1a, 0x93, 0xfb,
        0xcd, 0xbb, 0xe5, 0x0a, 0xa5, 0x62, 0x8d, 0xa4,
        0xd0, 0x42, 0x95, 0x3f, 0x56, 0x8a, 0xdb, 0x46,
        0x13, 0x79, 0x35, 0x6e, 0xef, 0x1f, 0xee, 0x12,
        0x13, 0x15, 0x21, 0xf2, 0xc4, 0xf0, 0x1b, 0x47,
        0xd9, 0x07, 0xd2, 0xae, 0x98, 0x17, 0x3b, 0xdc,
        0xc2, 0x0e, 0x08, 0xa8, 0xf3, 0x95, 0xf4, 0x7a,
        0x88, 0xfe, 0x42, 0x49, 0x7f, 0x17, 0x5a, 0xcf,
        0x70, 0xeb, 0x36, 0xc6, 0xe8, 0x4a, 0x3f, 0x67,
        0x22, 0x5e, 0x76, 0x92, 0x57, 0x45, 0xa6, 0x7a,
        0xda, 0x66, 0xa9, 0x65, 0xb6, 0x1f, 0x6b, 0x42,
        0x8a, 0x8f, 0xcf, 0x8b, 0x53, 0x8f, 0x85, 0xc5,
        0x88, 0x77, 0x94, 0x1c, 0x18, 0xfe, 0x41, 0x0e,
        0x04, 0xfa, 0x1e, 0xaa, 0x92, 0xb8, 0xe2, 0xee,
        0x7b, 0xd6, 0x88, 0xf8, 0x0d, 0x4e, 0x43, 0x7c,
        0xf9, 0xac, 0x2e, 0x2d, 0x8b, 0xed, 0x9d, 0xb0,
        0xc4, 0x9f, 0xa8, 0x9c, 0xb5, 0xd5, 0x99, 0x86,
        0x26, 0x3b, 0xf9, 0x8b, 0x99, 0x9f, 0x65, 0xf8,
        0xc7, 0x77, 0x3b, 0x06, 0x2a, 0xbc, 0x62, 0x16,
        0xbe, 0x87, 0xe5, 0x96, 0xe0, 0x7b, 0x32, 0x43,
        0x5f, 0x2d, 0xd1, 0x35, 0x66, 0x4b, 0xca, 0xf3,
        0x15, 0x87, 0x58, 0xae, 0x00, 0xd5, 0x95, 0x91,
        0x43, 0xda, 0xe6, 0x5a, 0x92, 0x4b, 0xa5, 0xc6,
        0x77, 0x27, 0x72, 0x12, 0x9b, 0x7c, 0x93, 0x99,
        0x75, 0x65, 0x57, 0x12, 0x3b, 0x26, 0x82, 0xc5,
        0x28, 0x06, 0xd3, 0x4a, 0x96, 0x9b, 0x1e, 0x1f,
        0x21, 0xcc, 0xc5, 0xa7, 0x99, 0x03, 0x93, 0xd2,
        0x67, 0xcb, 0x90, 0x7a, 0xf3, 0xa1, 0x94, 0xca,
        0xfa, 0x23, 0xf0, 0xc5, 0xa8, 0x3a, 0xde, 0xf6,
        0x67, 0x28, 0x13, 0x53, 0x99, 0x6c, 0xeb, 0xff,
        0x47, 0x6c, 0xfc, 0xe8, 0xe4, 0xf5, 0xbb, 0xdb,
        0x3e, 0x7e, 0xc3, 0xd0, 0x76, 0x30, 0x94, 0xf4,
        0x62, 0xe4, 0xa0, 0x55, 0x12, 0xf8, 0xaa, 0xbb,
        0x8c, 0x5b, 0xfe, 0xea, 0x86, 0x96, 0xf9, 0x1e,
        0xcc, 0xe1, 0x3e, 0x53, 0xb8, 0xcf, 0x8e, 0x1f,
        0x84, 0x81, 0xb2, 0xda, 0xd1, 0x76, 0x57, 0x1a,
        0xab, 0x41, 0x11, 0xa1, 0x42, 0xf1, 0x06, 0xb0,
        0xc7, 0xfd, 0x1c, 0x09, 0x20, 0x65, 0xee, 0x2c,
        0x84, 0x22, 0x8b, 0x30, 0x60, 0xcc, 0xd4, 0x52,
        0x6e, 0xd0, 0xe7, 0xd4, 0x98, 0x42, 0x24, 0x43,
        0xc7, 0x17, 0x81, 0x49, 0x20, 0xa6, 0x1e, 0x0d,
        0x5a, 0x39, 0xae, 0xc4, 0x28, 0x55, 0xbe, 0x96,
        0x5d, 0xb6, 0x78, 0x86, 0xec, 0x33, 0x91, 0x2f,
        0x99, 0xee, 0x99, 0x7c, 0x41, 0x56, 0xf5, 0xbd,
        0x30, 0x0d, 0xdc, 0x6f, 0x4b, 0xb9, 0xb9, 0x7a,
        0xe4, 0x55, 0x00, 0x68, 0x65, 0x38, 0xed, 0xa2,
        0xaa, 0x7a, 0x26, 0x7f, 0xa6, 0x7a, 0xa5, 0x70,
        0x1d, 0xa7, 0xe2, 0x9e, 0x1b, 0xa0, 0xc2, 0xb3,
        0x51, 0xa1, 0xeb, 0x7e, 0x04, 0x05, 0xff, 0x76,
        0xc8, 0x3b, 0x1a, 0x9c, 0x85, 0x1e, 0xbe, 0x91,
        0x35, 0xfa, 0x37, 0x58, 0x44, 0xf2, 0xac, 0x02,
        0x1c, 0x27, 0x0b, 0xef, 0xd6, 0x16, 0x09, 0x85,
        0x22, 0x0a, 0xa8, 0x8d, 0xe6, 0x6b, 0xfb, 0xaa,
        0x21, 0x8d, 0xf3, 0x79, 0x79, 0x65, 0x2e, 0x3f,
        0x46, 0x23, 0x2d, 0xee, 0xd4, 0xc3, 0x0d, 0xcd,
        0x33, 0x0c, 0xcf, 0x25, 0x0f, 0xf3, 0x4d, 0x00,
        0x09, 0x88, 0xc5, 0xc6, 0xe7, 0x6f, 0x49, 0x5b,
        0xcc, 0xc6, 0x04, 0xec, 0xb0, 0x4d, 0x04, 0x82,
        0x9c, 0x1c, 0xdf, 0xbf, 0xd8, 0xaa, 0xf0, 0x16,
        0x25, 0x8e, 0x0e, 0x14, 0x4e, 0x05, 0x04, 0x65,
        0x0f, 0x9e, 0xac, 0x35, 0x4e, 0x9e, 0xa3, 0x49,
        0x9c, 0xbf, 0x82, 0xee, 0x6c, 0x4e, 0x21, 0x8b,
        0x42, 0x28, 0x9a, 0xf9, 0xd6, 0x7a, 0x48, 0x51,
        0x47, 0xc8, 0xe9, 0x71, 0xc5, 0x7f, 0x34, 0xc0
    };

    /**
     * This is the unit under test.
     */
    CryptoSigning::Sign sign;

    // Methods

    // ::testing::Test

    virtual void SetUp() {
        const std::string data = "Hello, World!";
        dataChunk.assign(
            data.begin(),
            data.end()
        );
    }

    virtual void TearDown() {
    }
};

TEST_F(SignTests, ConfigureValidUnencryptedKey) {
    EXPECT_TRUE(sign.Configure(unencryptedKey));
}

TEST_F(SignTests, ConfigureValidEncryptedKeyCorrectPassphrase) {
    EXPECT_TRUE(sign.Configure(encryptedKey, correctPassphrase));
}

TEST_F(SignTests, ConfigureValidEncryptedKeyIncorrectPassphrase) {
    EXPECT_FALSE(sign.Configure(encryptedKey, "FeelsBadMan"));
}

TEST_F(SignTests, ConfigureInvalidKey) {
    EXPECT_FALSE(sign.Configure("This isn't a valid key."));
}

TEST_F(SignTests, SignWhenConfiguredWithUnencryptedKey) {
    (void)sign.Configure(unencryptedKey);
    EXPECT_EQ(
        validSignature,
        sign(dataChunk)
    );
}

TEST_F(SignTests, SignWhenConfiguredWithEncryptedKey) {
    (void)sign.Configure(encryptedKey, correctPassphrase);
    EXPECT_EQ(
        validSignature,
        sign(dataChunk)
    );
}

TEST_F(SignTests, SignWhenNotConfigured) {
    EXPECT_EQ(
        std::vector< uint8_t >(),
        sign(dataChunk)
    );
}
