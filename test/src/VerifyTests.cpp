/**
 * @file VerifyTests.cpp
 *
 * This module contains the unit tests of the CryptoSigning::Verify class.
 *
 * © 2018 by Richard Walters
 */

#include <CryptoSigning/Verify.hpp>
#include <gtest/gtest.h>
#include <stdint.h>
#include <string>
#include <vector>

/**
 * This is the test fixture for these tests, providing common
 * setup and teardown for each test.
 */
struct VerifyTests
    : public ::testing::Test
{
    // Properties

    /**
     * This is the public key to use to verify the signature,
     * in PEM format.
     */
    const std::string key = (
        "-----BEGIN PUBLIC KEY-----\r\n"
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyrfjuShD8ZoWeJG1Ddq5\r\n"
        "G0537dW2XJLwdy57BuLPv0rTPIHL9tFSJAag+qXgw3zW1uZX/PEftBvYv41LIu3l\r\n"
        "TiwO1L0tlY4okyMHT7+dv+W3B6zZaSX65CrK95s6TbTDQWjrzUmn4GtAJOY/XEe5\r\n"
        "BaXDp2VDcxMssXYaO4vc0nV4txpj50Ke1Xvq6SNbMY09kd3FzRi0kmZvT8tu8DWC\r\n"
        "EWbkypH6QUBN/b5UBnuGAA9VvrlhnmkONLzX+OBovcBdXYBhyjklHoAKj+OyGSs+\r\n"
        "tPaOyiUu5m0qaFV+a5dyf8fxFAeQKSm+NEUb78v5VoVb2LF+piPw5cyWRiBwQ4zK\r\n"
        "/Osc+M9i2OBJNe8pBUqDD2OLn3fu0uM8nyfk8LyIh8HUpRtqLUCIrQ6ijOiUigc3\r\n"
        "N227qkWH005LwKKQVVvONjtSnsT+WLXeRHMMJwhroPERIh3J4lM7DbNptNB1AShF\r\n"
        "bg0qmcyTlxi/Dky2qc8xS49PGV8Dec0Dty0wx8bXwJOldYEP2qZcskZT0dWSpwf8\r\n"
        "EiiNdPU5qZyZrdD4zzhCdOhoV5I3uDGSTafFHWgUSToBBB1BCulPSW6BoY6lLZs7\r\n"
        "yjY7OoBxOh+u5ZC8o/6MYnmGrRWPusrg1QkvJg+//wbpkwOC/iNdpPlcN9e6fY81\r\n"
        "1OSD5QQtYAs4jYgawjRzQtECAwEAAQ==\r\n"
        "-----END PUBLIC KEY-----\r\n"
    );

    /**
     * This is the modulus used to form the public key to use to verify
     * the signature.
     */
    const uint8_t modulus[512] = {
              0xca, 0xb7, 0xe3, 0xb9, 0x28, 0x43, 0xf1, 0x9a, 0x16, 0x78, 0x91,
        0xb5, 0x0d, 0xda, 0xb9, 0x1b, 0x4e, 0x77, 0xed, 0xd5, 0xb6, 0x5c, 0x92,
        0xf0, 0x77, 0x2e, 0x7b, 0x06, 0xe2, 0xcf, 0xbf, 0x4a, 0xd3, 0x3c, 0x81,
        0xcb, 0xf6, 0xd1, 0x52, 0x24, 0x06, 0xa0, 0xfa, 0xa5, 0xe0, 0xc3, 0x7c,
        0xd6, 0xd6, 0xe6, 0x57, 0xfc, 0xf1, 0x1f, 0xb4, 0x1b, 0xd8, 0xbf, 0x8d,
        0x4b, 0x22, 0xed, 0xe5, 0x4e, 0x2c, 0x0e, 0xd4, 0xbd, 0x2d, 0x95, 0x8e,
        0x28, 0x93, 0x23, 0x07, 0x4f, 0xbf, 0x9d, 0xbf, 0xe5, 0xb7, 0x07, 0xac,
        0xd9, 0x69, 0x25, 0xfa, 0xe4, 0x2a, 0xca, 0xf7, 0x9b, 0x3a, 0x4d, 0xb4,
        0xc3, 0x41, 0x68, 0xeb, 0xcd, 0x49, 0xa7, 0xe0, 0x6b, 0x40, 0x24, 0xe6,
        0x3f, 0x5c, 0x47, 0xb9, 0x05, 0xa5, 0xc3, 0xa7, 0x65, 0x43, 0x73, 0x13,
        0x2c, 0xb1, 0x76, 0x1a, 0x3b, 0x8b, 0xdc, 0xd2, 0x75, 0x78, 0xb7, 0x1a,
        0x63, 0xe7, 0x42, 0x9e, 0xd5, 0x7b, 0xea, 0xe9, 0x23, 0x5b, 0x31, 0x8d,
        0x3d, 0x91, 0xdd, 0xc5, 0xcd, 0x18, 0xb4, 0x92, 0x66, 0x6f, 0x4f, 0xcb,
        0x6e, 0xf0, 0x35, 0x82, 0x11, 0x66, 0xe4, 0xca, 0x91, 0xfa, 0x41, 0x40,
        0x4d, 0xfd, 0xbe, 0x54, 0x06, 0x7b, 0x86, 0x00, 0x0f, 0x55, 0xbe, 0xb9,
        0x61, 0x9e, 0x69, 0x0e, 0x34, 0xbc, 0xd7, 0xf8, 0xe0, 0x68, 0xbd, 0xc0,
        0x5d, 0x5d, 0x80, 0x61, 0xca, 0x39, 0x25, 0x1e, 0x80, 0x0a, 0x8f, 0xe3,
        0xb2, 0x19, 0x2b, 0x3e, 0xb4, 0xf6, 0x8e, 0xca, 0x25, 0x2e, 0xe6, 0x6d,
        0x2a, 0x68, 0x55, 0x7e, 0x6b, 0x97, 0x72, 0x7f, 0xc7, 0xf1, 0x14, 0x07,
        0x90, 0x29, 0x29, 0xbe, 0x34, 0x45, 0x1b, 0xef, 0xcb, 0xf9, 0x56, 0x85,
        0x5b, 0xd8, 0xb1, 0x7e, 0xa6, 0x23, 0xf0, 0xe5, 0xcc, 0x96, 0x46, 0x20,
        0x70, 0x43, 0x8c, 0xca, 0xfc, 0xeb, 0x1c, 0xf8, 0xcf, 0x62, 0xd8, 0xe0,
        0x49, 0x35, 0xef, 0x29, 0x05, 0x4a, 0x83, 0x0f, 0x63, 0x8b, 0x9f, 0x77,
        0xee, 0xd2, 0xe3, 0x3c, 0x9f, 0x27, 0xe4, 0xf0, 0xbc, 0x88, 0x87, 0xc1,
        0xd4, 0xa5, 0x1b, 0x6a, 0x2d, 0x40, 0x88, 0xad, 0x0e, 0xa2, 0x8c, 0xe8,
        0x94, 0x8a, 0x07, 0x37, 0x37, 0x6d, 0xbb, 0xaa, 0x45, 0x87, 0xd3, 0x4e,
        0x4b, 0xc0, 0xa2, 0x90, 0x55, 0x5b, 0xce, 0x36, 0x3b, 0x52, 0x9e, 0xc4,
        0xfe, 0x58, 0xb5, 0xde, 0x44, 0x73, 0x0c, 0x27, 0x08, 0x6b, 0xa0, 0xf1,
        0x11, 0x22, 0x1d, 0xc9, 0xe2, 0x53, 0x3b, 0x0d, 0xb3, 0x69, 0xb4, 0xd0,
        0x75, 0x01, 0x28, 0x45, 0x6e, 0x0d, 0x2a, 0x99, 0xcc, 0x93, 0x97, 0x18,
        0xbf, 0x0e, 0x4c, 0xb6, 0xa9, 0xcf, 0x31, 0x4b, 0x8f, 0x4f, 0x19, 0x5f,
        0x03, 0x79, 0xcd, 0x03, 0xb7, 0x2d, 0x30, 0xc7, 0xc6, 0xd7, 0xc0, 0x93,
        0xa5, 0x75, 0x81, 0x0f, 0xda, 0xa6, 0x5c, 0xb2, 0x46, 0x53, 0xd1, 0xd5,
        0x92, 0xa7, 0x07, 0xfc, 0x12, 0x28, 0x8d, 0x74, 0xf5, 0x39, 0xa9, 0x9c,
        0x99, 0xad, 0xd0, 0xf8, 0xcf, 0x38, 0x42, 0x74, 0xe8, 0x68, 0x57, 0x92,
        0x37, 0xb8, 0x31, 0x92, 0x4d, 0xa7, 0xc5, 0x1d, 0x68, 0x14, 0x49, 0x3a,
        0x01, 0x04, 0x1d, 0x41, 0x0a, 0xe9, 0x4f, 0x49, 0x6e, 0x81, 0xa1, 0x8e,
        0xa5, 0x2d, 0x9b, 0x3b, 0xca, 0x36, 0x3b, 0x3a, 0x80, 0x71, 0x3a, 0x1f,
        0xae, 0xe5, 0x90, 0xbc, 0xa3, 0xfe, 0x8c, 0x62, 0x79, 0x86, 0xad, 0x15,
        0x8f, 0xba, 0xca, 0xe0, 0xd5, 0x09, 0x2f, 0x26, 0x0f, 0xbf, 0xff, 0x06,
        0xe9, 0x93, 0x03, 0x82, 0xfe, 0x23, 0x5d, 0xa4, 0xf9, 0x5c, 0x37, 0xd7,
        0xba, 0x7d, 0x8f, 0x35, 0xd4, 0xe4, 0x83, 0xe5, 0x04, 0x2d, 0x60, 0x0b,
        0x38, 0x8d, 0x88, 0x1a, 0xc2, 0x34, 0x73, 0x42, 0xd1
    };

    /**
     * This is the public exponent used to form the public key to use to verify
     * the signature.
     */
    const uint8_t exponent[3] = {0x01, 0x00, 0x01};

    /**
     * This is the private key, not encrypted, to use to verify the
     * signature, in PEM format.
     */
    const std::string privateKey = (
        "-----BEGIN PRIVATE KEY-----\r\n"
        "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\r\n"
        "vRePIbo+jLVud6N90g1eqj6z/lFfgQ==\r\n"
        "-----END PRIVATE KEY-----\r\n"
    );

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
    CryptoSigning::Verify verify;

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

TEST_F(VerifyTests, ConfigureValidKey) {
    EXPECT_TRUE(verify.Configure(key));
}

TEST_F(VerifyTests, ConfigureInvalidKey) {
    EXPECT_FALSE(verify.Configure("This isn't a valid key."));
}

TEST_F(VerifyTests, VerifyValidSignatureWhenConfigured) {
    (void)verify.Configure(key);
    EXPECT_TRUE(verify(dataChunk, validSignature));
}

TEST_F(VerifyTests, VerifyValidSignatureUsingPrivateKey) {
    (void)verify.Configure(privateKey);
    EXPECT_TRUE(verify(dataChunk, validSignature));
}

TEST_F(VerifyTests, VerifyValidSignatureUsingModulusExponent) {
    (void)verify.Configure(
        modulus, sizeof(modulus),
        exponent, sizeof(exponent)
    );
    EXPECT_TRUE(verify(dataChunk, validSignature));
}

TEST_F(VerifyTests, VerifyValidSignatureNotConfigured) {
    EXPECT_FALSE(verify(dataChunk, validSignature));
}

TEST_F(VerifyTests, VerifyInvalidSignatureWhenConfigured) {
    (void)verify.Configure(key);
    auto invalidSignature(validSignature);
    invalidSignature[8] ^= 0x55;
    EXPECT_FALSE(verify(dataChunk, invalidSignature));
}
