/*
 * crypto-lib.h
 *
 *  Created on: Mar. 23, 2024
 *      Author: Marcus Moquin
 */

#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>

#define YEAR_IN_MS 				31536000000
#define MSG_LENGTH 				1024
#define ECDSA_SIGNATURE_SIZE 			64

using namespace std;

#ifndef SRC_CRYPTO_LIB_H_
#define SRC_CRYPTO_LIB_H_

// Store in JSON later
struct x509 {
	const EC_POINT *public_key; // keypairs are EC_KEY, while private is BIGNUM and public is EC_POINT.
	string signature; // stored in DER format
	string location;
	const EC_POINT *issuer; // public key of the issuer
	long issue_date;
	long valid_until;
};

class CryptoLib {
public:
	EC_KEY* generateECKeyPair();
	string signKey(const EC_POINT *, EC_KEY *);
	bool encryptData(const unsigned char*, size_t, const unsigned char*, unsigned char*, size_t&);
	bool decryptData(const unsigned char*, size_t, const unsigned char*, unsigned char*, size_t&);
	bool deriveSharedSecret(const EC_KEY*, const EC_POINT*, unsigned char*, size_t);
	bool verifyCertificate(const x509&, EC_KEY*);
};

#endif /* SRC_CRYPTO_LIB_H_ */
