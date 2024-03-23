/*
 * crypto-lib.cpp
 *
 *  Created on: Mar. 23, 2024
 *      Author: Marcus Moquin
 */

#include "crypto-lib.h"

EC_KEY* CryptoLib::generateECKeyPair() {
    EC_KEY *ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ecKey) {
        std::cerr << "Error creating EC key" << std::endl;
        exit(1);
    }
    if (!EC_KEY_generate_key(ecKey)) {
        std::cerr << "Error generating EC key" << std::endl;
        exit(1);
    }
    return ecKey;
}

string CryptoLib::signKey(const EC_POINT *public_key, EC_KEY *private_key) {
    if (!public_key || !private_key) {
        // Handle invalid input
        return "";
    }

    // Convert EC_POINT to octet string
    size_t len = EC_POINT_point2oct(EC_KEY_get0_group(private_key), public_key, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    if (len == 0) {
        // Handle conversion failure
        return "";
    }

    unsigned char *oct_str = new unsigned char[len];
    if (!oct_str) {
        // Handle memory allocation failure
        return "";
    }

    if (EC_POINT_point2oct(EC_KEY_get0_group(private_key), public_key, POINT_CONVERSION_UNCOMPRESSED, oct_str, len, nullptr) != len) {
        // Handle conversion failure
        delete[] oct_str;
        return "";
    }

    // Calculate the hash of the octet string
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(oct_str, len, hash);

    // Free allocated memory for octet string
    delete[] oct_str;

    // Create ECDSA signature context
    ECDSA_SIG *signature = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, private_key);

    if (!signature) {
        // Handle signature generation failure
        return "";
    }

    // Serialize the signature
    unsigned char *sig_der = nullptr;
    int sig_len = i2d_ECDSA_SIG(signature, &sig_der);
    string signature_str;
    if (sig_len > 0) {
    	// Convert binary signature to hexadecimal string
    	std::ostringstream oss;
    	for (int i = 0; i < sig_len; ++i) {
    		oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(sig_der[i]);
    	}
    	signature_str = oss.str();
    	OPENSSL_free(sig_der);
    }

    // Free ECDSA signature context
    ECDSA_SIG_free(signature);

    return signature_str;
}

// Function to encrypt data using AES
bool CryptoLib::encryptData(const unsigned char* plaintext, size_t plaintextLen, const unsigned char* key, unsigned char* ciphertext, size_t& ciphertextLen) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertextLenInt;

    EVP_CIPHER_CTX_init(ctx);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintextLen);
    ciphertextLenInt = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertextLenInt += len;

    EVP_CIPHER_CTX_free(ctx);

    ciphertextLen = static_cast<size_t>(ciphertextLenInt);
    return true;
}

// Function to decrypt data using AES
bool CryptoLib::decryptData(const unsigned char* ciphertext, size_t ciphertextLen, const unsigned char* key, unsigned char* decryptedtext, size_t& decryptedtextLen) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int decryptedtextLenInt;

    EVP_CIPHER_CTX_init(ctx);
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL);
    EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertextLen);
    decryptedtextLenInt = len;
    EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len);
    decryptedtextLenInt += len;

    EVP_CIPHER_CTX_free(ctx);

    decryptedtextLen = static_cast<size_t>(decryptedtextLenInt);
    return true;
}

bool CryptoLib::deriveSharedSecret(const EC_KEY* privateKey, const EC_POINT* peerPublicKey, unsigned char* sharedSecret, size_t sharedSecretLen) {
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *privKey = EVP_PKEY_new();
	EVP_PKEY *pubKey = EVP_PKEY_new();
	int ret = 0;

	// Set the EC private key
	ret = EVP_PKEY_set1_EC_KEY(privKey, (EC_KEY *)privateKey);
	if (ret != 1) {
		EVP_PKEY_free(privKey);
		EVP_PKEY_free(pubKey);
		return false;
	}

	EC_KEY *ecKey = generateECKeyPair();
	if (!EC_KEY_set_public_key(ecKey, peerPublicKey)) {
		EVP_PKEY_free(privKey);
		EVP_PKEY_free(pubKey);
		EC_KEY_free(ecKey);
		return false;
	}

	// Set the EC public key
	ret = EVP_PKEY_set1_EC_KEY(pubKey, ecKey);
	EC_KEY_free(ecKey);
	if (ret != 1) {
		EVP_PKEY_free(privKey);
		EVP_PKEY_free(pubKey);
		return false;
	}

	// Create context
	ctx = EVP_PKEY_CTX_new(privKey, NULL);
	if (!ctx) {
		EVP_PKEY_free(privKey);
		EVP_PKEY_free(pubKey);
		return false;
	}

	// Initialize context
	ret = EVP_PKEY_derive_init(ctx);
	if (ret != 1) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(privKey);
		EVP_PKEY_free(pubKey);
		return false;
	}

	// Set the peer's public key
	ret = EVP_PKEY_derive_set_peer(ctx, pubKey);
	if (ret != 1) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(privKey);
		EVP_PKEY_free(pubKey);
		return false;
	}

	// Derive the shared secret
	ret = EVP_PKEY_derive(ctx, sharedSecret, &sharedSecretLen);
	if (ret != 1) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(privKey);
		EVP_PKEY_free(pubKey);
		return false;
	}

	// Clean up
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(privKey);
	EVP_PKEY_free(pubKey);
	return true;
}

// Verifying certificate
// Checks if certificate issuer is equivalent to the issuer given
// Simple as fuck because nothing else I did worked.
bool CryptoLib::verifyCertificate(const x509& certificate, EC_KEY* issuerKey) {
    if (!issuerKey) {
    	cerr << "Invalid issuer key pair" << endl;
        return false;
    }

    // To verify signature, we need the issuer's public key
    const EC_POINT* issuer = certificate.issuer;
    const EC_POINT* givenIssuerPub = EC_KEY_get0_public_key(issuerKey);

    if (issuer == givenIssuerPub) {
    	return true;
    }

    return false;
}
