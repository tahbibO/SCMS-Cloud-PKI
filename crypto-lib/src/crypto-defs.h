/*
 * defs.h
 *
 *  Created on: Mar. 25, 2024
 *      Author: Marcus Moquin
 */
#pragma once

#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include <vector>
#include <map>
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
#include <openssl/err.h>
#include <cstring>

#define YEAR_IN_MS 				31536000000
#define MSG_LENGTH 				1024
#define ECDSA_SIGNATURE_SIZE 	64


void handleOpenSSLErrors() {
    ERR_print_errors_fp(stderr);
}

// Function to convert RSA public key to string
std::string publicKeyToString(RSA* rsaKey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSA_PUBKEY(bio, rsaKey)) {
        BIO_free(bio);
        return "";
    }

    char* buffer;
    long length = BIO_get_mem_data(bio, &buffer);
    std::string publicKeyStr(buffer, length);

    BIO_free(bio);
    return publicKeyStr;
}

// Function to copy RSA key from one object to another
bool copyRSAKey(RSA* rsaKeySrc, RSA* rsaKeyDest) {
    if (!rsaKeySrc || !rsaKeyDest) {
        std::cerr << "Invalid RSA key objects." << std::endl;
        return false;
    }

    // Copy RSA key components
    if (!RSA_set0_key(rsaKeyDest, BN_dup(RSA_get0_n(rsaKeySrc)), BN_dup(RSA_get0_e(rsaKeySrc)), nullptr)) {
        std::cerr << "Error setting RSA key components." << std::endl;
        return false;
    }

    return true;
}


// Function to convert string to RSA public key
RSA* stringToPublicKey(const std::string& publicKeyStr) {
    BIO* bio = BIO_new_mem_buf(publicKeyStr.c_str(), publicKeyStr.length());
    if (!bio) {
        return nullptr;
    }

    RSA* rsaKey = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return rsaKey;
}




struct x509 {
	std::string name;
	std::string public_key;
	std::string signature;
	std::string location;
	std::string issuer; // issuer cert
	long issue_date;
	long valid_until;

	// pubKey must be PUBLIC KEY. private key/whole keypair will break everything
	x509(std::string certName,
			std::string pubKey,
			std::string sig,
			std::string loc,
			std::string issr,
			long issue,
			long valid):
				name(certName),
				public_key(pubKey),
				signature(sig),
				location(loc),
				issuer(issr),
				issue_date(issue),
				valid_until(valid) {};


	x509(x509* other){
		x509(other->name, other->public_key, other->signature,other->location,other->issuer,other->issue_date,other->valid_until);
	}

	bool isSerializedEqual(std::string other) {
		return this->serialize() == other;
	}

	bool isEqual(const x509 &other) const {
		if (this->name != other.name) {
			return false;
		}

		if (this->public_key != other.public_key) {
			return false;
		}

		if (this->location != other.location) {
			return false;
		}

		if (this->issue_date != other.issue_date) {
			return false;
		}

		if (this->valid_until != other.valid_until) {
			return false;
		}

		return true;
	}

	std::string serialize() {
		std::stringstream ss;

		ss << "name:" << this->name << ";";
		ss << "public_key:" << this->public_key << ";";
		ss << "location:" << this->location << ";";
		ss << "issuer:" << this->issuer << ";";
		ss << "issue_data:" << this->issue_date << ";";
		ss << "valid_until:" << this->valid_until << ";";

		return ss.str();
	}

};

bool deserialize(x509* result, const std::string& serialized) {
        std::stringstream ss(serialized);
        std::string token;

        while (std::getline(ss, token, ';')) {
            std::istringstream tokenStream(token);
            std::string key, value;
            std::getline(tokenStream, key, ':');
            std::getline(tokenStream, value);

            if (key == "name") {
                result->name = value;
            } else if (key == "public_key") {
                result->public_key = value;
            } else if (key == "location") {
                result->location = value;
            } else if (key == "issuer") {
                result->issuer = value;
            } else if (key == "issue_date") {
                result->issue_date = std::stol(value);
            } else if (key == "valid_until") {
                result->valid_until = std::stol(value);
            }
        }

        return true;
    }

// Generates private key
RSA* generateRSAKeyPair() {
	RSA *rsa = RSA_new();
	BIGNUM *e = BN_new();

	if (!rsa || !e) {
		RSA_free(rsa);
		BN_free(e);
		return nullptr;
	}

    if (!BN_set_word(e, RSA_F4)) {
        RSA_free(rsa);
        BN_free(e);
        return nullptr;
    }

    if (!RSA_generate_key_ex(rsa, 2048, e, nullptr)) {
        RSA_free(rsa);
        BN_free(e);
        return nullptr;
    }

    BN_free(e);
    return rsa;
}

x509 generateRootCert(std::string public_key) {
	return x509("Root", public_key, "", "", "", -1L, -1L);
}

// always should be private key
std::string signData(const std::string &data, const RSA *key) {
    int rsaLen = RSA_size(key);
    std::string encryptedData;
    encryptedData.resize(rsaLen);

    int result = RSA_private_encrypt(data.length(), reinterpret_cast<const unsigned char*>(data.c_str()), reinterpret_cast<unsigned char*>(&encryptedData[0]), const_cast<RSA*>(key), RSA_PKCS1_PADDING);
    if (result == -1) {
    	handleOpenSSLErrors();
        return "";
    }

    encryptedData.resize(result);
    return encryptedData;
}

// always should be public key
std::string verifyData(const std::string &encryptedData, const RSA *key) {
    int rsaLen = RSA_size(key);
    std::string decryptedData;
    decryptedData.resize(rsaLen);

    int result = RSA_public_decrypt(encryptedData.length(), reinterpret_cast<const unsigned char*>(&encryptedData[0]), reinterpret_cast<unsigned char*>(&decryptedData[0]), const_cast<RSA*>(key), RSA_PKCS1_PADDING);
    if (result == -1) {
    	handleOpenSSLErrors();
        return "";
    }

    decryptedData.resize(result);
    return decryptedData;
}

bool signCertificate(x509 *certificate, RSA* private_key, x509 *issuerCertificate) {
	if (certificate == nullptr || issuerCertificate == nullptr || private_key == nullptr) {
		return false;
	}

	certificate->issuer = issuerCertificate->name;

	std::string signedData = signData(certificate->serialize(), private_key);
	if (signedData == "") {
		return false;
	}

	certificate->signature = signedData;
	return true;
}

// map is name associated, public key
bool verifyCertificate(x509 *certificate, std::map<std::string, RSA*> keyMap, std::map<std::string, x509*> certMap) {

	if (certificate == nullptr) {
		std::cerr << "Certificate is null" << std::endl;
		return false;
	}

	if (certificate->name == "Root") {
		return true;
	}

	// cannot find issuer in cert map
	if (certMap.find(certificate->issuer) == certMap.end()) {
		std::cerr << "Certificate Issuer is null" << std::endl;
		return false;
	}

	if (keyMap.find(certificate->issuer) == keyMap.end()) {
		std::cerr << "Could not find " << certificate->issuer << " key in key map." << std::endl;
		return false;
	}

	RSA *key = keyMap[certificate->issuer];
	std::string decrypted = verifyData(certificate->signature, key);

	if (!certificate->isSerializedEqual(decrypted)) {
		std::cerr << "Serialized is NOT equal" << std::endl;
		return false;
	}
	x509* nextCert = certMap[certificate->issuer];
	return verifyCertificate(nextCert, keyMap, certMap);
}


RSA* ROOT_KEY = generateRSAKeyPair();
x509 ROOT_CERT = generateRootCert(publicKeyToString(RSAPublicKey_dup(ROOT_KEY)));
