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

#define YEAR_IN_MS 31536000000
#define MSG_LENGTH 1024
#define ECDSA_SIGNATURE_SIZE 64

inline void handleOpenSSLErrors()
{
	ERR_print_errors_fp(stderr);
}

// Function to convert RSA public key to string
inline std::string publicKeyToString(RSA *rsaKey)
{
	BIO *bio = BIO_new(BIO_s_mem());
	if (!PEM_write_bio_RSA_PUBKEY(bio, rsaKey))
	{
		BIO_free(bio);
		return "";
	}

	char *buffer;
	long length = BIO_get_mem_data(bio, &buffer);
	std::string publicKeyStr(buffer, length);

	BIO_free(bio);
	return publicKeyStr;
}

// Function to copy RSA key from one object to another
inline bool copyRSAKey(RSA *rsaKeySrc, RSA *rsaKeyDest)
{
	if (!rsaKeySrc || !rsaKeyDest)
	{
		std::cerr << "Invalid RSA key objects." << std::endl;
		return false;
	}

	// Copy RSA key components
	if (!RSA_set0_key(rsaKeyDest, BN_dup(RSA_get0_n(rsaKeySrc)), BN_dup(RSA_get0_e(rsaKeySrc)), nullptr))
	{
		std::cerr << "Error setting RSA key components." << std::endl;
		return false;
	}

	return true;
}

// Function to convert string to RSA public key
inline RSA *stringToPublicKey(const std::string &publicKeyStr)
{
	BIO *bio = BIO_new_mem_buf(publicKeyStr.c_str(), publicKeyStr.length());
	if (!bio)
	{
		return nullptr;
	}

	RSA *rsaKey = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);
	return rsaKey;
}

struct x509
{
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
		 long valid) : name(certName),
					   public_key(pubKey),
					   signature(sig),
					   location(loc),
					   issuer(issr),
					   issue_date(issue),
					   valid_until(valid){};
	x509() {}

	x509(x509 *other)
	{
		this->name = other->name;
		this->public_key = other->public_key;
		this->signature = other->signature;
		this->location = other->location;
		this->issuer = other->issuer;
		this->issue_date = other->issue_date;
		this->valid_until = other->valid_until;
	}

	void copy(x509 *other)
	{
		this->name = other->name;
		this->public_key = other->public_key;
		this->signature = other->signature;
		this->location = other->location;
		this->issuer = other->issuer;
		this->issue_date = other->issue_date;
		this->valid_until = other->valid_until;
	}

	bool isSerializedEqual(std::string other)
	{
		return this->serialize() == other;
	}

	bool isEqual(const x509 &other) const
	{
		if (this->name != other.name)
		{
			return false;
		}

		if (this->public_key != other.public_key)
		{
			return false;
		}

		if (this->location != other.location)
		{
			return false;
		}

		if (this->issue_date != other.issue_date)
		{
			return false;
		}

		if (this->valid_until != other.valid_until)
		{
			return false;
		}

		return true;
	}

	std::string serialize()
	{
		std::stringstream ss;

		ss << "name:" << this->name << ";";
		// ss << "public_key:" << this->public_key << ";";
		ss << "location:" << this->location << ";";
		ss << "issuer:" << this->issuer << ";";
		ss << "issue_data:" << this->issue_date << ";";
		ss << "valid_until:" << this->valid_until << ";";

		return ss.str();
	}

	std::string toString()
	{
		std::stringstream ss;

		ss << "name:" << this->name << ";";
		ss << "public_key:" << this->public_key << ";";
		ss << "location:" << this->location << ";";
		ss << "issuer:" << this->issuer << ";";
		ss << "issue_date:" << this->issue_date << ";";
		ss << "valid_until:" << this->valid_until << ";";
		ss << "signature:" << this->signature << ";";

		return ss.str();
	}

	void fromString(std::string data)
	{
		std::stringstream ss(data);
		std::string field;

		while (std::getline(ss, field, ';'))
		{
			size_t pos = field.find(':');
			if (pos != std::string::npos)
			{
				std::string key = field.substr(0, pos);
				std::string value = field.substr(pos + 1);

				if (key == "name")
				{
					this->name = value;
				}
				else if (key == "public_key")
				{
					this->public_key = value;
				}
				else if (key == "signature")
				{
					this->signature = value;
				}
				else if (key == "location")
				{
					this->location = value;
				}
				else if (key == "issuer")
				{
					std::cout << "func: fromString, value: " << value << std::endl;

					this->issuer = value;
				}
				else if (key == "issue_date")
				{
					std::cout << "func: fromString, value: " << value << std::endl;
					this->issue_date = std::stol(value);
				}
				else if (key == "valid_until")
				{
					this->valid_until = std::stol(value);
				}
			}
		}
	}
};

// Generates private key
inline RSA *generateRSAKeyPair()
{
	RSA *rsa = RSA_new();
	BIGNUM *e = BN_new();

	if (!rsa || !e)
	{
		RSA_free(rsa);
		BN_free(e);
		return nullptr;
	}

	if (!BN_set_word(e, RSA_F4))
	{
		RSA_free(rsa);
		BN_free(e);
		return nullptr;
	}

	if (!RSA_generate_key_ex(rsa, 2048, e, nullptr))
	{
		RSA_free(rsa);
		BN_free(e);
		return nullptr;
	}

	BN_free(e);
	return rsa;
}

inline x509 generateRootCert(std::string public_key)
{
	return x509("Root", public_key, "", "", "", -1L, -1L);
}

// always should be private key
inline std::string signData(const std::string &data, const RSA *key)
{
	int rsaLen = RSA_size(key);
	std::string encryptedData;
	encryptedData.resize(rsaLen);

	int result = RSA_private_encrypt(data.length(), reinterpret_cast<const unsigned char *>(data.c_str()), reinterpret_cast<unsigned char *>(&encryptedData[0]), const_cast<RSA *>(key), RSA_PKCS1_PADDING);
	if (result == -1)
	{
		handleOpenSSLErrors();
		return "";
	}

	encryptedData.resize(result);
	return encryptedData;
}

// always should be public key
inline std::string verifyData(const std::string &encryptedData, const RSA *key)
{
	int rsaLen = RSA_size(key);
	std::string decryptedData;
	decryptedData.resize(rsaLen);

	int result = RSA_public_decrypt(encryptedData.length(), reinterpret_cast<const unsigned char *>(&encryptedData[0]), reinterpret_cast<unsigned char *>(&decryptedData[0]), const_cast<RSA *>(key), RSA_PKCS1_PADDING);
	if (result == -1)
	{
		handleOpenSSLErrors();
		return "";
	}

	decryptedData.resize(result);
	return decryptedData;
}

inline bool signCertificate(x509 *certificate, RSA *private_key, x509 *issuerCertificate)
{
	if (certificate == nullptr || issuerCertificate == nullptr || private_key == nullptr)
	{
		return false;
	}

	certificate->issuer = issuerCertificate->name;

	std::string signedData = signData(certificate->serialize(), private_key);
	if (signedData == "")
	{
		return false;
	}

	certificate->signature = signedData;
	return true;
}

// map is name associated, public key
inline bool verifyCertificate(x509 *certificate, std::map<std::string, RSA *> keyMap, std::map<std::string, x509 *> certMap)
{

	if (certificate == nullptr)
	{
		std::cerr << "Certificate is null" << std::endl;
		return false;
	}

	if (certificate->name == "Root")
	{
		return true;
	}

	// cannot find issuer in cert map
	if (certMap.find(certificate->issuer) == certMap.end())
	{
		std::cerr << "Certificate Issuer is null" << std::endl;
		return false;
	}

	if (keyMap.find(certificate->issuer) == keyMap.end())
	{
		std::cerr << "Could not find " << certificate->issuer << " key in key map." << std::endl;
		return false;
	}

	RSA *key = keyMap[certificate->issuer];
	std::string decrypted = verifyData(certificate->signature, key);

	if (!certificate->isSerializedEqual(decrypted))
	{
		std::cerr << "Serialized is NOT equal" << std::endl;
		return false;
	}
	x509 *nextCert = certMap[certificate->issuer];
	return verifyCertificate(nextCert, keyMap, certMap);
}


inline std::string STRING_ROOT_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----"
		"MIIEowIBAAKCAQEAnVMI3YnnTFFFf0MyWqYJN3DbbQhGskTcpjH7pyxEaWsy1Sfv"
		"wb8Vg0vGMA8km3qd5HGQXR8BMrhuRSNbBAxwcCCLZKNB8wN7N5I+ZkC/46YOs6bQ"
		"fWg7WsOk7sSiBr+qsDNNDHpmSff39HeDUYBbUIEyyFENeJ72lCvME+0fBgv9KIaT"
		"zGYxFny8NtVdY2cpxNNdBvGzLW+l8UxQ8bV+F98ARh08zr7ex18RSP2/QV3aFpvm"
		"qfLqbQlUMB3W/s6TZWZRkE0cPC9IYq5bsR35NT7JCfn0MBX2wmzxbw6hnwBgMPNM"
		"BhBqFsCVegc0lMgR+0nvEIgIhZ2C4T6msjgWnwIDAQABAoIBAAw07iIqWgz83VST"
		"hSutaFep5QyfsMSSPUCT7j+5WpGHZMlPMPYqemPWlEkUU7XQnMGl4hqnljM2RjAN"
		"HznAMVUx4T7sv+g4I+5a5YaPjZP/RXLBBbpFRR20wm5YSW4WnwrO4DKQqLEikVWh"
		"lEnVmMA1Vhhe2Zm7U8yJXWtKYbbZRiSk6UIvsYnks81TNGToIjagZyjpilAPGcFy"
		"kwlOrp02yt8FR4+fvwZUg8jn7ZT2ysdOwb0pXgFYsEV2OyDLJtBsCZ99/dPX9UWL"
		"Tj1IJVZ/ssQEq4WxI3mXpXVz3XTilVfh4qPkHRAgb+Tv4Ef0j+G7C1VEMdHMvmKJ"
		"kYcjAwECgYEAy/pwpgCcw+qivg4pZTo8fWm4aFPXuCXMOaS3KUyIqABSotrsLP5V"
		"v5eB7QuV1E/9qSsArAnem9eNcZg17oVKNOTMX4pS65IXTyNG9FJEh+E8zrDB0tze"
		"fgH1cO3BNmydCvbD5/1HFoIb7W5sxGyWESavayKrULlKovH1h/FuHx8CgYEAxXKZ"
		"76dj8k1ReY0OwjySraBl7dZBvbsYLjJ83VfcVwdRJ+mMQY8ZSy8U3eNN6mT/V4d+"
		"yD9c5RO2TbfZYRkYDFy2o6lDRhGpkCd2HXxurpCFAqtoySd8FRV98YXRLIfrtCck"
		"vejuVO2GmZPlfYG3Ei86DYEKumqTzzTQMLDAmIECgYEAthnjL5AkZBO5LoteEW0o"
		"S55yb1FKqK+131BZ5Jja94EyRQnFB3YX/2+3InTRUjYHc1tcwjodbmvFbsBAhayh"
		"Tw9kFXdcB8ro3FHWKpC3dcdzjeLnZuSgDUaaZDMd5wSYPw2GYDoRmNqXLCUFHWcD"
		"olQzDyZoYyzIoSf511+GvGkCgYAfmppdK9PposqZxCRKnttzgysNiK/5KItUSayG"
		"2VthasBovQ9AJyGLUTvr0EhWblgYsI1wjAPYfvE9O2JGEngw8l4hkCQ+gPE9K7PS"
		"QGqO8n730GvzVqibz1bbY+n5UMA/k8xjwXb0jRhwWKXxEuQ0uu513uPStuB12CRC"
		"xuftAQKBgB0NaznOV0Uhgrb1nr0Hs5IOJmnYkTQPMsS/BIjDN0G1evKqTBzLlNac"
		"qrcLmXUkok0lXIw4ncLjzwqZAWl9h1l/nL2+XYVLDLHrXpGikfAaQ5xscie0Haon"
		"SXjL5K1x5jhLl33s8k/pl2d05JQNAF18Ro7astn8lFS2BtTQs+ev"
		"-----END RSA PRIVATE KEY-----"

inline RSA *ROOT_KEY = stringToPrivateKey(STRING_ROOT_PRIVATE_KEY);
inline x509 ROOT_CERT = generateRootCert(publicKeyToString(RSAPublicKey_dup(ROOT_KEY)));