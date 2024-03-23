/*
 * main.cpp
 *
 *  Created on: Mar. 23, 2024
 *      Author: Marcus Moquin
 */

#include "crypto-lib.h"

int main() {
	CryptoLib *mCrypto = new CryptoLib();

	std::cout << "-----------------KEY GENERATION----------------" << std::endl;
	EC_KEY *keyPairA = mCrypto->generateECKeyPair();
	const EC_POINT *pubKeyA = EC_KEY_get0_public_key(keyPairA);

	EC_KEY *keyPairB = mCrypto->generateECKeyPair();
	const EC_POINT *pubKeyB = EC_KEY_get0_public_key(keyPairB);

	std::cout << "A's Key Pair: " << keyPairA << endl;
	std::cout << "A's Private Key: " << EC_KEY_get0_private_key(keyPairA) << endl;
	std::cout << "A's Public Key: " << pubKeyA << endl;
	std::cout << std::endl;
	std::cout << "B's Key Pair: " << keyPairB << endl;
	std::cout << "B's Private Key: " << EC_KEY_get0_private_key(keyPairB) << endl;
	std::cout << "B's Public Key: " << pubKeyB << endl;

	std::cout << "------------------KEY SIGNING------------------" << std::endl;

	string sigA = mCrypto->signKey(pubKeyA, keyPairA);
	std::cout << "A's Signature: " << sigA << endl;

	string sigB = mCrypto->signKey(pubKeyB, keyPairB);
	std::cout << "B's Signature: " << sigB << endl;

	std::cout << "------------------CERTIFICATES-----------------" << std::endl;

	// Certificate Testing
	x509 certificateA;
	certificateA.public_key = pubKeyA;
	certificateA.signature = sigB;
	certificateA.location = "idk here ig";
	certificateA.issuer = pubKeyB;
	certificateA.issue_date = time(nullptr) * 1000;
	certificateA.valid_until = certificateA.issue_date + YEAR_IN_MS; // a year

	x509 certificateB;
	certificateB.public_key = pubKeyB;
	certificateB.signature = sigA;
	certificateB.location = "idk here ig";
	certificateB.issuer = pubKeyA;
	certificateB.issue_date = time(nullptr) * 1000;
	certificateB.valid_until = certificateB.issue_date + YEAR_IN_MS; // a year

	std::cout << "Certificate for A's public key" << std::endl;
	std::cout << " Public Key: " << certificateA.public_key << std::endl;
	std::cout << " Signature: " << certificateA.signature << std::endl;
	std::cout << " Location: " << certificateA.location << std::endl;
	std::cout << " Issuer: " << certificateA.issuer << std::endl;
	std::cout << " Issue Date: " << certificateA.issue_date << std::endl;
	std::cout << " Valid Until: " << certificateA.valid_until << std::endl;
	std::cout << std::endl;

	// this works on a separate system, B system would know their own key pair and would be given certA
	bool certAVerified = mCrypto->verifyCertificate(certificateA, keyPairB);
	if (certAVerified) {
	    std::cout << "Certificate A verified." << std::endl;
	} else {
	    std::cout << "Certificate A verification failed." << std::endl;
	}

	std::cout << "----------------------------------------------" << std::endl;

	std::cout << "Certificate for B's public key" << std::endl;
	std::cout << " Public Key: " << certificateB.public_key << std::endl;
	std::cout << " Signature: " << certificateB.signature << std::endl;
	std::cout << " Location: " << certificateB.location << std::endl;
	std::cout << " Issuer: " << certificateB.issuer << std::endl;
	std::cout << " Issue Date: " << certificateB.issue_date << std::endl;
	std::cout << " Valid Until: " << certificateB.valid_until << std::endl;
	std::cout << std::endl;

	bool certBVerified = mCrypto->verifyCertificate(certificateB, keyPairA);
	if (certBVerified) {
		std::cout << "Certificate B verified." << std::endl;
	} else {
		std::cout << "Certificate B verification failed." << std::endl;
	}

	std::cout << "------------ENCRYPTING & DECRYPTING------------" << std::endl;

	const size_t sharedSecretLen = EVP_MD_size(EVP_sha256());
	unsigned char sharedSecret[sharedSecretLen];

	// Shared Secret, can confirm they work BOTH (Priv A, Pub B & Priv B, Pub A) ways
	if (!mCrypto->deriveSharedSecret(keyPairA, pubKeyB, sharedSecret, sharedSecretLen)) {
		cerr << "what the fuck man" << endl;
		return 1;
	}

	std::cout << "Shared Secret (hexadecimal): ";
	for (size_t i = 0; i < sharedSecretLen; ++i) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(sharedSecret[i]);
	}
	std::cout << std::endl;

	unsigned char plaintext[] = "I am Dr. Bakare Tunde, the cousin of Nigerian Astronaut, Air Force Major Abacha Tunde. He was the first African in space when he made a secret flight to the Salyut 6 space station in 1979. He was on a later Soviet spaceflight, Soyuz T-16Z to the secret Soviet military space station Salyut 8T in 1989. He was stranded there in 1990 when the Soviet Union was dissolved. His other Soviet crew members returned to earth on the Soyuz T-16Z, but his place was taken up by return cargo. There have been occasional Progrez supply flights to keep him going since that time. He is in good humor, but wants to come home.";
	size_t plaintextLen = strlen((char*)plaintext);

	// First 256 Bits of the shared secret
	unsigned char aesKey[32];
	memcpy(aesKey, sharedSecret, 32);

	unsigned char ciphertext[MSG_LENGTH];
	size_t ciphertextLen;
	if (!mCrypto->encryptData(plaintext, plaintextLen, aesKey, ciphertext, ciphertextLen)) {
		cerr << "encrypt fuckin broke" << endl;
		return 1;
	}

	// Print the encrypted ciphertext
	std::cout << "Encrypted Ciphertext (hexadecimal): ";
	for (size_t i = 0; i < ciphertextLen; ++i) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ciphertext[i]);
	}
	std::cout << std::endl;

	// Decrypt the ciphertext
	unsigned char decryptedtext[1024]; // Assuming decryptedtext won't exceed 1024 bytes
	size_t decryptedtextLen;
	if (!mCrypto->decryptData(ciphertext, ciphertextLen, aesKey, decryptedtext, decryptedtextLen)) {
		// Error handling
		return 1;
	}

	// Null-terminate the decrypted text to print it as a string
	decryptedtext[decryptedtextLen] = '\0';

	// Print the decrypted plaintext
	std::cout << "Decrypted Plaintext: " << decryptedtext << std::endl;

	std::cout << "-----------------------------------------------" << std::endl;

	EC_KEY_free(keyPairA);
	EC_KEY_free(keyPairB);
	EVP_cleanup();
	return 0;
}



