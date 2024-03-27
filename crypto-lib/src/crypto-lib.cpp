/*
 * crypto-lib.cpp
 *
 *  Created on: Mar. 23, 2024
 *      Author: Marcus Moquin
 */

#include "crypto-defs.h"

int main() {

	std::cout << "-----------------KEY GENERATION----------------" << std::endl;

	// add null checks
	RSA *keyPairA = generateRSAKeyPair();
	// Used to get public key from private key above
	RSA *pubKeyA = RSAPublicKey_dup(keyPairA);

	RSA *keyPairB = generateRSAKeyPair();
	RSA *pubKeyB = RSAPublicKey_dup(keyPairB);

	std::cout << "A's Key Pair: " << keyPairA << std::endl;
	std::cout << "A's Public Key: " << pubKeyA << std::endl;
	std::cout << std::endl;
	std::cout << "B's Key Pair: " << keyPairB << std::endl;
	std::cout << "B's Public Key: " << pubKeyB << std::endl;

	std::cout << "------------------CERTIFICATES-----------------" << std::endl;


	x509 certificateA("A", publicKeyToString(pubKeyA), "", "A was here", "", time(nullptr) * 1000, certificateA.issue_date + YEAR_IN_MS);
	x509 certificateB("B", publicKeyToString(pubKeyB), "", "B can be here", "", time(nullptr) * 1000, certificateB.issue_date + YEAR_IN_MS);

	if (signCertificate(&certificateA, ROOT_KEY, &ROOT_CERT)) {
		std::cout << "Successfully signed Certificate A" << std::endl;
	} else {
		std::cerr << "Failed signing certificate A, contact Tahbib (marcus is out of office)" << std::endl;
	}

	if (signCertificate(&certificateB, ROOT_KEY, &ROOT_CERT)) {
		std::cout << "Successfully signed Certificate B" << std::endl;
	} else {
		std::cerr << "Failed signing certificate B, contact Tahbib (marcus is out of office)" << std::endl;
	}

	std::map<std::string, x509*> certMap;
	certMap[ROOT_CERT.name] = &ROOT_CERT;
	certMap[certificateA.name] = &certificateA;
	certMap[certificateB.name] = &certificateB;

	std::map<std::string, RSA*> keyMap;
	RSA* pubKeyRoot = stringToPublicKey(ROOT_CERT.public_key);
	keyMap["Root"] = pubKeyRoot;
	keyMap["A"] = pubKeyA;
	keyMap["B"] = pubKeyB;

	std::cout << "Certificate for A's public key" << std::endl;
	std::cout << " Name: " << certificateA.name << std::endl;
	std::cout << " Public Key: " << certificateA.public_key << std::endl;
	std::cout << " Signature: " << certificateA.signature << std::endl;
	std::cout << " Location: " << certificateA.location << std::endl;
	std::cout << " Issuer: Certificate" << std::endl;
	std::cout << "  Name: " << certMap[certificateA.issuer]->name << std::endl;
	std::cout << "  Public Key: " << certMap[certificateA.issuer]->public_key << std::endl;
	std::cout << "  Signature: " << certMap[certificateA.issuer]->signature << std::endl;
	std::cout << "  Location: " << certMap[certificateA.issuer]->location << std::endl;
	std::cout << "  Issue Date: " << certMap[certificateA.issuer]->issue_date << std::endl;
	std::cout << "  Valid Until: " << certMap[certificateA.issuer]->valid_until << std::endl;
	std::cout << " Issue Date: " << certificateA.issue_date << std::endl;
	std::cout << " Valid Until: " << certificateA.valid_until << std::endl;
	std::cout << std::endl;

	std::cout << "----------------------------------------------" << std::endl;

	std::cout << "Certificate for B's public key" << std::endl;
	std::cout << " Name: " << certificateB.name << std::endl;
	std::cout << " Public Key: " << certificateB.public_key << std::endl;
	std::cout << " Signature: " << certificateB.signature << std::endl;
	std::cout << " Location: " << certificateB.location << std::endl;
	std::cout << " Issuer: Certificate" << std::endl;
	std::cout << "  Name: " << certMap[certificateB.issuer]->name << std::endl;
	std::cout << "  Public Key: " << certMap[certificateB.issuer]->public_key << std::endl;
	std::cout << "  Signature: " << certMap[certificateB.issuer]->signature << std::endl;
	std::cout << "  Location: " << certMap[certificateB.issuer]->location << std::endl;
	std::cout << "  Issue Date: " << certMap[certificateB.issuer]->issue_date << std::endl;
	std::cout << "  Valid Until: " << certMap[certificateB.issuer]->valid_until << std::endl;
	std::cout << " Issue Date: " << certificateB.issue_date << std::endl;
	std::cout << " Valid Until: " << certificateB.valid_until << std::endl;
	std::cout << std::endl;

	std::cout << "CertA == CertA? " << certificateA.isEqual(certificateA) << std::endl; // 1
	std::cout << "CertA == CertB? " << certificateA.isEqual(certificateB) << std::endl; // 0
	std::cout << "CertA == CertA?(Serialized) " << certificateA.isSerializedEqual(certificateA.serialize()) << std::endl; // 1
	std::cout << "CertA == CertB?(Serialized) " << certificateA.isSerializedEqual(certificateB.serialize()) << std::endl; // 0
	std::cout << "CertB == CertB? " << certificateB.isEqual(certificateB) << std::endl; // 1
	std::cout << "CertB == CertA? " << certificateB.isEqual(certificateA) << std::endl; // 0
	std::cout << std::endl;

	// example, should just be done by OBE




	std::cout << "Verify Certificate A: " << verifyCertificate(&certificateA, keyMap,certMap) << std::endl; // 1 is good
	std::cout << "Verify Certificate B: " << verifyCertificate(&certificateB, keyMap,certMap) << std::endl; // 1 is good
	std::cout << std::endl;
	std::cout << std::endl;

	std::cout << "------------------Keys Helper Functions-----------------" << std::endl;

	std::string stringRootKey = ROOT_CERT.public_key;
	RSA* stringToKeyRoot = stringToPublicKey(stringRootKey);
	std::cout << "Root Key to String == Root to String(String to Root Key)?:	"
			<< (stringRootKey.compare(publicKeyToString(stringToKeyRoot)))
			<< std::endl; // 0 is valid

	RSA* keyPairACopy = RSA_new();
	copyRSAKey(keyPairA, keyPairACopy);
	std::cout << "Key A Copy String == Key A String?:				"
			<< (publicKeyToString(keyPairACopy).compare(publicKeyToString(keyPairA)))
			<< std::endl; // 0 is valid

	std::cout << "--------------------------------------------------------" << std::endl;
// TODO: function to test deserialization
// TODO: function to test serialization
// TODO: function to test copy constructor
// TODO: function to test


	RSA_free(keyPairA);
	RSA_free(pubKeyA);
	RSA_free(keyPairB);
	RSA_free(pubKeyB);
	RSA_free(keyPairACopy);
	return 0;

}
