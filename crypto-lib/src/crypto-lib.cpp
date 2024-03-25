/*
 * crypto-lib.cpp
 *
 *  Created on: Mar. 23, 2024
 *      Author: Marcus Moquin
 */

#include "defs.h"

int main() {
	std::cout << "-----------------KEY GENERATION----------------" << std::endl;
	// add null checks
	RSA *keyPairA = generateRSAKeyPair();
	// Used to get public key from private key above
	RSA *pubKeyA = RSAPublicKey_dup(keyPairA);

	RSA *keyPairB = generateRSAKeyPair();
	RSA *pubKeyB = RSAPublicKey_dup(keyPairB);

	std::cout << "A's Key Pair: " << keyPairA << endl;
	std::cout << "A's Public Key: " << pubKeyA << endl;
	std::cout << std::endl;
	std::cout << "B's Key Pair: " << keyPairB << endl;
	std::cout << "B's Public Key: " << pubKeyB << endl;

	std::cout << "------------------CERTIFICATES-----------------" << std::endl;

	RSA* rootKey = generateRSAKeyPair();
	x509 root = generateRootCert(RSAPublicKey_dup(rootKey));

	x509 certificateA("A", pubKeyA, "", "A was here", nullptr, time(nullptr) * 1000, certificateA.issue_date + YEAR_IN_MS);
	x509 certificateB("B", pubKeyB, "", "B can be here", nullptr, time(nullptr) * 1000, certificateB.issue_date + YEAR_IN_MS);

	if (signCertificate(&certificateA, rootKey, &root)) {
		cout << "Successfully signed Certificate A" << endl;
	} else {
		cerr << "Failed signing certificate A, contact Tahbib (marcus is out of office)" << endl;
	}

	if (signCertificate(&certificateB, rootKey, &root)) {
		cout << "Successfully signed Certificate B" << endl;
	} else {
		cerr << "Failed signing certificate B, contact Tahbib (marcus is out of office)" << endl;
	}

	std::cout << "Certificate for A's public key" << std::endl;
	std::cout << " Name: " << certificateA.name << std::endl;
	std::cout << " Public Key: " << certificateA.public_key << std::endl;
	std::cout << " Signature: " << certificateA.signature << std::endl;
	std::cout << " Location: " << certificateA.location << std::endl;
	std::cout << " Issuer: Certificate" << std::endl;
	std::cout << "  Name: " << certificateA.issuer->name << std::endl;
	std::cout << "  Public Key: " << certificateA.issuer->public_key << std::endl;
	std::cout << "  Signature: " << certificateA.issuer->signature << std::endl;
	std::cout << "  Location: " << certificateA.issuer->location << std::endl;
	std::cout << "  Issue Date: " << certificateA.issuer->issue_date << std::endl;
	std::cout << "  Valid Until: " << certificateA.issuer->valid_until << std::endl;
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
	std::cout << "  Name: " << certificateB.issuer->name << std::endl;
	std::cout << "  Public Key: " << certificateB.issuer->public_key << std::endl;
	std::cout << "  Signature: " << certificateB.issuer->signature << std::endl;
	std::cout << "  Location: " << certificateB.issuer->location << std::endl;
	std::cout << "  Issue Date: " << certificateB.issuer->issue_date << std::endl;
	std::cout << "  Valid Until: " << certificateB.issuer->valid_until << std::endl;
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
	map<string, RSA*> keyMap;
	keyMap["Root"] = root.public_key;
	keyMap["A"] = pubKeyA;
	keyMap["B"] = pubKeyB;

	std::cout << "Verify Certificate A: " << verifyCertificate(&certificateA, keyMap) << std::endl;
	std::cout << "Verify Certificate B: " << verifyCertificate(&certificateB, keyMap) << std::endl;

	RSA_free(keyPairA);
	RSA_free(pubKeyA);
	RSA_free(keyPairB);
	RSA_free(pubKeyB);
	return 0;
}
