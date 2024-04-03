/*
 * crypto-lib.cpp
 *
 *  Created on: Mar. 23, 2024
 *      Author: Marcus Moquin
 */

#include "../../include/crypto-defs.h"
#include "../../include/networking-defs.h"



int main()
{

	std::cout << "-----------------KEY GENERATION----------------" << std::endl;
	RSA* test = readPrivateKeyFromFile("ROOT_PRIVATE_KEY.pem");
	std::cout << "File Public Key: " << RSAPublicKey_dup(test) << std::endl;
	std::cout << "Root Public Key: " << RSAPublicKey_dup(ROOT_KEY) << std::endl;
	//encrypt with test and decrypt with root
	auto dat = "Mama";
	std::string e_data = signData(dat,test);
	std::cout << "e_data: " << e_data <<std::endl;
	std::string d_data = verifyData(e_data,RSAPublicKey_dup(ROOT_KEY));
	std::cout << "d_data: " << d_data <<std::endl;

	RSA_free(test);

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
	std::cout << "1 = Pass" << std::endl;

	x509 certificateA("A", publicKeyToString(pubKeyA), "", "A was here", "", time(nullptr) * 1000, certificateA.issue_date + YEAR_IN_MS);
	x509 certificateB("B", publicKeyToString(pubKeyB), "", "B can be here", "", time(nullptr) * 1000, certificateB.issue_date + YEAR_IN_MS);

	if (signCertificate(&certificateA, ROOT_KEY, &ROOT_CERT))
	{
		std::cout << "Successfully signed Certificate A" << std::endl;
	}
	else
	{
		std::cerr << "Failed signing certificate A, contact Tahbib (marcus is out of office)" << std::endl;
	}

	if (signCertificate(&certificateB, ROOT_KEY, &ROOT_CERT))
	{
		std::cout << "Successfully signed Certificate B" << std::endl;
	}
	else
	{
		std::cerr << "Failed signing certificate B, contact Tahbib (marcus is out of office)" << std::endl;
	}

	std::map<std::string, x509 *> certMap;
	certMap[ROOT_CERT.name] = &ROOT_CERT;
	certMap[certificateA.name] = &certificateA;
	certMap[certificateB.name] = &certificateB;

	std::map<std::string, RSA *> keyMap;
	RSA *pubKeyRoot = stringToPublicKey(ROOT_CERT.public_key);
	// RSA* pubKeyRoot = RSAPublicKey_dup(ROOT_KEY);
	keyMap["Root"] = pubKeyRoot;
	keyMap["A"] = pubKeyA;
	keyMap["B"] = pubKeyB;
	/*
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
	*/

	//std::cout << "----------------------------------------------" << std::endl;

	/*
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
	*/

	std::cout << "CertA == CertA? 		" << certificateA.isEqual(certificateA) << std::endl;									  		// 1
	std::cout << "CertA != CertB? 		" << !certificateA.isEqual(certificateB) << std::endl;									  	// 1
	std::cout << "CertA == CertA?(Serialized) 	" << certificateA.isSerializedEqual(certificateA.serialize()) << std::endl; 		// 1
	std::cout << "CertA != CertB?(Serialized) 	" << !certificateA.isSerializedEqual(certificateB.serialize()) << std::endl; 		// 1
	std::cout << "CertB == CertB? 		" << certificateB.isEqual(certificateB) << std::endl;									  		// 1
	std::cout << "CertB != CertA? 		" << !certificateB.isEqual(certificateA) << std::endl;									  	// 1
	std::cout << std::endl;

	// example, should just be done by OBE

	std::cout << "Verify Certificate A: 		" << verifyCertificate(&certificateA, keyMap, certMap) << std::endl; // 1 is good
	std::cout << "Verify Certificate B: 		" << verifyCertificate(&certificateB, keyMap, certMap) << std::endl; // 1 is good
	std::cout << std::endl;
	std::cout << std::endl;

	std::cout << "------------------Keys Conversion Functions-----------------" << std::endl;
	std::cout << "1 = Pass" << std::endl;

	std::string stringRootKey = ROOT_CERT.public_key;
	RSA *stringToKeyRoot = stringToPublicKey(stringRootKey);
	std::cout << "Root Key to String == Root to String(String to Root Key):	"
			  << (stringRootKey == publicKeyToString(stringToKeyRoot))
			  << std::endl; // 0 is valid

	RSA *keyPairACopy = RSA_new();
	copyRSAKey(keyPairA, keyPairACopy);
	std::cout << "Key A Copy String == Key A String:				"
			  << (publicKeyToString(keyPairACopy) == publicKeyToString(keyPairA))
			  << std::endl; // 0 is valid

	// generate key
	// make string root function
	// encrypt data normally
	// decrypt with normal public key and the string to pub key version

	RSA *publicKey = RSAPublicKey_dup(ROOT_KEY);
	RSA *stringKey = stringToPublicKey(publicKeyToString(publicKey));
	RSA *copyKey = RSA_new();
	copyRSAKey(publicKey, copyKey);
	std::string data = "Hello";

	std::string encryptedData = signData(data, ROOT_KEY);
	// std::cout << "Encrypted Data via Private Key:		" << encryptedData << std::endl;
	std::cout << "Verified Data via Public Key:		" << (verifyData(encryptedData, publicKey) == "Hello") << std::endl;
	std::cout << "Verified Data via String Public Key:	" << (verifyData(encryptedData, stringKey) == data) << std::endl;
	std::cout << "Verified Data via Copy Public Key:	" << (verifyData(encryptedData, copyKey) == data) << std::endl;

	std::cout << std::endl << "------------------Certificate Conversion  Functions-----------------" << std::endl;
	std::cout << "1 = Pass" << std::endl;


	x509 certC;
	certC.fromString(certificateA.toString());

	/*
	std::cout << "Certificate for C's public key" << std::endl;
	std::cout << "Name:		" << certC.name << std::endl;
	std::cout << "Public Key:	" << certC.public_key << std::endl;
	std::cout << "Signature:	" << certC.signature << std::endl;
	std::cout << "Location:	" << certC.location << std::endl;
	std::cout << "Issue Date:	" << certC.issue_date << std::endl;
	std::cout << "Valid Until:	" << certC.valid_until << std::endl;
	*/

	std::string someString = "Hello";
	std::string someEncryptedData = signData(someString, keyPairA);
	std::string someDecryptedData = verifyData(someEncryptedData, stringToPublicKey(certC.public_key));
	std::cout << "Decrypted Data == Data:	" << (someDecryptedData == "Hello") << std::endl;
/*
	std::cout << std::endl << "------------------Array Test Functions-----------------" << std::endl;
	std::cout << "1 = Pass" << std::endl;
	RSA *keyPairOne = generateRSAKeyPair();
	RSA *keyPairTwo = generateRSAKeyPair();
	RSA *keyPairThree = generateRSAKeyPair();
	RSA *keyPairFour = generateRSAKeyPair();
	RSA *keyPairFive = generateRSAKeyPair();

	RSA *pubKeyOne = RSAPublicKey_dup(keyPairOne);
	RSA *pubKeyTwo = RSAPublicKey_dup(keyPairTwo);
	RSA *pubKeyThree = RSAPublicKey_dup(keyPairThree);
	RSA *pubKeyFour = RSAPublicKey_dup(keyPairFour);
	RSA *pubKeyFive = RSAPublicKey_dup(keyPairFive);

	x509 certOne("One", publicKeyToString(pubKeyOne), "", "CA", "", time(nullptr) * 1000, time(nullptr) * 1000 + +YEAR_IN_MS);
	x509 certTwo("Two", publicKeyToString(pubKeyTwo), "", "CA", "", time(nullptr) * 1000, time(nullptr) * 1000 + +YEAR_IN_MS);
	x509 certThree("Three", publicKeyToString(pubKeyThree), "", "CA", "", time(nullptr) * 1000, time(nullptr) * 1000 + +YEAR_IN_MS);
	x509 certFour("Four", publicKeyToString(pubKeyFour), "", "CA", "", time(nullptr) * 1000, time(nullptr) * 1000 + +YEAR_IN_MS);
	x509 certFive("Five", publicKeyToString(pubKeyFive), "", "CA", "", time(nullptr) * 1000, time(nullptr) * 1000 + +YEAR_IN_MS);

	signCertificate(&certOne, ROOT_KEY, &ROOT_CERT);
	signCertificate(&certTwo, ROOT_KEY, &ROOT_CERT);
	signCertificate(&certThree, ROOT_KEY, &ROOT_CERT);
	signCertificate(&certFour, ROOT_KEY, &ROOT_CERT);
	signCertificate(&certFive, ROOT_KEY, &ROOT_CERT);

	std::string *certArray = new std::string[5];
	certArray[0] = certOne.toString();
	certArray[1] = certTwo.toString();
	certArray[2] = certThree.toString();
	certArray[3] = certFour.toString();
	certArray[4] = certFive.toString();

	//std::string resultStringArr = arrayToString(certArray, 5);

	std::cout << "resultStringArr: 	" << 5*resultStringArr.length() << std::endl;

	//std::string *certArrayTwo = stringToArray(resultStringArr,5);

	for(int i = 0;i<5;i++){
		x509 tempX509;
		//std::cout << certArrayTwo[i] << std::endl << std::endl;
		std::cout << "certArr[" << i << "] == certArrayTwo[" << i << "]	:	" << (certArray[i] == certArrayTwo[i]) << std::endl;

		tempX509.fromString(certArrayTwo[i]);
		std::cout << "cert entry " << i+1 << " name:	" << tempX509.name << std::endl;
		std::cout << "cert entry " << i+1 << " key:	" << tempX509.public_key << std::endl;
		std::cout << "cert entry " << i+1 << " signature:	" << tempX509.signature << std::endl;
		std::cout << "cert entry " << i+1 << " location:	" << tempX509.location << std::endl;
		std::cout << "cert entry " << i+1 << " issuer:	" << tempX509.issuer << std::endl;
		std::cout << "cert entry " << i+1 << " issue_date:	" << tempX509.issue_date << std::endl;
		std::cout << "cert entry " << i+1 << " valid until:	" << tempX509.valid_until<< std::endl;
		std::cout << std::endl << std::endl;

	}


	RSA_free(keyPairOne);
	RSA_free(keyPairTwo);
	RSA_free(keyPairThree);
	RSA_free(keyPairFour);
	RSA_free(keyPairFive);
	*/
	RSA_free(keyPairA);
	RSA_free(pubKeyA);
	RSA_free(keyPairB);
	RSA_free(pubKeyB);
	RSA_free(keyPairACopy);
	RSA_free(publicKey);
	RSA_free(copyKey);
	RSA_free(stringKey);
	RSA_free(ROOT_KEY);
	return 0;
}
