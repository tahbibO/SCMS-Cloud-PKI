/*
 * certificateAuthority.cpp
 *
 *  Created on: Mar. 31, 2024
 *      Author: Muaadh Ali
 */
#include "certificateAuthority.hpp"

#include <iostream>

certificateAuthority::certificateAuthority(std::string name, std::string location){
	key_pair = nullptr;
    long int t = static_cast<long int> (time(NULL));
	this->name = name;
	long issue_date = t;
	long valid_until = t + 604800;
	cert = x509(name, "", "", location, "", issue_date, valid_until);


}

certificateAuthority::~certificateAuthority() {
	if (key_pair != nullptr){
	    RSA_free(key_pair);
	}
}

x509* certificateAuthority::get_cert() {
    return &cert;
}

std::string certificateAuthority::getName(){
	return name;
}

void certificateAuthority::issue_cert(x509 *certificate) {
    signCertificate(certificate, key_pair, &cert);
}

rootCertificateAuthority::rootCertificateAuthority(std::string name, std::string location) :
		certificateAuthority(name,location) {
	key_pair = ROOT_KEY;
	cert.public_key = publicKeyToString(RSAPublicKey_dup(key_pair));

}

void rootCertificateAuthority::self_sign() {
    cert = ROOT_CERT;
}

enrollmentCertificateAuthority::enrollmentCertificateAuthority(std::string name, std::string location) :
		certificateAuthority(name,location) {
	key_pair = generateRSAKeyPair();
	cert.public_key = publicKeyToString(RSAPublicKey_dup(key_pair));

}

bool enrollmentCertificateAuthority::enroll_device(x509 *certificate) {
    if (signCertificate(certificate, key_pair, &cert))
    {
        return true;
    }

    return false;
    
}

pseudonymCertificateAuthority::pseudonymCertificateAuthority(std::string name,std::string location) :
		certificateAuthority(name,location) {
	key_pair = generateRSAKeyPair();
	cert.public_key = publicKeyToString(RSAPublicKey_dup(key_pair));
}

void printcert(x509* a) {
    std::cout << "printing cert" << a->public_key << " "
        << a->signature << " "
        << a->location << " "
        << a->issuer<< " "
        << a->issue_date<< " "
        << a->valid_until;
}

