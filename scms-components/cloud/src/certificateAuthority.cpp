/*
 * certificateAuthority.cpp
 *
 *  Created on: Mar. 31, 2024
 *      Author: Muaadh Ali
 */
#include "certificateAuthority.hpp"

#include <iostream>

certificateAuthority::certificateAuthority(){
    key_pair = generateRSAKeyPair();
    long int t = static_cast<long int> (time(NULL));
	name = typeid(this).name();
	std::string location = std::string(typeid(this).name()) + " Location";
	long issue_date = t;
	long valid_until = t + 604800;

	cert = x509(name, publicKeyToString(RSAPublicKey_dup(key_pair)), "", "CA", "", issue_date, valid_until);
}

certificateAuthority::~certificateAuthority() {
    RSA_free(key_pair);
}

x509* certificateAuthority::get_cert() {
    return &cert;
}

void certificateAuthority::issue_cert(x509 *certificate) {
    signCertificate(certificate, key_pair, &cert);
}

rootCertificateAuthority::rootCertificateAuthority() : certificateAuthority() {

}

void rootCertificateAuthority::self_sign() {
    cert = ROOT_CERT;
}

enrollmentCertificateAuthority::enrollmentCertificateAuthority() : certificateAuthority() {

}

bool enrollmentCertificateAuthority::enroll_device(x509 *certificate) {
    if (signCertificate(certificate, key_pair, &cert))
    {
        return true;
    }

    return false;
    
}

pseudonymCertificateAuthority::pseudonymCertificateAuthority() : certificateAuthority() {

}

void printcert(x509 a) {
    std::cout << "printing a.cert" << a.public_key << " " 
        << a.signature << " " 
        << a.location << " " 
        << a.issuer<< " " 
        << a.issue_date<< " " 
        << a.valid_until;
}

//int main() {
//    certificateAuthority* a = new certificateAuthority("a", 1, "someSignature", "someLocation", 1, 123, 321);
//
//    std::cout << "printing a.cert ";
//
//    printcert(a->get_cert());
//
//    x509 temp = a->issue_cert({345, 543});
//
//    printcert(temp);
//
//    return 0;
//}
