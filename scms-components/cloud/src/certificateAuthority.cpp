#include "certificateAuthority.hpp"

#include <iostream>

certificateAuthority::certificateAuthority{
    *key_pair = generateRSAKeyPair();    
}

certificateAuthority::~certificateAuthority() {
    delete key_pair;
}

x509 certificateAuthority::get_cert() {
    return cert;
}

x509 certificateAuthority::issue_cert(std::tuple<int, int> key_p) {
    //Do
}

bool rootCertificateAuthority::self_sign() {

    cert = generateRootCert(RSAPublicKey_dup(key_pair));

    return cert != NULL;
}

enrollmentCertificateAuthority::enrollmentCertificateAuthority(x509* root) : certificateAuthority() {
    long int t = static_cast<long int> (time(NULL));
    std::string name = typeid(this);
    std::string location = typeid(this) + " Location";
    long issue_date = t;
    long valid_until = t + 604800;

    cert = x509(name, RSAPublicKey_dup(key_pair), "", location, root, issue_date, valid_until);

}

bool enrollmentCertificateAuthority::enroll_device(x509 *certificate) {
    if (signCertificate(certificate, key_pair, &cert))
    {
        return true;
    }

    return false;
    
}

pseudonymCertificateAuthority::pseudonymCertificateAuthority(x509* root) : certificateAuthority() {
    long int t = static_cast<long int> (time(NULL));
    std::string name = typeid(this);
    std::string location = typeid(this) + " Location";
    long issue_date = t;
    long valid_until = t + 604800;

    cert = x509(name, RSAPublicKey_dup(key_pair), "", location, root, issue_date, valid_until);

}

void printcert(x509 a) {
    std::cout << "printing a.cert" << a.public_key << " " 
        << a.signature << " " 
        << a.location << " " 
        << a.issuer<< " " 
        << a.issue_date<< " " 
        << a.valid_until;
}

int main() {
    certificateAuthority* a = new certificateAuthority("a", 1, "someSignature", "someLocation", 1, 123, 321);

    std::cout << "printing a.cert ";

    printcert(a->get_cert());
    
    x509 temp = a->issue_cert({345, 543});

    printcert(temp);

    return 0;
}