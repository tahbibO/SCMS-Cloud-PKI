#include "certificateAuthority.hpp"

#include <iostream>

certificateAuthority::certificateAuthority(std::string name, int public_key, std::string signature, std::string location, int issuer, long issue_date, long valid_until) : name(name), cert{public_key, signature, location, &issuer, issue_date, valid_until} {
    srand(time(NULL));
    int rand = std::rand() % 1000;

    while (keys.find(rand*public_key) != keys.end())
    {
        rand = std::rand() % 1000;
    }

    keys.insert(rand*public_key);

    key_pair = {public_key, rand*public_key};

}

x509 certificateAuthority::get_cert() {
    return cert;
}

x509 certificateAuthority::issue_cert(std::tuple<int, int> key_p) {
    int a = std::get<0>(key_p);
    int b = std::get<1>(key_p);

    // srand(time(NULL));
    // int rand = std::rand() % 1000;

    // while (keys.find(rand*a) != keys.end())
    // {
    //     rand = std::rand() % 1000;
    // }

    x509 temp_cert = {
        a,
        "someSignature",
        "someLocation",
        &cert.public_key,
        123,
        321
    };

    return temp_cert;
}

rootCertificateAuthority::rootCertificateAuthority() {

}

bool rootCertificateAuthority::self_sign() {
    srand(time(NULL));
    int rand = std::rand() % 1000;

    while (keys.find(rand) != keys.end())
    {
        rand = std::rand() % 1000;
    }

    keys.insert(rand);

    cert = {
        rand,
        "someSignature",
        "someLocation",
        &rand,
        123,
        321
    };

    return true;
}

x509 enrollmentCertificateAuthority::enroll_device() {
    srand(time(NULL));
    int rand = std::rand() % 1000;

    while (keys.find(rand) != keys.end())
    {
        rand = std::rand() % 1000;
    }

    keys.insert(rand);

    x509 temp_cert = {
        rand,
        "someSignature",
        "someLocation",
        &cert.public_key,
        123,
        321
    };

    return temp_cert;
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