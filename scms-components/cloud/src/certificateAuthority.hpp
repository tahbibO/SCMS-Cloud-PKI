#ifndef CERTIFICATEAUTHORITY_HPP
#define CERTIFICATEAUTHORITY_HPP

#include <stdlib.h>
#include <string>
#include <memory>
#include <random>
#include <unordered_set>
#include <time.h>


static std::unordered_set<int> keys;

struct x509 {
	int public_key; // keypairs are EC_KEY, while private is BIGNUM and public is EC_POINT.
	std::string signature; // stored in DER format
	std::string location;
	int *issuer; // public key of the issuer
	long issue_date;
	long valid_until;
};

class certificateAuthority {
    public:
        certificateAuthority(std::string, int, std::string, std::string, int, long, long);
        ~certificateAuthority();
        x509 issue_cert(std::tuple<int, int>);
        x509 get_cert();
        std::string name; 
    protected:
        x509 cert;
        std::tuple<int, int> key_pair;
};

class rootCertificateAuthority : public certificateAuthority {
    public:
        bool self_sign();
};

class enrollmentCertificateAuthority : public certificateAuthority {
    public:
        x509 enroll_device();
};

class pseudonymCertificateAuthority : public certificateAuthority {
};

#endif