#ifndef CERTIFICATEAUTHORITY_HPP
#define CERTIFICATEAUTHORITY_HPP

#include <stdlib.h>
#include <string>
#include <memory>
#include <random>
#include <unordered_set>
#include <time.h>
#include "../../../crypto-lib/src/defs.h"



class certificateAuthority {
    public:
        certificateAuthority();
        ~certificateAuthority();
        x509 issue_cert(std::tuple<int, int>);
        x509 get_cert();
        std::string name; 
    protected:
        x509 cert;
        RSA* key_pair;
};

class rootCertificateAuthority : public certificateAuthority {
    public:
        bool self_sign();
};

class enrollmentCertificateAuthority : public certificateAuthority {
    public:
        enrollmentCertificateAuthority(x509*);
        x509 enroll_device(x509*);
};

class pseudonymCertificateAuthority : public certificateAuthority {
    public:
        pseudonymCertificateAuthority(x509*);
};

#endif