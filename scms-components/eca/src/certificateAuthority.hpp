/*
 * certificateAuthority.hpp
 *
 *  Created on: Mar. 31, 2024
 *      Author: Muaadh Ali
 */
#ifndef CERTIFICATEAUTHORITY_HPP
#define CERTIFICATEAUTHORITY_HPP

#include <stdlib.h>
#include <string>
#include <memory>
#include <random>
#include <unordered_set>
#include <time.h>
#include "../../../include/crypto-defs.h"



class certificateAuthority {
    public:
        certificateAuthority(std::string,std::string);
        ~certificateAuthority();
        std::string getName();
        void issue_cert(x509*);
        x509* get_cert();
        std::string name; 
    protected:
        x509 cert;
        RSA* key_pair;
};

class rootCertificateAuthority : public certificateAuthority {
    public:
		rootCertificateAuthority(std::string,std::string);
        void self_sign();
};

class enrollmentCertificateAuthority : public certificateAuthority {
    public:
        enrollmentCertificateAuthority(std::string,std::string);
        bool enroll_device(x509*);
};

class pseudonymCertificateAuthority : public certificateAuthority {
    public:
        pseudonymCertificateAuthority(std::string,std::string);
};

#endif

