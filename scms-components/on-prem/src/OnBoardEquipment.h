/*
 * OnBoardEquipment.h
 *
 *  Created on: Mar. 22, 2024
 *      Author: Jordan Bayne
 */

#include <iostream>
#include <map>
#include <vector>
#include "../../../include/crypto-defs.h"
#include "../../../include/client.h"
#include "../../../include/networking-defs.h"

#ifndef SRC_ONBOARDEQUIPMENT_H_
#define SRC_ONBOARDEQUIPMENT_H_

class OnBoardEquipment {

public:
	OnBoardEquipment(x509*, std::vector<std::tuple<std::string, std::string, int>>, bool);
	virtual ~OnBoardEquipment();

	bool getEnrollmentCertificate(); // add ECA cert to OBE
	bool getPseudonymCertificates(); // add PCA to OBE vector
	void addCACertificate(x509*); // add CA certs to OBE certificate Map
	static int ID;

private:
	struct Network {
		std::string ip;
		int port;
	};

	void log(std::string);

	int id;
	std::map<std::string, Network> addressMap;
	std::map<std::string, x509*> certificateMap;
	std::map<std::string, RSA*> caPubKeyPairMap;
	std::map<std::string, RSA*> keyPairMap;
	x509* enrollmentCert;
	std::vector<x509*> pseudonymCerts;
	std::vector<RSA*> pseudonymKeyPairs;
	Client* client;
	bool logging;

};

#endif /* SRC_ONBOARDEQUIPMENT_H_ */
