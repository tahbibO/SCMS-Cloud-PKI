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

#ifndef SRC_ONBOARDEQUIPMENT_H_
#define SRC_ONBOARDEQUIPMENT_H_

class OnBoardEquipment {

public:
	OnBoardEquipment(x509*, std::vector<std::tuple<std::string, std::string, int>>);
	virtual ~OnBoardEquipment();
	int getEnrollment();
	int getPseudonymCertificate();
	static int ID;

private:
	struct Network {
		std::string ip;
		int port;
	};

	int id;
	std::map<std::string, Network> addressMap;
	std::map<std::string, x509*> certificateMap; // Need to change value to x509 type
	std::map<std::string, RSA*> keyPairMap; // Need to change value to key object
	std::vector<x509*> pseudonymCerts; // Need to change type to x509 type
	std::vector<RSA*> pseudonymKeyPairs; // Need to change type to key objects
};

#endif /* SRC_ONBOARDEQUIPMENT_H_ */
