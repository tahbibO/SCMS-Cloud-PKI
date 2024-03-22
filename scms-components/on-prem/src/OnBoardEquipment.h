/*
 * OnBoardEquipment.h
 *
 *  Created on: Mar. 22, 2024
 *      Author: Jordan Bayne
 */

#include <iostream>
#include <map>
#include <vector>
using namespace std;

#ifndef SRC_ONBOARDEQUIPMENT_H_
#define SRC_ONBOARDEQUIPMENT_H_

class OnBoardEquipment {

public:
	OnBoardEquipment(string);
	virtual ~OnBoardEquipment();
	int sendMessage(string, string);
	int receiveMessage(string, string);

private:
	struct network {
		string ip;
		int port;
	};

	string ID;
	map<string, network> addressMap;
	map<string, int> certificateMap; // Need to change value to x509 type
	map<string, int> keyPairMap; // Need to change value to key object
	vector<int> pseudonymCerts; // Need to change type to x509 type
	vector<int> pseudonymKeyPairs; // Need to change type to key objects
};

#endif /* SRC_ONBOARDEQUIPMENT_H_ */
