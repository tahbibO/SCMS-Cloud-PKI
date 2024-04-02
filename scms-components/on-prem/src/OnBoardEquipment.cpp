/*
 * OnBoardEquipment.cpp
 *
 *  Created on: Mar. 22, 2024
 *      Author: Jordan Bayne
 */

#include "OnBoardEquipment.h"
int OnBoardEquipment::ID = 0;
OnBoardEquipment::OnBoardEquipment(x509* cert, std::vector<std::tuple<std::string, std::string, int>> CAs) {
	for(int i = 0; i < CAs.size(); i++){
		Network network = {std::get<1>(CAs.at(i)), std::get<2>(CAs.at(i))};
		addressMap[std::get<0>(CAs.at(i))] = network;

	}
	id = ++ID;
	certificateMap["root"] = cert;
	RSA* pubKey = stringToPublicKey(cert.public_key);

//		for (const auto& pair : addressMap) {
//			std::cout << "Key: " << pair.first << ", Value: " << pair.second.ip << std::endl;
//		}
}

OnBoardEquipment::~OnBoardEquipment() {

//	for (const auto& pair : myMap) {
//		RSA_free(pair.second);
//		std::cout << "Key: " << pair.first << ", Value: " << pair.second << std::endl;
//	}
	std::cout << "OnBoardEquipment Destructor" << std::endl;
}
