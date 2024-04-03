/*
 * DeviceConfigurationManager.cpp
 *
 *  Created on: Apr. 1, 2024
 *      Author: Jordan Bayne
 */

#include "DeviceConfigurationManager.h"

DeviceConfigurationManager::DeviceConfigurationManager(x509* cert, std::vector<std::tuple<std::string, std::string, int>> CAs) {
	// TODO Auto-generated constructor stub
	rootCert = cert;
	this->CAs = CAs;
}

DeviceConfigurationManager::~DeviceConfigurationManager() {
	// TODO Auto-generated destructor stub
}

OnBoardEquipment* DeviceConfigurationManager::createOBE(){
	OnBoardEquipment *obe = new OnBoardEquipment(rootCert, CAs,true);
	return obe;
}
