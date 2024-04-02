/*
 * DeviceConfigurationManager.h
 *
 *  Created on: Apr. 1, 2024
 *      Author: Jordan Bayne
 */

#include <map>
#include <vector>
#include "../../../include/crypto-defs.h"
#include "OnBoardEquipment.h"

#ifndef SRC_DEVICECONFIGURATIONMANAGER_H_
#define SRC_DEVICECONFIGURATIONMANAGER_H_

class DeviceConfigurationManager {
public:
	DeviceConfigurationManager(x509*, std::vector<std::tuple<std::string, std::string, int>>);
	virtual ~DeviceConfigurationManager();
	OnBoardEquipment* createOBE();

private:
	std::map<std::string, std::string> entityMap;
	std::map<std::string, x509> certificateMap;
	std::vector<std::tuple<std::string, std::string, int>> CAs;
	x509* rootCert;
	std::vector<OnBoardEquipment> *obes;
};

#endif /* SRC_DEVICECONFIGURATIONMANAGER_H_ */
