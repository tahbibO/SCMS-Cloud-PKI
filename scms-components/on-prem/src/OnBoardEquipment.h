/*
 * OnBoardEquipment.h
 *
 *  Created on: Mar. 22, 2024
 *      Author: Jordan Bayne
 */

#include <iostream>
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
	string ID;
};

#endif /* SRC_ONBOARDEQUIPMENT_H_ */
