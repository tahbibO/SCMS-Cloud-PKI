/*
 * OnBoardEquipment.cpp
 *
 *  Created on: Mar. 22, 2024
 *      Author: Jordan Bayne
 */

#include "OnBoardEquipment.h"

OnBoardEquipment::OnBoardEquipment(string ID) {
	this->ID = ID;
	// TODO Auto-generated constructor stub
	cout << "OnBoardEquipment Constructor " << this->ID << endl;
}

OnBoardEquipment::~OnBoardEquipment() {
	// TODO Auto-generated destructor stub
	cout << "OnBoardEquipment Destructor" << endl;
}

int OnBoardEquipment::sendMessage(string inMessage, string inHeader){
	cout << "Send message " << inMessage << " " << inHeader << endl;
	return 0;
}

int OnBoardEquipment::receiveMessage(string outMessage, string outHeader){
	cout << "Receive message " << outMessage << " " << outHeader << endl;
	return 0;
}
