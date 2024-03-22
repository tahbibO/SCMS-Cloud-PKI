#include <iostream>
using namespace std;

#include "OnBoardEquipment.h"

int main() {
	OnBoardEquipment onBoardEquipment("1");
	onBoardEquipment.sendMessage("testIn1", "testIn2");
	onBoardEquipment.receiveMessage("testOut1", "testOut2");
	cout << "Hello World!!!" << endl; // prints Hello World!!!
	return 0;
}
