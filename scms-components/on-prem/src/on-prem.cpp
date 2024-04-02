#include <iostream>
using namespace std;

#include "OnBoardEquipment.h"
#include "DeviceConfigurationManager.h"

int main() {
	std::vector<std::tuple<std::string, std::string, int>> temp;

	temp.push_back({"PCA", "8.8.8.8", 69});
	temp.push_back({"ECA", "7.7.7.7", 23});
	DeviceConfigurationManager *dcm = new DeviceConfigurationManager(&ROOT_CERT, temp);
	dcm->createOBE();

	return 0;
}
