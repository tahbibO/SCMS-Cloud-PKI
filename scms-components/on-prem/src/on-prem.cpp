#include <iostream>
using namespace std;

#include "OnBoardEquipment.h"
#include "DeviceConfigurationManager.h"

//TODO: create functions to ask for PCA
//TODO: create functions to ask for ECA
//TODO: create function to ask for Certificates
//TODO: DCM should load PEM file
//TODO: free maps

int main() {
	std::vector<std::tuple<std::string, std::string, int>> temp;

	temp.push_back({"PCA", "192.168.152.133", 3000}); //vm2
	temp.push_back({"ECA", "192.168.152.134", 3000}); //vm3
	DeviceConfigurationManager *dcm = new DeviceConfigurationManager(&ROOT_CERT, temp);
	OnBoardEquipment* obe =  dcm->createOBE();
	bool val = obe->getEnrollmentCertificate();
	std::cout << "OBE Enrollment: " << val << std::endl;
	val = obe->getPseudonymCertificates();
	std::cout << "OBE Pseudonym Certificate Provisoning: " << val << std::endl;
	return 0;
}
