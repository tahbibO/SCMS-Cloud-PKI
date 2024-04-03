/*
 * OnBoardEquipment.cpp
 *
 *  Created on: Mar. 22, 2024
 *      Author: Jordan Bayne
 */

#include "OnBoardEquipment.h"
int OnBoardEquipment::ID = 0;
OnBoardEquipment::OnBoardEquipment(x509* cert, std::vector<std::tuple<std::string, std::string, int>> CAs, bool should_log) {
	for(int i = 0; i < CAs.size(); i++){
		Network network = {std::get<1>(CAs.at(i)), std::get<2>(CAs.at(i))};
		addressMap[std::get<0>(CAs.at(i))] = network;

	}
	id = ++ID;
	certificateMap[cert->name] = cert;
	caPubKeyPairMap[cert->name] = stringToPublicKey(cert->public_key);

	client = new Client(false);

//		for (const auto& pair : addressMap) {
//			std::cout << "Key: " << pair.first << ", Value: " << pair.second.ip << std::endl;
//		}
	enrollmentCert = new x509();
	this->logging = should_log;
}

OnBoardEquipment::~OnBoardEquipment() {

//	for (const auto& pair : myMap) {
//		RSA_free(pair.second);
//		std::cout << "Key: " << pair.first << ", Value: " << pair.second << std::endl;
//	}
	std::cout << "OnBoardEquipment Destructor" << std::endl;
}


void OnBoardEquipment::addCACertificate(x509* cert){
	certificateMap[cert->name] = cert;
}

bool OnBoardEquipment::getEnrollmentCertificate(){

	//eca info
	std::string eca_ip = addressMap["ECA"].ip;
	int eca_port = addressMap["ECA"].port;

	/// request, response to get eca certificate
	Message eca_cert_request, eca_cert_response;
	eca_cert_request.setHeaders(0,eca_ip,eca_port,"/certificate","get","text/plain");

	client->sendMessage(eca_cert_request,eca_cert_response,eca_ip.c_str(),eca_port);

	if (eca_cert_response.status !=200){
		return false;
	}

	x509 temp_eca_cert;
	temp_eca_cert.fromString(std::string(eca_cert_response.data));

	//verify certificate
	if (!verifyCertificate(&temp_eca_cert,caPubKeyPairMap,certificateMap)){
		return false;
	}



	// request, response to get eca to sign certificate
	RSA* temp_enrollment_key = generateRSAKeyPair();
	x509 temp_enrollment_cert(std::to_string(id),publicKeyToString(RSAPublicKey_dup(temp_enrollment_key)),"","CA","",time(nullptr),time(nullptr));
	Message eca_sign_request, eca_sign_response;
	eca_sign_request.setHeaders(0,eca_ip,eca_port,"/signCertificate","get","text/plain");
	eca_sign_request.setData(temp_enrollment_cert.toString());
	client->sendMessage(eca_sign_request,eca_sign_response,eca_ip.c_str(),eca_port);
	if (eca_sign_response.status != 200){
		RSA_free(temp_enrollment_key);
		return false;
	}

	//updating OBE model
	enrollmentCert->fromString(std::string(eca_sign_response.data));

	certificateMap[temp_eca_cert.name] = &temp_eca_cert;
	caPubKeyPairMap[temp_eca_cert.name] = stringToPublicKey(temp_eca_cert.public_key);

	return true;
}

bool OnBoardEquipment::getPseudonymCertificates(){
	//pca server info
	std::string pca_ip = addressMap["PCA"].ip;
	int pca_port = addressMap["PCA"].port;

	//get pca cert
	Message pca_cert_request, pca_cert_response;
	pca_cert_request.setHeaders(0,pca_ip,pca_port,"/certificate","get","text/plain");

	client->sendMessage(pca_cert_request,pca_cert_response,pca_ip.c_str(),pca_port);

	if (pca_cert_response.status !=200){
		return false;
	}

	x509 temp_pca_cert;
	temp_pca_cert.fromString(std::string(pca_cert_response.data));


	//verify certificate
	if (!verifyCertificate(&temp_pca_cert,caPubKeyPairMap,certificateMap)){
		return false;
	}

	//request for 20 certs
	std::vector<x509*> temp_certs;
	std::vector<RSA*> temp_keys;

	for(int i = 0; i < 20; i++){
		RSA* temp_key = generateRSAKeyPair();
		x509* temp_cert= new x509(std::to_string(id),publicKeyToString(RSAPublicKey_dup(temp_key)),"","CA","",time(nullptr),time(nullptr));
		Message pca_sign_request, pca_sign_response;
		pca_sign_request.setHeaders(0,pca_ip,pca_port,"/signCertificate","get","text/plain");
		pca_sign_request.setData(temp_cert->toString());
		client->sendMessage(pca_sign_request,pca_sign_response,pca_ip.c_str(),pca_port);
		if (pca_sign_response.status != 200){
			RSA_free(temp_key);
			//free keys
			temp_keys.clear();
			//free certs
			temp_certs.clear();
			return false;
		}
		temp_certs.push_back(temp_cert);
		temp_keys.push_back(temp_key);
	}


	certificateMap[temp_pca_cert.name] = &temp_pca_cert;
	caPubKeyPairMap[temp_pca_cert.name] = stringToPublicKey(temp_pca_cert.public_key);

	pseudonymKeyPairs.resize(temp_keys.size());
    std::copy(temp_keys.begin(), temp_keys.end(), pseudonymKeyPairs.begin());

	pseudonymCerts.resize(temp_certs.size());
    std::copy(temp_certs.begin(), temp_certs.end(), pseudonymCerts.begin());

    return true;

}

void OnBoardEquipment::log(std::string msg){
	if(logging){
		std::cout << msg << std::endl;
	}
}

