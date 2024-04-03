#include <iostream>
#include "certificateAuthority.hpp"
#include "../../../include/networking-defs.h"
#include "../../../include/server.h"
#include "../../../include/crypto-defs.h"


using namespace std;

void ECAServer() {
	rootCertificateAuthority* RCA = new rootCertificateAuthority("Root","CA");
	enrollmentCertificateAuthority* ECA = new enrollmentCertificateAuthority("ECA","CA");

	RCA->self_sign();
	RCA->issue_cert(ECA->get_cert());



	int port = 3000;
	Server server = Server(port, true, ECA);

	server.addRoute("/certificate", [](const Message &request, Message &response, int clientSocket, Server *in_server, certificateAuthority *ca){
		// Send response
    	if (std::string(request.method) =="get"){
			response.setHeaders(200,"",in_server->getPort(),"","","certificate");
			response.setData(ca->get_cert()->toString());
			x509 temp;
			temp.fromString(std::string(response.data));
			in_server->sendMessage(response, clientSocket);
    	}
	});

	server.addRoute("/signCertificate", [](const Message &request, Message &response, int clientSocket, Server *in_server, certificateAuthority *ca){
		// Send response
		if (std::string(request.method) == "get"){
			response.setHeaders(200,"",in_server->getPort(),"","","signCertificate");
			x509 tempC;
			tempC.fromString(std::string(request.data));
			ca->issue_cert(&tempC);
			response.setData(tempC.toString());
			in_server->sendMessage(response, clientSocket);
		}

	});

	cout << "Hello from " << ECA->getName() <<endl; // prints Hello World!!!
	server.startServer();

	delete RCA;
	delete ECA;
}

void PCAServer() {
	rootCertificateAuthority* RCA = new rootCertificateAuthority("Root","CA");
	pseudonymCertificateAuthority* PCA = new pseudonymCertificateAuthority("PCA","CA");

	RCA->self_sign();
	RCA->issue_cert(PCA->get_cert());


	Server server = Server(3000, true, PCA);

	server.addRoute("/certificate", [](const Message &request, Message &response, int clientSocket, Server *in_server, certificateAuthority *ca){
		// Send response
		if (std::string(request.method) =="get"){
			response.setHeaders(200,"",3000,"","","certificate");
			response.setData(ca->get_cert()->toString());
			in_server->sendMessage(response, clientSocket);
			std::cout << "sent data!" << std::endl;
		}

	});

	server.addRoute("/signCertificate", [](const Message &request, Message &response, int clientSocket, Server *in_server, certificateAuthority *ca){
		// Send response
		response.setHeaders(200,"",3000,"","","signCertificate");
		x509 tempC;
		tempC.fromString(std::string(request.data));
		ca->issue_cert(&tempC);
		response.setData(tempC.toString());
		in_server->sendMessage(response, clientSocket);
		std::cout << "sent data!" << std::endl;
	});

	cout << "Hello from " << PCA->getName() <<endl; // prints Hello World!!!
	server.startServer();

	delete RCA;
	delete PCA;
}

int main() {

	//ECAServer();
	PCAServer();

	return 0;
}



