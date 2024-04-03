#include <iostream>
#include "certificateAuthority.hpp"
#include "../../../include/networking-defs.h"
#include "../../../include/server.h"
#include "../../../include/crypto-defs.h"


using namespace std;


void PCAServer() {
	rootCertificateAuthority* RCA = new rootCertificateAuthority("Root","CA");
	pseudonymCertificateAuthority* PCA = new pseudonymCertificateAuthority("PCA","CA");

	RCA->self_sign();
	RCA->issue_cert(PCA->get_cert());

	std::cout << "Cert:	" << PCA->get_cert()->toString() << std::endl;


	Server server = Server(3000, true, PCA);

	server.addRoute("/certificate", [](const Message &request, Message &response, int clientSocket, Server *in_server, certificateAuthority *ca){
		// Send response
		if (std::string(request.method) =="get"){
			response.setHeaders(200,"",3000,"","","certificate");
			std::cout << "PCA Cert:	" << ca->get_cert()->toString() << std::endl;
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
	PCAServer();

	return 0;
}
