#include <iostream>
#include "certificateAuthority.hpp"
#include "../../../include/networking-defs.h"
#include "../../../include/server.h"
#include "../../../include/crypto-defs.h"


using namespace std;

void ECAServer() {
	rootCertificateAuthority* RCA = new rootCertificateAuthority;
	enrollmentCertificateAuthority* ECA = new enrollmentCertificateAuthority();

	RCA->self_sign();
	RCA->issue_cert(ECA->get_cert());


	Server server = Server(3000, true, ECA);

		    server.addRoute("/getCertificate", [](const Message &request, Message &response, int clientSocket, Server *in_server, certificateAuthority *ca){
				// Send response
				response.setHeaders(200,"",3000,"/","getCertificate");
				response.setData(ca->get_cert()->toString());
				in_server->sendMessage(response, clientSocket);
				std::cout << "send data!" << std::endl;
		    });

		    server.addRoute("/signCertificate", [](const Message &request, Message &response, int clientSocket, Server *in_server, certificateAuthority *ca){
		    				// Send response
		    				response.setHeaders(200,"",3000,"/","getCertificate");
		    				x509 tempC;
		    				tempC.fromString(std::string(request.data));
		    				ca->issue_cert(&tempC);
		    				response.setData(tempC.toString());
		    				in_server->sendMessage(response, clientSocket);
		    				std::cout << "send data!" << std::endl;
		    		    });


	server.startServer();

	delete RCA;
	delete ECA;
}

void PCAServer() {
	rootCertificateAuthority* RCA = new rootCertificateAuthority;
	pseudonymCertificateAuthority* PCA = new pseudonymCertificateAuthority();

	RCA->self_sign();
	RCA->issue_cert(PCA->get_cert());


	Server server = Server(3000, true, PCA);

		    server.addRoute("/getCertificate", [](const Message &request, Message &response, int clientSocket, Server *in_server, certificateAuthority *ca){
				// Send response
				response.setHeaders(200,"",3000,"/","getCertificate");
				response.setData(ca->get_cert()->toString());
				in_server->sendMessage(response, clientSocket);
				std::cout << "send data!" << std::endl;
		    });

		    server.addRoute("/signCertificate", [](const Message &request, Message &response, int clientSocket, Server *in_server, certificateAuthority *ca){
		    				// Send response
		    				response.setHeaders(200,"",3000,"/","getCertificate");
		    				x509 tempC;
		    				tempC.fromString(std::string(request.data));
		    				ca->issue_cert(&tempC);
		    				response.setData(tempC.toString());
		    				in_server->sendMessage(response, clientSocket);
		    				std::cout << "send data!" << std::endl;
		    		    });


	server.startServer();

	delete RCA;
	delete PCA;
}

int main() {
	cout << "Hello World from the cloud!!!" << endl; // prints Hello World!!!

	ECAServer();
	PCAServer();

	return 0;
}



