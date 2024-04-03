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

	std::cout << "Cert:	" << ECA->get_cert()->toString() << std::endl;


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

int main() {

	ECAServer();
	//PCAServer();

	return 0;
}



