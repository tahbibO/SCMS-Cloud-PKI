#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <sys/types.h>
#include <arpa/inet.h>
#include <chrono>

#include "../../../include/server.h"
#include "../../../include/networking-defs.h"
#include "../../../include/crypto-defs.h"
#include "../../../scms-components/cloud/src/certificateAuthority.hpp"




// TODO: unit tests
// TODO: example code




int main()
{

    Server server = Server(3000, true);

    // Add routes and corresponding route handler functions
    server.addRoute("/", [](const Message &request, Message &response, int clientSocket, Server *in_server, certificateAuthority * in_ca ){
		// Send response
		response.setHeaders(200,"",3000,"/","","text/plain");
		response.setData("Hello from server");
		in_server->sendMessage(response, clientSocket);

		std::cout << "send data!" << std::endl;
    });

    server.addRoute("/cert", [](const Message &request, Message &response, int clientSocket, Server *in_server, certificateAuthority * in_ca){
		// Send response
		response.setHeaders(200,"",3000,"/","certificate");
		RSA* key = generateRSAKeyPair();
		std::string stringKey = publicKeyToString(RSAPublicKey_dup(key));
		x509 newCert("new Cert", stringKey, "","CA", "", 500, 5+ 10);
		signCertificate(&newCert,ROOT_KEY,&ROOT_CERT);
		response.setData(newCert.toString());

		//std::cout << "cert:		" << newCert.toString() << std::endl;
		//std::cout << "size of cert:	" << newCert.toString().length() << std::endl;

		in_server->sendMessage(response, clientSocket);

		std::cout << "send data!" << std::endl;
    });

    server.startServer();


    return 0;
}
