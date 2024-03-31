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



// TODO: unit tests
// TODO: example code




int main()
{

    Server server = Server(30, true);

    // Add routes and corresponding route handler functions
    server.addRoute("/", [](const Message &request, Message &response, int clientSocket, Server *in_server){
		// Send response
		response.setHeaders(200,"",30,"/","text/plain");
		response.setData("Hello from server");
		in_server->sendMessage(response, clientSocket);

		std::cout << "send data!" << std::endl;
    });

    server.addRoute("/cert", [](const Message &request, Message &response, int clientSocket, Server *in_server){
		// Send response
		response.setHeaders(200,"",30,"/","certificate");
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

/*	getting multiple certs does not work reliably
    server.addRoute("/certArr", [](const Message &request, Message &response, int clientSocket, Server *in_server){

    	RSA *keyPairOne = generateRSAKeyPair();
    	RSA *keyPairTwo = generateRSAKeyPair();
    	RSA *keyPairThree = generateRSAKeyPair();

    	RSA *pubKeyOne = RSAPublicKey_dup(keyPairOne);
    	RSA *pubKeyTwo = RSAPublicKey_dup(keyPairTwo);
    	RSA *pubKeyThree = RSAPublicKey_dup(keyPairThree);

    	x509 certOne("One", publicKeyToString(pubKeyOne), "", "CA", "", time(nullptr) * 1000, time(nullptr) * 1000 + +YEAR_IN_MS);
    	x509 certTwo("Two", publicKeyToString(pubKeyTwo), "", "CA", "", time(nullptr) * 1000, time(nullptr) * 1000 + +YEAR_IN_MS);
    	x509 certThree("Three", publicKeyToString(pubKeyThree), "", "CA", "", time(nullptr) * 1000, time(nullptr) * 1000 + +YEAR_IN_MS);

    	signCertificate(&certOne, ROOT_KEY, &ROOT_CERT);
    	signCertificate(&certTwo, ROOT_KEY, &ROOT_CERT);
    	signCertificate(&certThree, ROOT_KEY, &ROOT_CERT);

    	std::string *certArray = new std::string[3];
    	certArray[0] = certOne.toString();
    	certArray[1] = certTwo.toString();
    	certArray[2] = certThree.toString();

    	std::string stringCertArr= arrayToString(certArray, 3);
		std::cout << "------------------stringCertArr------------------" << std::endl << stringCertArr << std::endl;


    	response.setHeaders(200,"",30,"/","certificates");
    	response.setData(stringCertArr);
		std::cout << "------------------ResponseData------------------" << std::endl << std::string(response.data) << std::endl;

    	in_server->sendMessage(response, clientSocket);

		std::cout << "send data!" << std::endl;
    });
    */

    server.startServer();


    return 0;
}
