#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <sys/types.h>
#include <arpa/inet.h>

#include "../../../include/client.h"
#include "../../../include/networking-defs.h"
#include "../../../include/crypto-defs.h"


using namespace std;

int main() {
	/*
    std::string data = "Hello World";
    std::string address = "192.168.152.133"; // replace with your address
    int send_port = 30;                     // replace with your port
    int receive_port = 30;


    sendData(data, address, send_port);

*/

	Client client = Client(true);

	cout << "Client!!!" << endl; // prints Hello World!!!
	Message request;
	Message response;
	cout << "created response and request!!!" << endl; // prints Hello World!!!
	std::string ip_address = "54.165.85.13";
	int port= 3000;
	request.setHeaders(0,ip_address,port,"/cert","certificate");
	cout << "set headers!!!" << endl; // prints Hello World!!!

	request.setData("Hello from Client");
	cout << "set data!!!" << endl; // prints Hello World!!!

	client.sendMessage(request,response,ip_address.c_str(),port);

	cout << "Sent Data!!!" << endl; // prints Hello World!!!
	if (std::string(response.dataType) == "certificate"){

		std::cout << "string response: " << std::string(response.data) << std::endl;
		x509 tempCert;
		tempCert.fromString(std::string(response.data));
		std::cout << "Cert Name:	" << tempCert.name << std::endl;
		std::cout << "Cert Public Key:	" << tempCert.public_key << std::endl;
		std::cout << "Cert Signature:	" << tempCert.signature<< std::endl;
		std::cout << "Cert Location:	" << tempCert.location << std::endl;
		std::cout << "Cert Issuer:	" << tempCert.issuer << std::endl;
		std::cout << "Cert Issue Date:	" << tempCert.issue_date << std::endl;
		std::cout << "Cert Valid Until:	" << tempCert.valid_until << std::endl;

	}


/* getting mutiple certs does not work reliably
	Message requestTwo, responseTwo;
	requestTwo.setHeaders(0,"192.168.152.133",30,"/certArr","certificates");
	requestTwo.setData("Hello from Client");
	client.sendMessage(requestTwo,responseTwo,"192.168.152.133",30);

		if (std::string(responseTwo.dataType) == "certificates" || responseTwo.status == 200){
		std::cout << "string arr size :	" << responseTwo.dataSize << std::endl;
		std::cout << "string arr:	" << std::string(responseTwo.data) << std::endl;
		std::string *certArrayTwo = stringToArray(responseTwo.data,3);
		for(int i = 0;i<3;i++){
			x509 tempX509;
			//std::cout << certArrayTwo[i] << std::endl << std::endl;
			tempX509.fromString(certArrayTwo[i]);
			std::cout << "cert entry " << i+1 << " name:	" << tempX509.name << std::endl;
			std::cout << "cert entry " << i+1 << " key:	" << tempX509.public_key << std::endl;
			std::cout << "cert entry " << i+1 << " signature:	" << tempX509.signature << std::endl;
			std::cout << "cert entry " << i+1 << " location:	" << tempX509.location << std::endl;
			std::cout << "cert entry " << i+1 << " issuer:	" << tempX509.issuer << std::endl;
			std::cout << "cert entry " << i+1 << " issue_date:	" << tempX509.issue_date << std::endl;
			std::cout << "cert entry " << i+1 << " valid until:	" << tempX509.valid_until<< std::endl;
			std::cout << std::endl << std::endl;

		}


	}
			*/



	return 0;
}
