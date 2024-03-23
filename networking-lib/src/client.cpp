#include "Client.h"
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include "defs.h"
#include <arpa/inet.h>


Client::Client() : sockfd(-1)
{
}

Client::~Client()
{
    // Close socket
    close(sockfd);
}

bool Client::sendMessage(const Message &request, Message &response, const char *serverIp, int serverPort)
{
    // Create a socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        std::cerr << "Error creating socket\n";
        return false;
    }

    // Set the server address
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);

    if (inet_pton(AF_INET, serverIp, &serverAddr.sin_addr) <= 0)
    {
        std::cerr << "Invalid address/ Address not supported \n";
        return false;
    }

    // Connect to the server

    if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
        std::cerr << "Error connecting to server\n";
        return false;
    }

    // Send the request message
    char buffer[4096];
    memcpy(buffer, &request, sizeof(buffer));
    if (send(sockfd, &buffer, sizeof(buffer), 0) == -1) {
        std::cerr << "Error sending request\n";
        close(sockfd);
        return false;
    }

    // Receive the response
    char response_buffer[4096];
    int bytesRead = recv(sockfd, &response_buffer, sizeof(response_buffer), 0);
    std::cout << "receiving data" << std::endl;
    if (bytesRead == -1)
    {
        std::cerr << "Error receiving response\n";
        close(sockfd);
        return false;
    }

    // Process the response
	memcpy(&response, response_buffer, bytesRead);
	std::cout << "Received: " << std::string(response_buffer, sizeof(response_buffer)) << std::endl;
	char deserializedText[sizeof(response.data) + 1];
	memcpy(deserializedText, response.data, sizeof(response.data));
	deserializedText[sizeof(response.data)] = '\0';
	std::cout << "Received Data " << deserializedText << std::endl;





    // Close socket
    close(sockfd);

    return true;
}

// how to send data
