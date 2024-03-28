#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include "message.h"

class Client
{
private:
    int sockfd;
    bool logging;
    void Client::log(std::string message)
    {
        if (logging)
        {
            std::cout << message << std::endl;
        }
    }

public:
    Client::Client(bool logging = false) : sockfd(-1), logging(logging)
    {
        log("Creating Client");
    }

    Client::~Client()
    {
        // Close socket
        log("Destroying Client");
        close(sockfd);
    }

    bool sendMessage(const Message &request, Message &response, const char *serverIp, int serverPort)
    {
        // Create a socket
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
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
        char buffer[sizeof(Message)];
        memcpy(buffer, &request, sizeof(buffer));

        if (send(sockfd, &buffer, sizeof(buffer), 0) == -1)
        {
            std::cerr << "Error sending request\n";
            close(sockfd);
            return false;
        }

        // Receive the response
        char response_buffer[sizeof(Message)];
        char bytesRead = recv(sockfd, &response_buffer, sizeof(response_buffer), 0);
        log("Received " + std::to_string(bytesRead) + " bytes");
        if (bytesRead == -1)
        {
            std::cerr << "Error receiving response\n";
            close(sockfd);
            return false;
        }

        // Process the response
        memcpy(&response, response_buffer, bytesRead);

        // Close socket
        close(sockfd);

        return true;
    }
};
