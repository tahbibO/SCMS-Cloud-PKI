#include "server.h"
#include <iostream>
#include <thread>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/json.h>
#include <arpa/inet.h>
#include <string.h>
#include <chrono>
#include <thread>

Server::Server(int portNumber) : serverSocket(-1), port(portNumber) {}

Server::~Server()
{
    stopServer();
}

void Server::addRoute(const std::string &path, const std::function<void(const Message &, Message &, int, Server *)> &handler)
{
    routes[path] = handler;
}

void Server::startServer()
{
    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
        std::cerr << "Error creating socket\n";
        return;
    }

    // Bind socket to port
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
        std::cerr << "Error binding socket\n";
        stopServer();
        return;
    }

    // Listen for incoming connections
    if (listen(serverSocket, 5) == -1)
    {
        std::cerr << "Error listening on socket\n";
        stopServer();
        return;
    }

    std::cout << "Server started on port " << port << std::endl;

    handleConnections();
}

void Server::handleConnections()
{
    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
    std::cout << "listening for requests" << std::endl;
    while (true)
    {
    	std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "accepting connection" << std::endl;
        int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &clientAddrLen);
        if (clientSocket == -1)
        {
            std::cerr << "Error accepting connection\n";
            stopServer();
            return;
        }
        std::cout << "going next" << std::endl;
        std::cout << "Received connection from: " << inet_ntoa(clientAddr.sin_addr) << std::endl;

        char buffer[4096];
        int bytesRead;
        std::cout << "95" << std::endl;
        Message request;
        bytesRead = recv(clientSocket, buffer, sizeof(request), 0);

		std::cout << "Received: " << std::string(buffer, bytesRead) << std::endl;

		// Parse the received message
		// ... code to parse the message ...
		// use memcpy to copy the buffer to the request object
		memcpy(&request, buffer, bytesRead);

		// Find the corresponding handler for the route
		std::cout << "95" << std::endl;
		std::cout << "Path "<<request.path << std::endl;
		std::cout << "Status "<<request.status << std::endl;
		if (routes.find(std::string(request.path)) != routes.end())
		{
			// Call the handler function and pass the request
			Message response;
			routes[std::string(request.path)](request, response, clientSocket, this);
		}
		else
		{
			// else send a message with status of 404 using the send function
			Message response;

			// Copy the string values into char[64] arrays
			response.status = 404;
			std::strncpy(response.path, "", sizeof(response.path));
			std::strncpy(response.datatype, "text/plain", sizeof(response.datatype));

			sendMessage(response, clientSocket);
        }
        std::cout << "105" << std::endl;
    }
}

void Server::stopServer()
{
    if (serverSocket != -1)
    {
        close(serverSocket);
        serverSocket = -1;
    }
}

void Server::sendMessage(const Message &response, int clientSocket)
{
    // serialize the response object to a buffer using memcpy
    size_t size = sizeof(response);
    char buffer[size];
    memcpy(buffer, &response, size);

    // Send the response
    send(clientSocket, buffer, sizeof(buffer), 0);
}
