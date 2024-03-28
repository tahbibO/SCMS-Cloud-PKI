#pragma once

#include <functional>
#include <unordered_map>
#include "networking-defs.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/json.h>
#include <arpa/inet.h>
#include <string.h>
#include <chrono>
#include <thread>

class Server
{
private:
    std::unordered_map<std::string, std::function<void(const Message &, Message &, int, Server *)>> routes;
    int serverSocket;
    int port;
    bool logging;
    void log(std::string message)
    {
        if (logging)
        {
            std::cout << message << std::endl;
        }
    }

public:
    Server(int portNumber, bool logging = false) : serverSocket(-1), port(portNumber), logging(logging)
    {
        log("Created Server Object");
    }

    ~Server()
    {
        stopServer();
    }

    void addRoute(const std::string &path, const std::function<void(const Message &, Message &, int, Server *)> &handler)
    {
        log("Function added to route: " + path);
        routes[path] = handler;
    }

    void startServer()
    {
        // Create socket
        if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
            std::cerr << "Error creating socket\n";
            stopServer();
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

        log("Listening on " + std::to_string(port));

        // handle routes
        handleConnections();
    }

    void stopServer()
    {
        if (serverSocket != -1)
        {
            log("Closing server socket");
            close(serverSocket);
            serverSocket = -1;
        }
    }

    void handleConnections()
    {
        // creating a client socket
        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);

        while (true)
        {
            // Accept incoming connections, this is a blocking call
            int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &clientAddrLen);
            if (clientSocket == -1)
            {
                std::cerr << "Error accepting connection\n";
                stopServer();
                return;
            }

            // Read the request message
            char buffer[sizeof(Message)];
            Message request, response;
            int bytesRead = recv(clientSocket, buffer, sizeof(request), 0);
            memcpy(&request, buffer, bytesRead);

            log("Received " + std::to_string(bytesRead) + " bytes");

            // Find the corresponding handler for the route
            if (routes.find(std::string(request.path)) != routes.end())
            {
                // Call the handler function and pass the request
                log("Handling request for: " + std::string(request.path));
                routes[std::string(request.path)](request, response, clientSocket, this);
            }
            else
            {
                // return 404 if route not found
                log("Route not found: " + std::string(request.path));
                response.setHeaders(404, "", port, "", "empty");
                sendMessage(response, clientSocket);
            }
        }
    }

    void sendMessage(const Message &response, int clientSocket)
    {
        // serialize the response object to a buffer using memcpy
        size_t size = sizeof(response);
        char buffer[size];
        memcpy(buffer, &response, size);

        // Send the response
        send(clientSocket, buffer, sizeof(buffer), 0);
    }
};
