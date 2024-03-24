#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <sys/types.h>
#include <arpa/inet.h>
#include "server.h"
#include "defs.h"



// TODO: unit tests
// TODO: example code


void unitTests(){


}



int main()
{

	/*
    Server server = Server(30, true);

    // Add routes and corresponding route handler functions
    server.addRoute("/", [](const Message &request, Message &response, int clientSocket, Server *in_server)
                    {
                        // Send response
                        response.setHeaders(200,"",30,"/","text/plain");
                        response.setData("Hello from server");
                        in_server->sendMessage(response, clientSocket);

                        std::cout << "send data!" << std::endl; });

    server.startServer()
    */

    return 0;
}
