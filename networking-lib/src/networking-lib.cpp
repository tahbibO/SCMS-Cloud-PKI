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


int main() {
    Server server = Server(30);

    // Add routes and corresponding route handler functions
    server.addRoute("/", [](const Message &request, Message &response, int clientSocket, Server *in_server)
                    {

                        // Send response
    					std::cout << "here" << std::endl;
                        response.status = 200;
                        std::strncpy(response.path, "", sizeof(response.path));
                        std::strncpy(response.datatype, "text/plain", sizeof(response.datatype));
                        memccpy(response.data, "Hello from server", 0, 17);
                        in_server->sendMessage(response, clientSocket);
                        std::cout << "send data!" << std::endl;


                    });

    server.startServer();

    return 0;
}
