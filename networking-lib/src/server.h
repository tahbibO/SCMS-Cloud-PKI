/*
 * Server.h
 *
 *  Created on: Mar. 21, 2024
 *      Author: Tahbib
 */

#ifndef SRC_INCLUDES_SERVER_H_
#define SRC_INCLUDES_SERVER_H_

#include <functional>
#include <unordered_map>
#include <string>
#include <sys/json.h>
#include "defs.h"

class Server
{
private:
    std::unordered_map<std::string, std::function<void(const Message &, Message &, int, Server *)>> routes;
    int serverSocket;
    int port;

public:
    Server(int portNumber);
    ~Server();

    void addRoute(const std::string &path, const std::function<void(const Message &, Message &, int, Server *)> &handler);
    void startServer();
    void stopServer();
    void handleConnections();
    void sendMessage(const Message &response, int clientSocket);
};

#endif /* SRC_INCLUDES_SERVER_H_ */
