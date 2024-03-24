#pragma once

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
    bool logging;
    void log(std::string);

public:
    Server(int portNumber, bool logging = false);
    ~Server();

    void addRoute(const std::string &path, const std::function<void(const Message &, Message &, int, Server *)> &handler);
    void startServer();
    void stopServer();
    void handleConnections();
    void sendMessage(const Message &response, int clientSocket);
};

