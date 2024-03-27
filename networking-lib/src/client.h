#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include "networking-defs.h"

class Client
{
private:
    int sockfd;
    bool logging;
    void log(std::string);

public:
    Client(bool logging = false);
    ~Client();

    bool sendMessage(const Message &, Message &, const char *serverIp, int serverPort);
};


