#ifndef CLIENT_H
#define CLIENT_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include "defs.h"

class Client
{
private:
    int sockfd;

public:
    Client();
    ~Client();

    bool sendMessage(const Message &, Message &, const char *serverIp, int serverPort);
};

#endif // CLIENT_H
