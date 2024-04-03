#pragma once

#include <string.h>
#include "crypto-defs.h"

class Message
{

public:
    int status;
    int port;
    char ip_address[64];
    char path[64];
    char method[64];
    char dataType[64];
    size_t dataSize;
    char data[49152];

    Message(){};
    virtual ~Message(){};

    void setHeaders(int status,
    		std::string ip_address,
			int port,
			std::string path,
			std::string method,
			std::string dataType)
    {

        this->status = status;
        std::strncpy(this->ip_address, ip_address.c_str(), sizeof(this->ip_address));
        this->port = port;
        std::strncpy(this->path, path.c_str(), sizeof(this->path));
        std::strncpy(this->method, method.c_str(), sizeof(this->method));
        std::strncpy(this->dataType, dataType.c_str(), sizeof(this->dataType));
    }

    virtual void setData(std::string data)
    {
        this->dataSize = data.length();
        std::strcpy(this->data,data.c_str());

    }
};

