#pragma once

#include <string.h>

struct Message
{
    int status;
    int port;
    char ip_address[64];
    char path[64];
    char dataType[64];
    size_t dataSize;
    char data[2048];

    void setHeaders(int status, std::string ip_address, int port, std::string path, std::string dataType)
    {

        this->status = status;
        std::strncpy(this->ip_address, ip_address.c_str(), sizeof(this->ip_address));
        this->port = port;
        std::strncpy(this->path, path.c_str(), sizeof(this->path));
        std::strncpy(this->dataType, dataType.c_str(), sizeof(this->dataType));
    }

    void setData(std::string data)
    {
        this->dataSize = sizeof(data);
        std::strncpy(this->data, data.c_str(), this->dataSize);
    }

    std::string dataToString()
    {
        std::string dataString(this->data);
        return dataString;
    }
};
