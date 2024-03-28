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
    char dataType[64];
    size_t dataSize;
    char data[4096];

    Message(){};
    virtual ~Message(){};

    void setHeaders(int status, std::string ip_address, int port, std::string path, std::string dataType)
    {

        this->status = status;
        std::strncpy(this->ip_address, ip_address.c_str(), sizeof(this->ip_address));
        this->port = port;
        std::strncpy(this->path, path.c_str(), sizeof(this->path));
        std::strncpy(this->dataType, dataType.c_str(), sizeof(this->dataType));
    }

    virtual void setData(std::string data)
    {
        this->dataSize = data.length();
        std::strncpy(this->data, data.c_str(), data.length());
    }
};

std::string arrayToString(std::string *&arr, int size)
{
    std::string result;
    std::string delimiter = "<SPLIT>";
    for (int i = 0; i < size; ++i)
    {
        result += arr[i];
        if (i < size)
        {
            result += delimiter;
        }
    }

    return result;
}

std::string *stringToArray(std::string str, int size)
{
    std::string *result = new std::string[size];
    std::string delimiter = "<SPLIT>";
    size_t pos = 0;
    int index = 0;

    while ((pos = str.find(delimiter)) != std::string::npos) {
        result[index++] = str.substr(0, pos);
        if (index == size){
        	break;
        }
        str.erase(0, pos + delimiter.length());
    }

    return result;
}
