#pragma once

#include <string.h>
#include "crypto-defs.h"

// TODO: take in certificate
// TODO: take certificate array


struct Message
{
    int status;
    int port;
    char ip_address[64];
    char path[64];
    char dataType[64];
    size_t dataSize;
    char data[4096];

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
    	std::string dataType = std::str(dataType);
    	if(dataType != "text/plain"){
    		return "";
    	}
        std::string dataString(this->data);
        return dataString;
    }

};