#pragma once
#include <string.h>

struct Message
{
    int status;
    int port;
    char ip_address[64];
    char path[64];
    char datatype[64];
    uint8_t data[2048];

    void setHeaders(int status, std::string ip_address, int port, std::string path, std::string datatype){

        this->status = status;
        std::strncpy(this->ip_address, ip_address.c_str(), sizeof(this->ip_address));
        this->port = port;
        std::strncpy(this->path, path.c_str(), sizeof(this->path));
        std::strncpy(this->datatype, datatype.c_str(), sizeof(this->datatype));
    }

};
