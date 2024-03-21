#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <sys/types.h>
#include <arpa/inet.h>


void sendData(const std::string &data, const std::string &address, int port)
{
    int sendSocket;
    struct sockaddr_in sendAddr;

    // Create a socket
    sendSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (sendSocket < 0)
    {
        std::cerr << "Error creating send socket\n";
        return;
    }

    sendAddr.sin_family = AF_INET;
    sendAddr.sin_port = htons(port);
    if (inet_pton(AF_INET, address.c_str(), &sendAddr.sin_addr) <= 0)
    {
        std::cerr << "Invalid address/ Address not supported \n";
        return;
    }

    // Connect to the server
    if (connect(sendSocket, (struct sockaddr *)&sendAddr, sizeof(sendAddr)) < 0)
    {
        std::cerr << "Error connecting to port " << port << "\n";
        close(sendSocket);
        return;
    }

    // Send data
    send(sendSocket, data.c_str(), data.length(), 0);

    std::cout << "Sent message to port " << port << ": " << data << std::endl;

    close(sendSocket);
}

void receiveData(int port)
{
    int listenSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
    char buffer[1024];

    // Create a socket to listen on port 30
    listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket < 0)
    {
        std::cerr << "Error creating socket\n";
        return;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket
    if (bind(listenSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
        std::cerr << "Error binding socket\n";
        close(listenSocket);
        return;
    }

    // Listen for incoming connections
    listen(listenSocket, 5);

    std::cout << "Listening on port 30...\n";

    // Accept incoming connections
    clientSocket = accept(listenSocket, (struct sockaddr *)&clientAddr, &clientAddrLen);
    if (clientSocket < 0)
    {
        std::cerr << "Error accepting connection\n";
        close(listenSocket);
        return;
    }

    std::cout << "Received connection from: " << inet_ntoa(clientAddr.sin_addr) << std::endl;

    // Receive data
    int bytesRead;
    while ((bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0)) > 0)
    {
        std::cout << "Received from port 20: " << std::string(buffer, bytesRead) << std::endl;
    }

    close(clientSocket);
    close(listenSocket);
}



int main()
{
    std::string data = "Hello World";
    std::string address = "127.0.0.1"; // replace with your address
    int send_port = 30;                     // replace with your port
    int receive_port = 30;


    std::thread sender(sendData, data, address, send_port);
    std::thread receiver(receiveData, receive_port);

    // Join the threads with the main thread
    sender.join();
    receiver.join();

    return 0;
}
