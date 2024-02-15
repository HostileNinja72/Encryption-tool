#include "peertopeer.hpp"
#include <iostream>
#include <vector>

// Define the atomic flag
std::atomic<bool> done(false);

void messageHandler(asio::ip::tcp::socket &socket)
{
    while (!done)
    {
        try
        {
            asio::error_code ec;
            std::vector<char> vBuffer(1024);
            size_t length = socket.read_some(asio::buffer(vBuffer.data(), vBuffer.size()), ec);
            if (!ec && length > 0)
            {
                std::cout.write(vBuffer.data(), length);
                std::cout << std::endl;
            }
        }
        catch (std::exception &e)
        {
            std::cerr << e.what() << std::endl;
            done = true;
        }
    }
}

void server(asio::io_context &context, unsigned short port)
{
    asio::ip::tcp::acceptor acceptor(context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port));
    std::cout << "Listening on port " << port << std::endl;
    asio::ip::tcp::socket socket(context);
    acceptor.accept(socket);
    std::cout << "Connection established!" << std::endl;
    messageHandler(socket);
}

void client(asio::io_context &context, const std::string &host, unsigned short port)
{
    asio::ip::tcp::socket socket(context);
    asio::error_code ec;
    socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address(host, ec), port), ec);

    if (!ec)
    {
        std::cout << "Connected to " << host << ":" << port << std::endl;
        messageHandler(socket);
    }
    else
    {
        std::cout << "Failed to connect, starting server..." << std::endl;
        server(context, port);
    }
}
