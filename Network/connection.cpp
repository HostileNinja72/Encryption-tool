#include "peertopeer/peertopeer.hpp"
#include <asio.hpp>


int main()
{
    asio::io_context context;
    unsigned short port = 12345;
    std::string peerAddress = "127.0.0.1";

    std::thread clientThread([&context, peerAddress, port]()
    {client(context, peerAddress, port);});

    context.run();

    done = true;
    clientThread.join();

    return 0;

}