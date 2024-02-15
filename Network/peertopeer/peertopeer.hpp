
#ifndef PEERTOPEER_HPP
#define PEERTOPEER_HPP

#include <asio.hpp>
#include <string>
#include <atomic>

#ifdef _WIN32
#define _WIN32_WINNT 0x0A00
#endif

#define ASIO_STANDALONE
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>



extern std::atomic<bool> done;

void messageHandler(asio::ip::tcp::socket &socket);
void server(asio::io_context &context, unsigned short port);
void client(asio::io_context &context, const std::string &host, unsigned short port);

#endif
