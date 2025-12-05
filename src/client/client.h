#pragma once
#include <memory>

#include "websock.h"

namespace ctier
{

    class Client
    {
      private:
        std::unique_ptr<WebSock> _socket;

      public:
        // Constructor: creates the socket on the heap and takes ownership
        Client(int domain, int type, int protocol, bool ssl) :
            _socket(std::make_unique<WebSock>(domain, type, protocol, ssl, false))
        {
        }

        // Disable copying (unique_ptr cannot be copied)
        Client(const Client&)            = delete;
        Client& operator=(const Client&) = delete;

        // Allow move semantics
        Client(Client&&) noexcept            = default;
        Client& operator=(Client&&) noexcept = default;

        // Accessor for the socket (non-owning)
        WebSock* get_web_socket() const { return _socket.get(); }

        bool send_data(const char* data, size_t size)
        {
            if (!_socket)
                return false;
            return _socket->send(data, size);
        }

        bool receive_data(char* buffer, size_t size)
        {
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_all_algorithms();

            if (!_socket)
                return false;
            return _socket->receive(buffer, size);
        }

        bool connect(const char* address, const char* port) { return _socket->connect(address, port); }
        void close() { _socket->close_socket(); }
        int receive(char* buffer, size_t size) { return _socket->receive(buffer, size);}
        ~Client() = default;
    };

}  // namespace ctier
