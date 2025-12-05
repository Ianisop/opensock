#pragma once

#include "sslwebsock.h"
#if defined(_WIN32) || defined(_WIN64)
#define IS_WINDOWS 1
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#define IS_WINDOWS 0
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#endif

#include <cstddef>
namespace opensock {
class WebSock {
public:
  WebSock(int domain, int type, int protocol, bool ssl_socket, bool server);
  WebSock(int fd);
  ~WebSock();

  bool create(int domain = AF_INET, int type = SOCK_STREAM, int protocol = 0);
  bool bind(const char *address, const char *port);
  bool listen(int backlog = 5);
  int accept(sockaddr_in *clientAddr = nullptr);
  bool connect(const char *address, const char *port);
  bool send(const char *buffer, size_t size);
  int receive(char *buffer, size_t size);
  void close_socket();
  SSLWebSock *get_ssl();
  int get_socket();
  static void cleanup();
  bool valid() const;

private:
#if IS_WINDOWS
  using socket_t = SOCKET;
  static constexpr socket_t INVALID_SOCKET_VALUE = INVALID_SOCKET;
#else
  using socket_t = int;
  static constexpr socket_t INVALID_SOCKET_VALUE = -1;
#endif
  socket_t _socket;
  bool _ssl = false;
  SSLWebSock *_ssl_socket;
};
}; // namespace opensock
