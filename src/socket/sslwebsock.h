#pragma once
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <unistd.h>

#include <string>

namespace opensock {
class SSLWebSock {
  int _socket = -1;
  SSL_CTX *_ctx = nullptr;
  SSL *_ssl = nullptr;
  bool _isServer = false;

public:
  SSLWebSock(bool isServer) : _isServer(isServer) {}
  ~SSLWebSock() { close(); }

  bool init(const std::string &certFile = "", const std::string &keyFile = "") {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    _ctx = SSL_CTX_new(_isServer ? TLS_server_method() : TLS_client_method());
    if (!_ctx)
      return false;

    if (_isServer) {
      if (SSL_CTX_use_certificate_file(_ctx, certFile.c_str(),
                                       SSL_FILETYPE_PEM) <= 0)
        return false;
      if (SSL_CTX_use_PrivateKey_file(_ctx, keyFile.c_str(),
                                      SSL_FILETYPE_PEM) <= 0)
        return false;
    }

    return true;
  }

  bool attach(int socketFd) {
    _socket = socketFd;
    _ssl = SSL_new(_ctx);
    SSL_set_fd(_ssl, _socket);

    if (_isServer) {
      if (SSL_accept(_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return false;
      }
    } else {
      if (SSL_connect(_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return false;
      }
    }
    return true;
  }

  bool send(const char *data, size_t size) {
    return SSL_write(_ssl, data, size) > 0;
  }

  bool receive(char *buffer, size_t size) {
    return SSL_read(_ssl, buffer, size) > 0;
  }
  SSL_CTX *get_context() const { return _ctx; }
  void set_context(SSL_CTX *ctx) { _ctx = ctx; }

  void close() {
    if (_ssl) {
      SSL_shutdown(_ssl);
      SSL_free(_ssl);
      _ssl = nullptr;
    }
    if (_socket != -1) {
#if IS_WINDOWS
      ::closesocket(_socket);
#else
      ::close(_socket);
#endif
      printf("client closed!\n");
      _socket = -1;
    }
  }
};
} // namespace opensock
