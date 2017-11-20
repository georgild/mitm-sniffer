#ifndef SSL_H_INCLUDED
#define SSL_H_INCLUDED

#include <openssl/ssl.h>

void show_last_ssl_error(char* description);
void openssl_init();
void create_certificate(char* certificate_file);
SSL_CTX* init_ssl_server_context(const char* certificate_file);
SSL* ssl_init_server_connection(int* fd, SSL_CTX* ssl_context);
SSL* ssl_init_client_connection(char* vhost);
int ssl_read(SSL* fd, char* buffer, int size);
int ssl_write(SSL* fd, char* buffer, int size);
int ssl_close(SSL* fd);

#endif // SSL_H_INCLUDED
