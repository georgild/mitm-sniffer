#ifndef PROXYMITM_H_INCLUDED
#define PROXYMITM_H_INCLUDED

extern char vhost[52];
void proxy_init(int *victim_fd, SSL_CTX* ssl_context);

#endif // PROXYMITM_H_INCLUDED
