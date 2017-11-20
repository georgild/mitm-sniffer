#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "SSL.h"
#include "ProxyMITM.h"
#include "Server.h"
#include "HttpParser.h"

int init_server()
{

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        err(1, "Error opening server socket");
        return -1;
    }

    int i = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) < 0)
    {
        err(1, "Error on allow socket to bind to an address and port already in use");
        return -1;
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        err(1, "Error binding server socket");
        return -1;
    }

    if (listen(server_fd, 5) < 0)
    {
        err(1, "Error listening server socket");
        return -1;
    }
    return server_fd;
}

void start_server(int server_fd, char* certificate_file_path)
{
    printf("Server started and listening on port %d for vhost: %s\n", port, (strlen(vhost) <= 0 ? "any" : vhost));

    SSL_CTX* ssl_proxy_context = init_ssl_server_context(certificate_file_path);

    while(1)
    {
        struct sockaddr_in victim_address;

        int size = sizeof(victim_address);
        int victim_fd = accept(server_fd, (struct sockaddr *)&victim_address, &size);

        /*if (connected_hosts[0] != NULL && strcmp(connected_hosts[0], inet_ntoa(victim_address.sin_addr)) == 0)
        {
            puts("Rejecting victim\n");
            continue;
        }
        strcpy(connected_hosts[0], inet_ntoa(victim_address.sin_addr));*/

        printf("New connection from %s:%d\n",
        inet_ntoa(victim_address.sin_addr), ntohs(victim_address.sin_port));

        if (victim_fd < 0)
        {
            err(1, "Error accepting victim");
        }
        int pid = fork();
        if (pid < 0)
            err(1, "Error on fork");
        if (pid == 0)
        {
            close(server_fd);
            proxy_init(&victim_fd, ssl_proxy_context);
            close(victim_fd);
            exit(0);
        }
        else
         close(victim_fd);

    }

}
