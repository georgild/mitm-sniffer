#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "SSL.h"
#include "Server.h"
#include "ProxyMITM.h"

int dump_mode = 2; // 1 = all, 2 = requests, 3 = responses
int output_file_fd = -1;
int port = 443;
char vhost[52];

void print_usage()
{
    printf("NetSec2_MITM_c [-c certificate_file] [-f output_file] [-d dump_mode] [-p port] [-v vhost]\n\
    -c certificate_file (default generated is certificate.crt)\n\
    -f output_file (optional)\n\
    -d dump_mode (1 for all | 2 for requests | 3 for responses, default is requests)\n\
    -v vhost (vhost to sniff)\n\
    -p port (default is 443)\n\n");
}

int main(int argc, char *argv[])
{
    // ZOMBIES
    //signal(SIGCHLD,SIG_IGN);

    char certificate_file_path[52];
    strcpy(certificate_file_path, "certificate.crt");

    if (argc == 1)
    {
        print_usage();
        //exit(0);
    }
    else
    {
        int i = 0;
        for(i = 1; i < argc; i++)
        {
            if (strcmp(argv[i], "-c") == 0)
            {
                if (sizeof(argv[i + 1]) > sizeof(certificate_file_path))
                    err(1, "Certificate file name too big");
                strcpy(certificate_file_path, argv[i + 1]);
            }
            else if(strcmp(argv[i], "-f") == 0)
            {
                output_file_fd = open(argv[i + 1], O_WRONLY | O_APPEND | O_CREAT, S_IWUSR);
                if (output_file_fd < 0)
                    err(1, "Could not open output file");
            }
            else if(strcmp(argv[i], "-d") == 0)
            {
                dump_mode = atoi(argv[i + 1]);
                if (dump_mode < 1 || dump_mode > 3)
                {
                    printf("Invalid dump mode value provided");
                    exit(0);
                }
            }
            else if(strcmp(argv[i], "-v") == 0)
            {
                if (sizeof(argv[i + 1]) > sizeof(vhost))
                    err(1, "Vhost name too big");
                strcpy(vhost, argv[i + 1]);
            }
            else if(strcmp(argv[i], "-p") == 0)
            {
                port = atoi(argv[i + 1]);
            }
        }
    }

    create_certificate(certificate_file_path);
    openssl_init();
    int server = init_server();

    start_server(server, certificate_file_path);
    return 0;
}
