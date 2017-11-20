#include <openssl/ssl.h>
#include <openssl/err.h>
#include <err.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <libnet.h>

void show_last_ssl_error(char* description)
{
    puts("SSL error: ");
    puts(description);
    puts("\n");
    char *buf;
    ERR_error_string(ERR_get_error(), buf);
    err(1, "ERR_error_string %s", buf);
}

void openssl_init()
{
    SSL_library_init();
    SSL_load_error_strings();
}

void create_certificate(char* certificate_file)
{
    struct stat st;

    int status;

    if (stat(certificate_file, &st) < 0)
    {

        if (!fork())
        {
            if (execlp("openssl",  "genrsa", "-out", certificate_file, "1024", NULL) < 0)
                err(1, "Openssl genrsa error");
            exit(0);
        }

        wait(&status);

        if (!fork())
        {
            if (execlp("openssl",  "req", "-new", "-key", certificate_file, "-out", "req.pem", NULL) < 0)
                err(1, "Openssl req error");
            exit(0);
        }

        wait(&status);

        if (!fork())
        {
            if (execlp("openssl", "x509", "-req", "-days", "-365", "-in", "req.pem", "-signkey", certificate_file, "-out",
                "cert.new", NULL) < 0)
                err(1, "Openssl x509 error");
            exit(0);
        }

        wait(&status);

        /*if (!fork())
        {
            if (execlp("cat", "cert.new", ">>", certificate_file, NULL) < 0)
                err(1, "Openssl cat error");
            //wait(&status);
            exit(0);
        }
        wait(&status);*/
        char cmd[25];
        strcpy(cmd, "cat cert.new >> ");
        strcat(cmd, certificate_file);

        if (system(cmd) != 0)
            err(1, "Openssl cat error");

        unlink("cert.new");
        unlink("req.pem");

        printf("Certificate generated in %s\n", certificate_file);
    }
}

SSL_CTX* init_ssl_server_context(const char* certificate_file)
{
    struct stat st;
    if (stat(certificate_file, &st) < 0)
    {
        err(1, "Could not access certificate file");
    }

    SSL_CTX *ssl_context = SSL_CTX_new(SSLv23_server_method());

    if (SSL_CTX_use_certificate_file(ssl_context, certificate_file, SSL_FILETYPE_PEM) == 0)
    {
        show_last_ssl_error("SSL_CTX_use_certificate_file");
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_context, certificate_file, SSL_FILETYPE_PEM) == 0)
    {
        show_last_ssl_error("SSL_CTX_use_PrivateKey_file");
        return NULL;
    }

    if (SSL_CTX_check_private_key(ssl_context) == 0)
    {
        show_last_ssl_error("SSL_CTX_check_private_key");
        return NULL;
    }

    return ssl_context;
}

SSL* ssl_init_server_connection(int* fd, SSL_CTX* ssl_context)
{
    if (fcntl(*fd, F_SETFL, 0) < 0)
        err(1, "fcntl");

    SSL *ssl_client = SSL_new(ssl_context);

    SSL_set_fd(ssl_client, *fd);

    if (SSL_accept(ssl_client) <= 0)
    {
        show_last_ssl_error("SSL_accept");
        return NULL;
    }

    return ssl_client;
}

SSL* ssl_init_client_connection(char* vhost)
{
    struct	sockaddr_in server_in;
    int server_fd;

    server_in.sin_family = AF_INET;
    server_in.sin_port = htons(443);

    libnet_t *l;
    char errbuf[LIBNET_ERRBUF_SIZE];
    l = libnet_init (LIBNET_LINK, NULL, errbuf);

    if (l == NULL)
        err(1, errbuf);

    uint32_t addr = libnet_name2addr4(l, vhost, LIBNET_RESOLVE);//20974879;//

    if (addr <= 0)
        err(1, "Error getting byte representation of vhost address");

    if (addr == ntohl(INADDR_LOOPBACK))
        err(1, "Looping danger!");

    server_in.sin_addr.s_addr = addr;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        err(1, "Error opening socket to target vhost");

    if (connect(server_fd, (struct sockaddr *)&server_in, sizeof(server_in)) < 0)
        err(1, "Error connecting to target vhost");

    SSL_CTX *ssl_server_ctx = SSL_CTX_new(SSLv23_client_method()); // TLS_method ?!

    SSL* ssl_server = SSL_new(ssl_server_ctx);
    SSL_set_connect_state(ssl_server);
    SSL_set_fd(ssl_server, server_fd);

    if (SSL_connect(ssl_server) <= 0)
      show_last_ssl_error("SSL_connect");

    return ssl_server;

}

int ssl_read(SSL* fd, char* buffer, int size)
{
    int bytes = SSL_read(fd, buffer, size);

    if (bytes < 0)
        show_last_ssl_error("SSL_read");

    return bytes;
}

int ssl_write(SSL* fd, char* buffer, int size)
{
    int bytes = SSL_write(fd, buffer, size);

    if (bytes < 0)
        show_last_ssl_error("ssl_write");

    return bytes;
}

void ssl_close(SSL* fd)
{
    SSL_free(fd);
}
