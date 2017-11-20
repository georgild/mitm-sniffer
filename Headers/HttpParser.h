#ifndef HTTPPARSER_H_INCLUDED
#define HTTPPARSER_H_INCLUDED

extern int dump_mode;
extern int output_file_fd;
extern char vhost[52];

char* change_host(char* request, char* new_host);
int construct_request(char* bufferToWrite, char* buffer, SSL* ssl_victim_fd);

#endif // HTTPPARSER_H_INCLUDED
