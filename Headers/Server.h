#ifndef SERVER_H_INCLUDED
#define SERVER_H_INCLUDED

extern int port;

int init_server();
void start_server(int server_fd, char* certificate_file_path);

#endif // SERVER_H_INCLUDED
