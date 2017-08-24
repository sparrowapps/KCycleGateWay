#define _BSD_SOURCE

// #define _PACKET_ENCRYPTY

// function prototype
static void handle_uart_data(int fd);
static void handle_uart_request(int fd, char *request);
static void handle_socket_data(int fd);
static void handle_socket_request(int fd, char *request);
static void uart_write(int fd, char *msg);
static void http_write( char *msg, int fd);
