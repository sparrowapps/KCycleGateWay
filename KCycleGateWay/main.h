#define _BSD_SOURCE

//#define _PACKET_ENCRYPTY

void SSLServerSend(char *url, char *value, int valuelen, int modem_addr);
void request_uart_send(int cmd);
