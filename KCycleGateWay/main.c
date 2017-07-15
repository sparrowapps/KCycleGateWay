/*
============================================================================
Name        : main.c
Author      : sparrow
Version     : 1.0
Date        : 2017.07.03
Copyright   : 
Description : 

serial read thread
socket listen thread 
uart write thread
http write thread

serial read --> uart write thread
serial read --> http write thread --> (http read) --> uart write thread
socket read (ack) --> http write thread --> (http read) --> uart write thread
============================================================================

*/

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/select.h>
#include <pthread.h>
#include <signal.h>
#include "message_queue.h"
#include "ssltest.h"
#include "uart.h"
#include "wiringPi.h"
#include "micomd.h"

// function prototype
static void handle_uart_data(int fd);
static void handle_uart_request(int fd, char *request);
static void handle_socket_data(int fd);
static void handle_socket_request(int fd, char *request);
static void uart_write(int fd, const char *msg);
static void http_write(const char *msg);

// Message queue related code

struct gateway_op {
	enum { OP_WRITE_UART, OP_WRITE_HTTP, OP_READ_SOCKET, OP_READ_UART, OP_EXIT } operation;
	const char *message_txt; //
	int fd;
	int server_fd;
};


static struct message_queue uart_w_queue;
static struct message_queue uart_r_queue;
static struct message_queue https_queue;
static struct message_queue socket_queue;

static pthread_t main_thread; //serial read
static pthread_t socket_read_thread;
static pthread_t uart_read_thread; 
static pthread_t uart_write_thread;
static pthread_t http_write_thread;

static int main_blocked;

static void *uart_write_threadproc(void *dummy) {
	printf("uart_write_threadproc start\n");
	while (1) {
		struct gateway_op *message = message_queue_read(&uart_w_queue);

		if ( message->operation == OP_WRITE_HTTP ) {
			uart_write( message->fd, message->message_txt );
			message_queue_message_free(&uart_w_queue, message);
		} else if ( message->operation == OP_EXIT ) {
			message_queue_message_free(&uart_w_queue, message);
			return NULL;
		}
		
	}
	return NULL;
}

static void *http_write_threadproc(void *dummy) {
	printf("http_write_threadproc start\n");
	while (1) {
		struct gateway_op *message = message_queue_read(&https_queue);
		if ( message->operation == OP_WRITE_HTTP ) { 
			printf("message->operation == OP_WRITE_HTTP\n");
			http_write( message->message_txt );
			message_queue_message_free(&https_queue, message);
		} else if ( message->operation == OP_EXIT ) {
			message_queue_message_free(&https_queue, message);
			return NULL;
		}
	}
	return NULL;
}

extern int cnt_fd_socket;
static void *socket_read_threadproc(void *dummy) {
	printf("socket_read_threadproc start\n");
	while (1)  {
		struct gateway_op *message = message_queue_read(&socket_queue);
		if (message->operation == OP_READ_SOCKET ) {
			printf("OP_READ_SOCKET\n");
			handle_socket_data(message->fd);
			message_queue_message_free(&socket_queue, message);
		} else if ( message->operation == OP_EXIT ) {
			message_queue_message_free(&socket_queue, message);
			return NULL;
		}
	}
	return NULL;
}

static void *uart_read_threadproc(void *dummy) {
	printf("uart_read_threadproc start\n");
	while(1) {
		struct gateway_op *message = message_queue_read(&uart_r_queue);
		if (message->operation == OP_READ_UART ) {
			printf("OP_READ_UART\n");
			handle_uart_data(message->fd);
			message_queue_message_free(&uart_r_queue, message);
		} else if ( message->operation == OP_EXIT ) {
			message_queue_message_free(&uart_r_queue, message);
			return NULL;
		}
	}
	return NULL;
}

static void threads_init() {
	message_queue_init(&uart_r_queue, sizeof(struct gateway_op), 512);
	message_queue_init(&uart_w_queue, sizeof(struct gateway_op), 512);
	message_queue_init(&https_queue, sizeof(struct gateway_op), 512);
	message_queue_init(&socket_queue, sizeof(struct gateway_op), 512);
	
	pthread_create(&uart_write_thread, NULL, &uart_write_threadproc, NULL);
	pthread_create(&uart_read_thread, NULL, &uart_read_threadproc, NULL);
	pthread_create(&http_write_thread, NULL, &http_write_threadproc, NULL);
	pthread_create(&socket_read_thread, NULL, &socket_read_threadproc, NULL);
	
}

static void threads_destroy() {
	struct gateway_op *posion_uart_r = message_queue_message_alloc_blocking(&uart_r_queue);
	posion_uart_r->operation = OP_EXIT;
	message_queue_write(&uart_r_queue, posion_uart_r);

	struct gateway_op *poison_uart_w = message_queue_message_alloc_blocking(&uart_w_queue);
	poison_uart_w->operation = OP_EXIT;
	message_queue_write(&uart_w_queue, poison_uart_w);

	struct gateway_op *poison_https = message_queue_message_alloc_blocking(&https_queue);
	poison_https->operation = OP_EXIT;
	message_queue_write(&https_queue, poison_https);

	struct gateway_op *poison_socket = message_queue_message_alloc_blocking(&socket_queue);
	poison_socket->operation = OP_EXIT;
	message_queue_write(&socket_queue, poison_socket);


	pthread_join(uart_write_thread, NULL);
	pthread_join(uart_read_thread, NULL);
	pthread_join(http_write_thread, NULL);
	pthread_join(socket_read_thread, NULL);

	message_queue_destroy(&uart_r_queue);
	message_queue_destroy(&uart_w_queue);
	message_queue_destroy(&https_queue);
	message_queue_destroy(&socket_queue);
}

static void wake_main_thread() {
	if (__sync_lock_test_and_set(&main_blocked, 0)) {
		pthread_kill(main_thread, SIGUSR1);
	}
}

// MARK: uart data processing
struct socket_state {
	enum { SOCKET_INACTIVE, SOCKET_READING, SOCKET_WRITING } state;
	char buf[1024];
	int pos;
	// struct io_op *write_op;
};

struct socket_state socket_data[FD_SETSIZE];

// socket read
static void handle_socket_data(int fd) {
	int r;

	printf("handle_socket_data fd %d ", fd);


	if((r = read(fd, socket_data[fd].buf+socket_data[fd].pos, 1024-socket_data[fd].pos)) > 0) {
		printf("handle_socket_data %s\n",socket_data[fd].buf);
		socket_data[fd].pos += r;
		if(socket_data[fd].pos >= 4 ) {
			socket_data[fd].buf[socket_data[fd].pos] = '\0';
			socket_data[fd].state = SOCKET_INACTIVE;
			// 수신데이터 처리
			handle_socket_request(fd, socket_data[fd].buf);
			return;
		}
	} else {
		socket_data[fd].state = SOCKET_INACTIVE;
		close(fd);
	}
}

static void handle_socket_request(int fd, char *request) {
	//ack
	write(fd,"ack",3);
	printf("handle_socket_request ack!\n");
	if(!strncmp(request, "HELLO", 5)) {
		struct gateway_op *message = message_queue_message_alloc_blocking(&https_queue);
		message->operation = OP_WRITE_HTTP;
		message->message_txt = "GET /gateway/hello HTTP/1.1\n\
Host: 115.136.138.81:4432\n\
Connection: keep-alive\n\
Cache-Control: max-age=0\n\
Upgrade-Insecure-Requests: 1\n\
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n\
Accept-Encoding: gzip, deflate, sdch, br\n\
Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.6,en;q=0.4\n\
Cookie: JSESSIONID=5EBE4E35EBC10452C92EC291149B798F\n\
";
		message_queue_write(&https_queue, message);
		close(fd);
		del_socket(fd);
	} else {
		close(fd);
		del_socket(fd);
	}
}

// MARK: uart data processing
struct uart_state {
	enum { UART_INACTIVE, UART_READING, UART_WRITING } state;
	char buf[1024];
	int pos;
};

struct uart_state uart_data[FD_SETSIZE];

// uart 에서 데이터를 읽는 다.
// read_packet() 함수를 사용 하지 않는다.
static void handle_uart_data(int fd) {
	int r;
	if ((r = read(fd, uart_data[fd].buf + uart_data[fd].pos, 1024 - uart_data[fd].pos)) > 0) {
		uart_data[fd].pos += r;
		
		// 4글자의 시작 문자
		//if (uart_data[fd].pos >= 4 && !strncmp(uart_data[fd].buf + uart_data[fd].pos - 4, "\r\n\r\n", 4)) {

		//2글자의 시작 문자로 판단
/*
		if (uart_data[fd].pos >= 2 && 
			((uart_data[fd].buf + uart_data[fd].pos - 2) == 0x0D) &&
			((uart_data[fd].buf + uart_data[fd].pos - 1) == 0x0A)
			) 
		{
			printf("uart request read\n");

			uart_data[fd].buf[uart_data[fd].pos] = '\0';
			uart_data[fd].state = UART_INACTIVE;
			handle_uart_request(fd, uart_data[fd].buf);
			return;
		}
*/
		handle_uart_request(fd, uart_data[fd].buf);
	}
	else {
		uart_data[fd].state = UART_INACTIVE;
		close(fd);
	}
}

extern int list_end;
extern int cmd_state;
extern int data_status;
extern fd_masks[MAX_SOCKET_FD];
static void handle_uart_request(int fd, char *request) {
	// parse and cmd process
	int uart_cnt = 0;
	if (parse_data(request , &uart_cnt) == 1) {

		if (uart_cnt >0  || (cmd_state == 13 && list_end == 1) ) {
			printf("handle_uart_request\n");
			if (data_status == 0) {
				check_rf_data(request);
			} else {
				check_uart(request);
			}
		}

		// UART cmd ? HTTP cmd ?
		if(!strncmp(request, "UART", 4)) {
			char *msg_txt = request+4;

			struct gateway_op *message = message_queue_message_alloc_blocking(&uart_w_queue);
			message->operation = OP_WRITE_UART;
			message->message_txt = msg_txt;
			message->fd = fd;
			message_queue_write(&uart_w_queue, message);
		} else if (!strncmp(request, "HTTP", 4)) {
			char *msg_txt = request+4;

			struct gateway_op *message = message_queue_message_alloc_blocking(&https_queue);
			message->operation = OP_WRITE_HTTP;
			message->message_txt = msg_txt;
			message->fd = fd;
			message_queue_write(&https_queue, message);	
		} else {
			close(fd);
		}

	} else {
		return;
	}
}

static void uart_write(int fd, const char *msg) {
	int r = write_packet(fd, msg, strlen(msg));
}

static void http_write(const char *msg) {
	int r = ssl_write( msg, strlen(msg) );
}

// main fd select
int main(int argc, char *argv[]) {
	main_thread = pthread_self();
	threads_init();

	if (init_wiringPi() == -1) {
		printf("wirig pi failed\n");
		return -1;
	}

	int uart_fd = 0;
	int server_sockfd, client_sockfd = 0; 
	int client_len;

	fd_set readfds, wfds;
	int max_fd, r;
	struct sockaddr_in clientaddr;

	memset(fd_masks, -1, MAX_SOCKET_FD);

	uart_fd =  open_uart();
	server_sockfd = create_socket(PORT_NUM);
	printf("uart fd %d\n",uart_fd);
	printf("server_sockfd fd %d\n",server_sockfd);
	max_fd = uart_fd > server_sockfd ? uart_fd : server_sockfd;
	printf("maxfd %d\n",max_fd);
	max_fd = mk_fds(&readfds, max_fd);
	printf("maxfd %d\n",max_fd);

	if (server_sockfd >=0 && uart_fd >= 0 ) {
		while(1) {
			FD_ZERO(&readfds);
			FD_ZERO(&wfds);

			if (server_sockfd) FD_SET(server_sockfd, &readfds);
			if (uart_fd) FD_SET(uart_fd, &readfds);
			
			r = select(max_fd + 1, &readfds, (fd_set *)0, NULL, NULL);

			if (r < 0 && errno != EINTR) {
				perror("Error in select");
				return -1;
			}
			if (r >= 0) {
				
				if (FD_ISSET(uart_fd, &readfds)) {

					uart_data[uart_fd].state = UART_READING;
					uart_data[uart_fd].pos = 0;
					
					struct gateway_op *message = message_queue_message_alloc_blocking(&uart_r_queue);
					message->operation = OP_READ_UART;
					message->fd = uart_fd;
					message_queue_write(&uart_r_queue, message);
				}

				if (FD_ISSET(server_sockfd, &readfds)) {
					printf("SOCKET server_sockfd %d, uart_fd %d, max_fd %d\n", server_sockfd, uart_fd, max_fd);
					client_sockfd = accept(server_sockfd, (struct sockaddr *)&clientaddr, &client_len);
					if (client_sockfd < 0) {
						printf("Failed to accept the connection request from App Framework!\n");
					} else {
						
						if(add_socket(client_sockfd) == -1) {
							printf("Failed to add socket because of the number of socket(%d) !! \n", cnt_fd_socket);
						} else {
							printf("App Framework socket connected[fd = %d, cnt_fd = %d]!!!\n", client_sockfd, cnt_fd_socket);

							socket_data[client_sockfd].state = SOCKET_READING;
							socket_data[client_sockfd].pos = 0;
							
							struct gateway_op *message = message_queue_message_alloc_blocking(&socket_queue);
							printf("message queue write OP_READ_SOCKET\n");
							message->operation = OP_READ_SOCKET;
							message->fd = client_sockfd;
							
							message_queue_write(&socket_queue, message);

						}
					}

				}
			}
		}

		for(int i=0; i < cnt_fd_socket; i++)
		{
			del_socket(fd_masks[i]);
		}

		close(server_sockfd);
		uart_close(uart_fd);

		printf("End of GateWay Daemon!\n");

		return 0;

	} else {
		perror("Error listening on uart or socket");
	}
}

// message 전문
// GET /gateway/hello HTTP/1.1
// Host: 115.136.138.81:4432
// Connection: keep-alive
// Cache-Control: max-age=0
// Upgrade-Insecure-Requests: 1
// User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36
// Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
// Accept-Encoding: gzip, deflate, sdch, br
// Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.6,en;q=0.4
// Cookie: JSESSIONID=5EBE4E35EBC10452C92EC291149B798F
