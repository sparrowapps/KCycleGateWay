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

// 메인 스레드 <---> 스레드 풀( 시리얼 write, http write 명령 컨텍스트)
struct gateway_op {
	enum { OP_WRITE_UART, OP_WRITE_HTTP, OP_EXIT } operation;
	const char *message_txt; //
	int rfd, fd;
};

// 메인 스레드 <--- 입출력 컨텍스트
struct io_op {
	char buf[1024]; //
	int len, pos; //
	int fd, rfd;
	int close_pending;
};

static struct message_queue worker_queue;
static struct message_queue io_queue;

static pthread_t main_thread; //serial read
static pthread_t socket_read_thread; //소켓 수신대기 스레드 
static pthread_t uart_write_thread;
static pthread_t http_write_thread;

static int main_blocked;

static void *uart_write_threadproc(void *dummy) {
	while (1) {
		struct gateway_op *message = message_queue_read(&worker_queue);

		if ( message->operation == OP_WRITE_HTTP ) {
			uart_write( message->fd, message->message_txt );
			message_queue_message_free(&worker_queue, message);
		} else if ( message->operation == OP_EXIT ) {
			message_queue_message_free(&worker_queue, message);
			return NULL;
		}
		
	}
	return NULL;
}

static void *http_write_threadproc(void *dummy) {
	while (1) {
		struct gateway_op *message = message_queue_read(&worker_queue);
		if ( message->operation == OP_WRITE_HTTP ) { 
			http_write( message->message_txt );
			message_queue_message_free(&worker_queue, message);
		} else if ( message->operation == OP_EXIT ) {
			message_queue_message_free(&worker_queue, message);
			return NULL;
		}
	}
	return NULL;
}

extern int cnt_fd_socket;
static void *socket_read_threadproc(void *dummy) {
	int server_sockfd, client_sockfd = 0;
	int state = 0;
	struct sockaddr_in clientaddr;
	int client_len = sizeof(clientaddr);

	server_sockfd = create_socket(PORT_NUM);
	if (server_sockfd >= 0) {
		while (1) {
			int max_fd, r;
			fd_set readfds, wfds;
			FD_ZERO(&readfds);
			r = select(max_fd + 1, &readfds, &wfds, NULL, NULL );
			if (r >= 0) {
				if (FD_ISSET(server_sockfd, &readfds)) {

					client_sockfd = accept(server_sockfd, (struct sockaddr *)&clientaddr, &client_len);

					if (client_sockfd < 0 ) {
						printf("Failed to accept the connection request from App Framework!\n");
					} else {
						if (add_socket(client_sockfd) == -1) {
							printf("Failed to add socket because of the number of socket(%d) !! \n", cnt_fd_socket);
						} else {
							//client_fd = client_sockfd;
							printf("App Framework socket connected[fd = %d, cnt_fd = %d]!!!\n", client_sockfd, cnt_fd_socket);
							handle_socket_data(client_sockfd); // socket 수신 처리
						}
					}
				}
			}
		}
	}
	return NULL;
}


static void threads_init() {
	message_queue_init(&worker_queue, sizeof(struct gateway_op), 512);
	
	pthread_create(&uart_write_thread, NULL, &uart_write_threadproc, NULL);
	pthread_create(&http_write_thread, NULL, &http_write_threadproc, NULL);
	pthread_create(&socket_read_thread, NULL, &socket_read_threadproc, NULL);
}

static void threads_destroy() {
	struct gateway_op *poison = message_queue_message_alloc_blocking(&worker_queue);
	poison->operation = OP_EXIT;
	message_queue_write(&worker_queue, poison);
	
	pthread_join(uart_write_thread, NULL);
	pthread_join(http_write_thread, NULL);
	pthread_join(socket_read_thread, NULL);

	message_queue_destroy(&worker_queue);
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
	struct io_op *write_op;
};

struct socket_state socket_data[FD_SETSIZE];

// socket read
static void handle_socket_data(int fd) {
	int r;
	if((r = read(fd, socket_data[fd].buf+socket_data[fd].pos, 1024-socket_data[fd].pos)) > 0) {
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

	if(!strncmp(request, "HELLO", 5)) {
		struct gateway_op *message = message_queue_message_alloc_blocking(&worker_queue);
		message->operation = OP_WRITE_HTTP;
		message->message_txt = "HELLO";
		message->fd = fd;
		message_queue_write(&worker_queue, message);
		close(fd);
	} else {
		close(fd);
	}
}

// MARK: uart data processing
struct uart_state {
	enum { UART_INACTIVE, UART_READING, UART_WRITING } state;
	char buf[1024];
	int pos;
	struct io_op *write_op;
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

			struct gateway_op *message = message_queue_message_alloc_blocking(&worker_queue);
			message->operation = OP_WRITE_UART;
			message->message_txt = msg_txt;
			message->fd = fd;
			message_queue_write(&worker_queue, message);
		} else if (!strncmp(request, "HTTP", 4)) {
			char *msg_txt = request+4;

			struct gateway_op *message = message_queue_message_alloc_blocking(&worker_queue);
			message->operation = OP_WRITE_HTTP;
			message->message_txt = msg_txt;
			message->fd = fd;
			message_queue_write(&worker_queue, message);	
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

static void service_io_message_queue() {
	struct io_op *message;
	while(message = message_queue_tryread(&io_queue)) {
		uart_data[message->fd].state = UART_WRITING;
		uart_data[message->fd].write_op = message;
	}
}

static void handle_signal(int signal) {
}

int main(int argc, char *argv[]) {
	main_thread = pthread_self();
	signal(SIGUSR1, &handle_signal);
	signal(SIGPIPE, SIG_IGN);
	message_queue_init(&io_queue, sizeof(struct io_op), 128);
	
	threads_init();

	if (init_wiringPi() == -1) {
		printf("wirig pi failed\n");
		return -1;
	}

	int fd = open_uart();

	if (fd >=0 ) {
		while(1) {
			fd_set rfds, wfds;
			int max_fd, r;
			main_blocked = 1;
			__sync_synchronize();
			service_io_message_queue(); //main thread io_message queue
			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			max_fd = 0;
			FD_SET(fd, &rfds);

			for (int i = 0; i<FD_SETSIZE; ++i) {
				if (uart_data[i].state == UART_READING) {
					FD_SET(i, &rfds);
					max_fd = i;
				}
				else if (uart_data[i].state == UART_WRITING) {
					FD_SET(i, &wfds);
					max_fd = i;
				}
			}

			max_fd = fd > max_fd ? fd : max_fd;
			r = select(max_fd + 1, &rfds, &wfds, NULL, NULL);
			main_blocked = 0;
			__sync_synchronize();

			if (r < 0 && errno != EINTR) {
				perror("Error in select");
				return -1;
			}
			if (r > 0) {
				if (FD_ISSET(fd, &rfds)) {
						uart_data[fd].state = UART_READING;
						uart_data[fd].pos = 0;

						handle_uart_data(fd);
				}
			}
			service_io_message_queue();
		}
	} else {
		perror("Error listening on uart ");
	}
}


