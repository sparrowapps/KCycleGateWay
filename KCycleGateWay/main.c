/*
============================================================================
Name        : main.c
Author      : sparrow
Version     : 1.0
Date        : 2017.07.03
Copyright   : 
Description : 

main thread           : Serial read
worker thread pool    : Serial write / http write (http request)
socket receive thread : tcp listen
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
static void uart_write(int fd, const char *msg);
static void http_write(const char *msg);

// Message queue related code

#ifndef WORKER_THREADS
#define WORKER_THREADS 32
#endif

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

static pthread_t main_thread;
static pthread_t worker_threads[WORKER_THREADS];

static int main_blocked;

/*
worker thread 
uart write
http request
*/
static void *worker_threadproc(void *dummy) {
	while (1) {
		struct gateway_op *message = message_queue_read(&worker_queue);
		switch (message->operation) {
		case OP_WRITE_UART:
			uart_write( message->fd, message->message_txt );
			break;
		case OP_WRITE_HTTP:
			http_write(message->message_txt);
			break;
		case OP_EXIT:
			message_queue_message_free(&worker_queue, message);
			return NULL;
		}
		message_queue_message_free(&worker_queue, message);
	}
	return NULL;
}

static void threadpool_init() {
	message_queue_init(&worker_queue, sizeof(struct gateway_op), 512);
	for (int i = 0; i<WORKER_THREADS; ++i) {
		pthread_create(&worker_threads[i], NULL, &worker_threadproc, NULL);
	}
}

static void threadpool_destroy() {
	for (int i = 0; i<WORKER_THREADS; ++i) {
		struct gateway_op *poison = message_queue_message_alloc_blocking(&worker_queue);
		poison->operation = OP_EXIT;
		message_queue_write(&worker_queue, poison);
	}
	for (int i = 0; i<WORKER_THREADS; ++i) {
		pthread_join(worker_threads[i], NULL);
	}
	message_queue_destroy(&worker_queue);
}


static void wake_main_thread() {
	if (__sync_lock_test_and_set(&main_blocked, 0)) {
		pthread_kill(main_thread, SIGUSR1);
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
		if (uart_data[fd].pos >= 2 && 
			((uart_data[fd].buf + uart_data[fd].pos - 2) == 0x0D) &&
			((uart_data[fd].buf + uart_data[fd].pos - 1) == 0x0A)
			) 
		{
			uart_data[fd].buf[uart_data[fd].pos] = '\0';
			uart_data[fd].state = UART_INACTIVE;
			handle_uart_request(fd, uart_data[fd].buf);
			return;
		}
	}
	else {
		uart_data[fd].state = UART_INACTIVE;
		close(fd);
	}
}


static void handle_uart_request(int fd, char *request) {
	// parse and cmd process

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
	threadpool_init();
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
				}
				for (int i = 0; i<FD_SETSIZE; ++i) {
					if (i != fd && FD_ISSET(i, &rfds)) {
						handle_uart_data(i);
					}
					else if (i != fd && FD_ISSET(i, &wfds)) { // 시리얼 write
						int r = write(i, uart_data[i].write_op->buf + uart_data[i].write_op->pos, uart_data[i].write_op->len - uart_data[i].write_op->pos);
						if (r >= 0) {
							uart_data[i].write_op->pos += r;
							if (uart_data[i].write_op->pos == uart_data[i].write_op->len) {
								uart_data[i].state = UART_INACTIVE;
								if (uart_data[i].write_op->close_pending) {
									close(uart_data[i].write_op->rfd);
									close(i);
								}
								else {
									struct gateway_op *message = message_queue_message_alloc_blocking(&worker_queue);
									message->operation = OP_WRITE_UART;
									message->fd = i;
									message->rfd = uart_data[i].write_op->rfd;
									message_queue_write(&worker_queue, message);
								}
								message_queue_message_free(&io_queue, uart_data[i].write_op);
							}
						}
						else {
							close(uart_data[i].write_op->rfd);
							close(i);
							message_queue_message_free(&io_queue, uart_data[i].write_op);
							uart_data[i].state = UART_INACTIVE;
						}
					}
				}
			}

		}
	}
	
}


