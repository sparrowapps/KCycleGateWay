/*
============================================================================
Name        : main.c
Author      : sparrow
Version     : 1.0
Date        : 2017.07.03
Copyright   : 막 쓰세요~
Description : message_queue 를 이용한 worker thread pool 

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

// function prototype

// Message queue related code

#ifndef WORKER_THREADS
#define WORKER_THREADS 32
#endif

struct gateway_op {
	enum { OP_WRITE_UART, OP_WRITE_HTTP, OP_EXIT } operation;
	const char *message_txt; //전송 문자열
	int rfd, fd;
};

struct io_op {
	char buf[1024]; // 데이터 버퍼
	int len, pos; //길이, 포지션
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
			//generate_client_reply(message->fd, message->filename);
			break;
		case OP_WRITE_HTTP:
			//copy_data(message->rfd, message->fd);
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

// 메인스레드 깨우기
static void wake_main_thread() {
	if (__sync_lock_test_and_set(&main_blocked, 0)) {
		pthread_kill(main_thread, SIGUSR1);
	}
}

//MARK:  기능 함수

// uart write packet
int write_packet(int fd, unsigned char* pbuf, int size) {
	int wrtsize = 0;
	int it = 0;
	char msg[100] = { 0, };

	if (fd > 0) {
		do {
			wrtsize += write(fd, pbuf + wrtsize, size - wrtsize);
		} while ((size - wrtsize) > 0);

		for (it = 0; it < size; it++) {
			sprintf(msg, "%x ", *(pbuf + it));
		}

		printf("write packet fd(%d), size(%d), data = [%s] \n", fd, size, msg);

		return 0;
	}
	else {
		return -1;
	}
}

// ssl http write 
int ssl_write(unsigned char * msg, int size) {

	char buf[10000];
	int bytes;

	SSL_OPEN_TO_SERVER sslOpenToServer;

	if (SSLOpenToServer(&sslOpenToServer, "192.168.137.1", "8443") != SSL_OPEN_TO_SERVER_SUCCESS)
	{
		puts("SSLOpenToServer fail\n");
		return -1;
	}

	SSL_write(sslOpenToServer.ssl, msg, strlen(msg));
	BIO_dump_fp(stdout, msg, strlen(msg));

	bytes = SSL_read(sslOpenToServer.ssl, buf, sizeof(buf));
	buf[bytes] = 0;
	BIO_dump_fp(stdout, buf, bytes);

	SSLCloseToServer(&sslOpenToServer);

	return 0;
}


// MARK: uart data processing
struct uart_state {
	enum { UART_INACTIVE, UART_READING, UART_WRITING } state;
	char buf[1024];
	int pos;
	struct io_op *write_op;
};

struct uart_state uart_data[FD_SETSIZE];

static void handle_uart_data(int fd) {
	int r;
	if ((r = read(fd, uart_data[fd].buf + uart_data[fd].pos, 1024 - uart_data[fd].pos)) > 0) {
		uart_data[fd].pos += r;
		if (uart_data[fd].pos >= 4 && !strncmp(uart_data[fd].buf + uart_data[fd].pos - 4, "\r\n\r\n", 4)) {
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


// MARK: uart open 
static int get_uart_fd() {
	int uart_fd;

	do {
		uart_fd = uart_open();
		if (uart_fd < 0) {
			printf("UART open failed!\n");
		}
	} while (uart_fd < 0);

	return uart_fd;
}

// MARK: wiringPI
#define RST 9
#define PIO 7
static int init_wiringPi() {
	if (wiringPiSetup() == -1)
		return -1;

	pinMode(PIO, OUTPUT);
	pinMode(RST, OUTPUT);

	digitalWrite(PIO, 1);
	delay(100);
	digitalWrite(RST, 1);
	delay(1000);
	digitalWrite(RST, 0);
	printf("RST low.............\n");
	delay(1000);
	digitalWrite(RST, 1);
	printf("RST high.............\n");

	return 0;
}
