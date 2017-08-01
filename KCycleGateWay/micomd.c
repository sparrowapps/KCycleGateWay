 
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <termios.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "micomd.h"
#include "uart.h"
#include "wiringPi.h"
#include "ssltest.h"

#define RST 9
#define PIO 7

#define Expected_OutputMessage_LENGTH 32
#define CRL_AES192_KEY   24
#define CRL_AES_BLOCK     16
#define MAX_DEVICES       256

// common variables for threads
int uart_fd;
int fd_masks[MAX_SOCKET_FD];
int cnt_fd_socket = 0;
int init_flag = 0;
int ap_init_flag = 1;
int mcu_init_flag = 0;
int ipc1_flag = 0;
int ipc_send_flag = 0;
int ipc_send_count = 0;
int ipc_send_wait = 0;
int ssl_send_flag = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

BYTE SockBuffer[MAX_PACKET_BUFFER];
BYTE MicomBuffer[MAX_PACKET_BUFFER];
BYTE Sock1TempBuf[MAX_SOCKET_FD][MAX_PACKET_BUFFER];
BYTE TempMsgBuf[MAX_PACKET_BUFFER];
int sock1_cnt[MAX_SOCKET_FD];

int cmd_id = 0;
int cmd_state = -1;
int list_end = 0;
int op_mode = 0;
int packet_size = 0;
BYTE grp_id[3] = {0, 0, 0};
BYTE dev_id[3] = {0, 0, 0};
int rf_band = -1;
int mod_address = -1;
int rf_channel = -1;
int bcst_status = 0;
int data_rate = -1;
int rand_channel = -1;
int pair_status = 0;
int data_status = 0;
int rst_status = 0;
int device_idx = 0;

typedef struct list_id {
    BYTE dev_addr;
    BYTE dev_id[3];
} list;

list devices[MAX_DEVICES];

#if 1
#define PLAINTEXT_LENGTH 64
unsigned char Plaintext[PLAINTEXT_LENGTH] =
{
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
#else
#define PLAINTEXT_LENGTH 8
unsigned char Plaintext[PLAINTEXT_LENGTH] =
{
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96
};
#endif
/* Key to be used for AES encryption/decryption */
unsigned char Key[CRL_AES192_KEY] =
{
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
};

/* Initialization Vector */
unsigned char IV[CRL_AES_BLOCK] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};


/* Buffer to store the output data */
unsigned char OutputMessage[PLAINTEXT_LENGTH];

/* Size of the output data */
DWORD OutputMessageLength = 0;

#if 1
unsigned char Expected_Ciphertext[PLAINTEXT_LENGTH + 16] =
{
    0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d,
    0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
    0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4,
    0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
    0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0,
    0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
    0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81,
    0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd,
    0x61, 0x2C, 0xCD, 0x79, 0x22, 0x4B, 0x35, 0x09,
    0x35, 0xD4, 0x5D, 0xD6, 0xA9, 0x8F, 0x81, 0x76,
};
#endif

unsigned char Expected_OutputMessage[] =
{
  0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
  0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
  0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
  0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
};


BYTE cmd_buffer[MAX_CMD][MAX_PACKET_BUFFER] = 
{
    "++++\r\n",                        //  0
    "AT+ACODE=00 00 00 00\r\n",        //  1
    "AT+MMODE=1\r\n",                //  2
    "AT+GRP_ID=01 35 46\r\n",        //  3
    "AT+FBND=3\r\n",                //  4
    "AT+MADD=0\r\n",                //  5
    "AT+CHN=5\r\n",                    //  6
    "AT+BCST=1\r\n",                //  7
    "AT+DRATE=2\r\n",                //  8
    "AT+RNDCH=0\r\n",                //  9
    "AT+PAIR=1\r\n",                // 10
    "AT+ID?\r\n",                    // 11
    "AT+RST=1\r\n",                    // 12
    "AT+LST_ID?\r\n",                // 13
    "",
};

int add_socket(int fd)
{
    if(cnt_fd_socket < MAX_SOCKET_FD) {
        fd_masks[cnt_fd_socket] = fd;

        return ++cnt_fd_socket;
    } else {
        return -1;
    }
}


int del_socket(int fd)
{
    int i, flag;
    flag = 0;    /*     1:found, 0:not found    */
    close(fd);
    for(i = 0; i < cnt_fd_socket; i++) {
        if(fd_masks[i] == fd) {
            if(i != (cnt_fd_socket - 1)) {
                fd_masks[i] = fd_masks[cnt_fd_socket - 1];
            }
            fd_masks[cnt_fd_socket - 1] = -1;
            flag = 1;
            break;
        }
    }

    if(flag == 0) {
        return -1;
    }

    --cnt_fd_socket;

    return i;
}

int mk_fds(fd_set *fds, int fd_max)
{
    int i;

    //FD_ZERO(fds);

    for(i = 0; i < cnt_fd_socket; i++) {
        if(fd_max < fd_masks[i]) {
            fd_max = fd_masks[i];
        }
        //fd_max = MAX(fd_max, fd_mask[i]);
        FD_SET(fd_masks[i], fds);
    }

    return fd_max;
}


// a simple hex-print routine. could be modified to print 16 bytes-per-line
static void hex_print(const void* pv, size_t len)
{
    const unsigned char * p = (const unsigned char*)pv;
    if (NULL == pv)
        printf("NULL");
    else
    {
        size_t i = 0;
        for (; i<len;++i)
            printf("%02X ", *p++);
    }
    printf("\n");
}


// ============================================================================
//	openssl 의 ase 알고리즘 test를 위해 작성한 함수
//	아래에 작성된 것처럼 다음과 같은 순서를 따름
//	1. 구조체 선언 SSL_OPEN_TO_SERVER
//	2. SSLOpenToServer() 함수 호출
//	3. ssl read, write
//	4. SSLCloseToServer() 함수 호출
// ============================================================================
int ssl_test()
{
    char msg[1000] =
"GET /race_sche_Select HTTP/1.1\n\
Host: localhost:8443\n\
Connection: keep-alive\n\
Cache-Control: max-age=0\n\
Upgrade-Insecure-Requests: 1\n\
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n\
Accept-Encoding: gzip, deflate, sdch, br\n\
Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.6,en;q=0.4\n\
\n\n";
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

// ssl http write 
int ssl_write(unsigned char * msg, unsigned char * outmsg, int * outmsglen) {

    //char buf[10000];
    unsigned char * buf;
    int bytes = 0;

    SSL_OPEN_TO_SERVER sslOpenToServer;
    printf("ssl write \n");
    printf("ssl write ip : %s \n", HTTPS_IP_ADDR);
    if (SSLOpenToServer(&sslOpenToServer, HTTPS_IP_ADDR, HTTPS_PORT_NUM) != SSL_OPEN_TO_SERVER_SUCCESS)
    {
        puts("SSLOpenToServer fail\n");
        return -1;
    }
    printf("ssl write ip : %s \n", HTTPS_IP_ADDR);

    SSL_write(sslOpenToServer.ssl, msg, strlen(msg));
    BIO_dump_fp(stdout, msg, strlen(msg));

   

    buf = malloc(MAX_HTTPS_PACKET_BUFFER);

    bytes = SSL_read(sslOpenToServer.ssl, buf, sizeof(buf));
    buf[bytes] = 0;

    printf("\n response \n");
    BIO_dump_fp(stdout, buf, bytes);

    SSLCloseToServer(&sslOpenToServer);

    if (bytes != 0) { 
        outmsg = buf;
        outmsglen = bytes;
    } else {
        outmsg = NULL;
        outmsglen = 0;
    }

    return 0;
}

// MARK: wiringPI
int init_wiringPi() {
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

// MARK: uart open 
int open_uart() {
    int uart_fd;

    do {
        uart_fd = uart_open();
        if (uart_fd < 0) {
            printf("UART open failed!\n");
        }
    } while (uart_fd < 0);

    return uart_fd;
}


#if 0
int main (int argc, char *argv[])
{
    int maxfd;
    int state = 0;

    // UART communication variables
    //int uart_fd;
    int uart_cnt = 0;

    // select() variables
    struct timeval tv;
    fd_set readfds;

    // socket variables for the communication with App Framework
    int server_sockfd, client_sockfd = 0; 
    int client_len;

    struct sockaddr_in clientaddr;

    int idx_fd = 0;
    int ix = 0, i = 0;

    memset(SockBuffer, 0x00, MAX_PACKET_BUFFER);
    memset(MicomBuffer, 0x00, MAX_PACKET_BUFFER);
    for(ix = 0; ix < MAX_SOCKET_FD; ix++) {
        memset(Sock1TempBuf[ix], 0x00, MAX_PACKET_BUFFER);
        sock1_cnt[ix] = 0;
    }
    memset(TempMsgBuf, 0x00, MAX_PACKET_BUFFER);
    memset(fd_masks, -1, MAX_SOCKET_FD);
    memset(devices, 0, sizeof(devices));

    client_len = sizeof(clientaddr);

    if(wiringPiSetup() == -1)
        return -1;

    pinMode(PIO, OUTPUT);
    pinMode(RST, OUTPUT);

    memset(TempMsgBuf, 0x00, MAX_PACKET_BUFFER);

    // socket for App Framework
    server_sockfd = create_socket(PORT_NUM);

    // open UART serial port
    do {
        uart_fd = uart_open();
        if (uart_fd < 0) {
            printf("UART open failed!\n");
        }
    } while (uart_fd < 0);

    digitalWrite(PIO, 1);
    delay(100);
    digitalWrite(RST, 1);
    delay(1000);
    digitalWrite(RST, 0);
    printf("RST low.............\n");
    delay(1000);
    digitalWrite(RST, 1);
    printf("RST high.............\n");
    ipc_send_flag = 0;
#if 0
    unsigned char digest[SHA256_DIGEST_LENGTH];
    const char* string = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, string, strlen(string));
    SHA256_Final(digest, &ctx);

    char mdString[SHA256_DIGEST_LENGTH*2+1];
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

    printf("SHA256 digest   : %s\n", mdString);

    memset(mdString, 0, SHA256_DIGEST_LENGTH*2+1);
    for (i = 0; i < sizeof(Expected_OutputMessage); i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)Expected_OutputMessage[i]);

    printf("SHA256 expected : %s \n", mdString);

    // buffers for encryption and decryption
    //size_t encslength = ((PLAINTEXT_LENGTH + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char enc_out[1000];
    unsigned char dec_out[1000];
    unsigned char enc_temp[1000];
    memset(enc_out, 0, sizeof(enc_out));
    memset(dec_out, 0, sizeof(dec_out));
    memset(enc_temp, 0, sizeof(enc_temp));

    int encslength = encrypt_block(enc_out, Plaintext, PLAINTEXT_LENGTH, Key, IV);
    printf("encryption length = %d .............. \n", encslength);
    memcpy(enc_temp, enc_out, encslength);
    int decslength = decrypt_block(dec_out, enc_temp, encslength, Key, IV);
    printf("decryption length = %d .............. \n", decslength);

    printf("original:\t");
    hex_print(Plaintext, PLAINTEXT_LENGTH);

    printf("encrypt :\t");
    hex_print(enc_out, encslength);

    printf("expected:\t");
    hex_print(Expected_Ciphertext, PLAINTEXT_LENGTH);

    printf("decrypt:\t");
    hex_print(dec_out, decslength);
#endif

    while (1) {
        pthread_mutex_lock(&mutex);

        FD_ZERO(&readfds);
        if (server_sockfd) FD_SET(server_sockfd, &readfds);
        if (uart_fd) FD_SET(uart_fd, &readfds);
        maxfd = get_max_fd(server_sockfd, uart_fd, 0);
        maxfd = mk_fds(&readfds, maxfd);

        pthread_mutex_unlock(&mutex);

        // save select timeout
        tv.tv_sec = 0;
        tv.tv_usec = 500000;

        // wait fd event
        state = select(maxfd + 1, &readfds, (fd_set *)0, (fd_set *)0, &tv);

        switch (state) {
            case -1:
                printf("Select function error!\n");
                continue;

            case 0:
#if 1
                //printf("communicate with uart...[fd:%d, cmd_buffer[%d]: %s] send_flag = %d.... \n", uart_fd, strlen((char *)cmd_buffer[cmd_id]), (char *)cmd_buffer[cmd_id], ipc_send_flag);
                if(ipc_send_flag == 1) {
                    if(uart_fd > 0) {
                        printf("send to uart...[fd:%d, cmd_buffer[%d]: %s].... \n", uart_fd, strlen((char *)cmd_buffer[cmd_id]), (char *)cmd_buffer[cmd_id]);
                        write_packet(uart_fd, cmd_buffer[cmd_id], strlen((char *)cmd_buffer[cmd_id]));
                        cmd_state = cmd_id;
                        printf("communicate with uart...[fd:%d, fd count: %d].... \n", uart_fd, cnt_fd_socket);
                    } else {
                        printf("fail to communicate with uart...[fd:%d, fd count:%d].... \n", uart_fd, cnt_fd_socket);
                    }
                    ipc_send_flag = 0;
                } else {
                    ipc_send_wait = 0;
                }
#endif

                if(ssl_send_flag == 1) {
                    printf("send to https ssl...................\n");
                    ssl_test();
                    ssl_send_flag = 0;
                }
                continue;

            default:
                if (FD_ISSET(server_sockfd, &readfds)) {
                    // accept a connection on a socket
                    client_sockfd = accept(server_sockfd, (struct sockaddr *)&clientaddr, &client_len);

                    if (client_sockfd < 0) {
                        printf("Failed to accept the connection request from App Framework!\n");
                    } else {
                        //client_sockfd_flag = 1;
                        if(add_socket(client_sockfd) == -1) {
                            printf("Failed to add socket because of the number of socket(%d) !! \n", cnt_fd_socket);
                        } else {
                            //client_fd = client_sockfd;
                            printf("App Framework socket connected[fd = %d, cnt_fd = %d]!!!\n", client_sockfd, cnt_fd_socket);
                        }
                    }
                }
                if (FD_ISSET(uart_fd, &readfds))
                {
                    pthread_mutex_lock(&mutex);
                    uart_cnt = read_packet(uart_fd, uart_cnt, TempMsgBuf, UART);
                    ipc_send_wait = 0;
                    pthread_mutex_unlock(&mutex);

                    if(parse_data(TempMsgBuf, &uart_cnt) == 1)
                    {
                        printf("read from uart...[fd:%d, recv_buffer[%d:%d]: %s].... \n", uart_fd, uart_cnt, strlen((char *)TempMsgBuf), (char *)TempMsgBuf);

                        if(uart_cnt > 0 || (cmd_state == 13 && list_end == 1)) {
                            if(data_status == 0)
                            {
                                check_rf_data(TempMsgBuf);
                            }
                            else
                            {
                                check_uart (TempMsgBuf);
                            }
                            memset(TempMsgBuf, 0, sizeof(TempMsgBuf));
                            uart_cnt = 0;
                        }
                    }
                }
        }
    }

    for(idx_fd = 0; idx_fd < cnt_fd_socket; idx_fd++)
    {
        del_socket(fd_masks[idx_fd]);
    }

    close(server_sockfd);
    uart_close(uart_fd);

    printf("End of GateWay Daemon!\n");

    return 0;
}
#endif


int create_socket (int portnum)
{
    int fd;
    int state = 0;
    int nSockOpt = 1;
    struct sockaddr_in address;

    do {
        fd = socket(PF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            printf("Failed to create the server socket!\n");
        }
    } while (fd < 0);

    bzero(&address, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(SOCK_IP_ADDR);
    address.sin_port = htons(portnum);

    // prevent bind error
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &nSockOpt, sizeof(nSockOpt));

    do {
        state = bind(fd, (struct sockaddr *)&address, sizeof(address));
        if (state < 0) {
            printf("Bind error!\n");
        }
    } while (state < 0);

    do {
        state = listen(fd, 5);
        if (state < 0) {
            printf("Failed to set the ready state!\n");
        }
    } while (state < 0);

    return fd;
}

int read_packet (int fd, int cnt, PBYTE buf, int fd_index)
{
    int ret = 0;
    //int index = 0, it = 0;
    //char msg[256] = {0, };

    if(fd > 0) {
        do {
            ret = read(fd, &buf[cnt], MAX_PACKET_BYTE);
        } while (ret == -1);
        cnt += ret;
        //printf("read packet size = %d, cnt = %d, buf = %s\n", ret, cnt, buf);

        return cnt;
    } else {
        printf("read packet fd error.....[%d]    \n", fd);
        return -1;
    }
}

int check_socket (PBYTE data_buf, WORD size, int fd)
{
    //int index;
    //BYTE chksum;
    //BYTE mask_field = 0;

    return 0;
}

int check_rf_data(PBYTE data_buf)
{
    int index = 0;

    if(memcmp(data_buf, AT_PAIR, 9) == 0)
    {
        printf("parse REG.START\n");
    }
    else if(memcmp(data_buf, TOKEN_TGT, 3) == 0)
    {
        printf("parse TGT\n");
    }
    else if(memcmp(data_buf, HEADER, 6) == 0 || memcmp(data_buf, AT_OK, 2) == 0)
    {
        char* token = NULL;
        char div[] = ",:\r\n";

        pair_status = 1;

        token = strtok((char *)data_buf, div);
        while(token != NULL)
        {
            printf("token = %s\n", token);
            if(strcmp(token, AT_OK) == 0)
            {
                printf("parse OK\n");
                cmd_state = 19;
            }
            else if(strcmp(token, TOKEN_BAND) == 0)
            {
                index = 1;
            }
            else if(strcmp(token, TOKEN_CHN) == 0)
            {
                index = 2;
            }
            else if(strcmp(token, TOKEN_DRATE) == 0)
            {
                index = 3;
            }
            else if(strcmp(token, TOKEN_MODE) == 0)
            {
                index = 4;
            }
            else if(strcmp(token, TOKEN_UNPAIR) == 0)
            {
                pair_status = 0;
            }
            else
            {
                if(index == 1)
                {
                    rf_band = atoi(token);
                }
                else if(index == 2)
                {
                    rf_channel = atoi(token);
                }
                else if(index == 3)
                {
                    data_rate = atoi(token);
                }
                else if(index == 4)
                {
                    op_mode = atoi(token);
                    index = 5;
                }
            }
            token = strtok(NULL, div);
        }

        if(op_mode != 1 || pair_status != 1)
        {
            cmd_id = 0;
            ipc_send_flag = 1;
            data_status = 1;
            printf("send_message = %s , send_flag = %d\n", cmd_buffer[0], ipc_send_flag);
        }
        else if(rst_status == 1)
        {
            ipc_send_flag = 0;
            rst_status = 0;
            data_status = 0;
            printf("data receiving status................\n");
        }
        else
        {
            cmd_id = 0;
            ipc_send_flag = 1;
            data_status = 1;
            printf("send message[%s] in pairing status.....\n", cmd_buffer[0]);
        }
    }
    else
    {
        char* token = NULL;
        char div[] = ",\r\n";
        int check_addr = 0, addr = 0;

        token = strtok((char *)data_buf, div);
        while(token != NULL)
        {
            printf("token = %s\n", token);
            if(check_addr == 0)
            {
                addr = atoi(token);
                check_addr = 1;
            }
            else if(memcmp(token, PING_CHECK, 4) == 0)
            {
                cmd_id = 14;
                sprintf(cmd_buffer[14], "%d,ping\r\n", addr);
                ipc_send_flag = 1;
            }
            else
            {
                rf_data_parser(data_buf);
                cmd_id = 19;
                ipc_send_flag = 0;
                ssl_send_flag = 1;
            }

            token = strtok(NULL, div);
        }
    }

    return 0;
}

int check_uart (PBYTE data_buf)
{
    int index = 0;

    if(memcmp(data_buf, HEADER, 6) == 0)
    {
        char* token = NULL;
        char div[] = ",:\r\n";

        pair_status = 1;

        token = strtok((char *)data_buf, div);
        while(token != NULL)
        {
            printf("token = %s\n", token);
            if(strcmp(token, TOKEN_BAND) == 0)
            {
                index = 1;
            }
            else if(strcmp(token, TOKEN_CHN) == 0)
            {
                index = 2;
            }
            else if(strcmp(token, TOKEN_DRATE) == 0)
            {
                index = 3;
            }
            else if(strcmp(token, TOKEN_MODE) == 0)
            {
                index = 4;
            }
            else if(strcmp(token, TOKEN_UNPAIR) == 0)
            {
                pair_status = 0;
            }
            else
            {
                if(index == 1)
                {
                    rf_band = atoi(token);
                }
                else if(index == 2)
                {
                    rf_channel = atoi(token);
                }
                else if(index == 3)
                {
                    data_rate = atoi(token);
                }
                else if(index == 4)
                {
                    op_mode = atoi(token);
                    index = 5;
                }
            }
            token = strtok(NULL, div);
        }

        if(op_mode != 1 || pair_status != 1)
        {
            cmd_id = 0;
            ipc_send_flag = 1;
            printf("send_message = %s , send_flag = %d\n", cmd_buffer[0], ipc_send_flag);
        }
        else if(rst_status == 1)
        {
            ipc_send_flag = 0;
            rst_status = 0;
            data_status = 0;
            printf("data receiving status................\n");
        }
        else
        {
            cmd_id = 0;
            ipc_send_flag = 1;
            printf("send message[%s] in pairing status.....\n", cmd_buffer[0]);
        }
    }
    else if(memcmp(data_buf, AT_ST_HEADER, 8) == 0)
    {
        cmd_id = 1;
        data_status = 1;
        ipc_send_flag = 1;
    }
    else if(memcmp(data_buf, AT_LOCKED, 6) == 0)
    {
        cmd_id = 1;
        ipc_send_flag = 1;
    }
    else if(memcmp(data_buf, AT_PAIR, 9) == 0)
    {
        cmd_id = 19;
        cmd_state = 19;
        ipc_send_flag = 0;
    }
    else if(memcmp(data_buf, AT_REG_FAIL, 8) == 0)
    {
        cmd_id = 19;
        cmd_state = 19;
        ipc_send_flag = 0;
        pair_status = 0;
    }
    else if(memcmp(data_buf, AT_REG_OK, 6) == 0)
    {
        cmd_id = 19;
        cmd_state = 19;
        ipc_send_flag = 0;
        pair_status = 1;
    }
    else if(memcmp(data_buf, AT_OK, 2) == 0)
    {
        switch(cmd_state)
        {
            case 1:
#if 1
                if(pair_status == 1)
                {
                    cmd_id = 13;
                    ipc_send_flag = 1;
                    device_idx = 0;
                    //rst_status = 1;
                }
                else
#endif
                {
                    cmd_id = 2;
                    ipc_send_flag = 1;
                }
                break;

            case 2:
                op_mode = 1;
#if 0
                if(pair_status == 1)
                {
                    cmd_id = 13;
                    ipc_send_flag = 1;
                    device_idx = 0;
                    //rst_status = 1;
                }
                else
#endif
                {
                    cmd_id = 4;
                    ipc_send_flag = 1;
                }
                break;

            case 3:
                grp_id[0] = 0x01;
                grp_id[1] = 0x35;
                grp_id[2] = 0x46;
                cmd_id = 4;
                ipc_send_flag = 1;
                break;

            case 4:
                rf_band = 3;
                cmd_id = 5;
                ipc_send_flag = 1;
                break;

            case 5:
                mod_address = 0;
                cmd_id = 6;
                ipc_send_flag = 1;
                break;

            case 6:
                rf_channel = 5;
                cmd_id = 7;
                ipc_send_flag = 1;
                break;

            case 7:
                bcst_status = 1;
                cmd_id = 8;
                ipc_send_flag = 1;
                break;

            case 8:
                data_rate = 2;
                cmd_id = 9;
                ipc_send_flag = 1;
                break;

            case 9:
                rand_channel = 0;
                cmd_id = 11;
                ipc_send_flag = 1;
                break;

            case 10:
                cmd_id = 19;
                cmd_state = 19;
                ipc_send_flag = 0;
                pair_status = 1;
                break;

            case 11:
                {
                    int i = 0;

                    for(i = 0; i < 3; i++)
                    {
                        hex_decode((char *)(data_buf + 3*i), 1, &dev_id[i]);

                        printf("device_id[%d] = %x  \n", i, dev_id[i]);
                    }
                    cmd_id = 10;
                    ipc_send_flag = 1;
                }
                break;

            default:
                ipc_send_flag = 0;
                break;
        }
    }
    else if(cmd_state == 11)
    {
        int i = 0;
        
        for(i = 0; i < 3; i++)
        {
            hex_decode((char *)(data_buf + 3*i), 1, &dev_id[i]);
        
            printf("device_id[%d] = %x    \n", i, dev_id[i]);
        }
        cmd_id = 10;
        ipc_send_flag = 1;
    }
    else if(cmd_state == 13)
    {
        char* token = NULL;
        char div[] = ",\r\n";

        token = strtok((char *)data_buf, div);
        while(token != NULL)
        {
            printf("token = %s   strlen = %d \n", token, strlen(token));

            if(strlen(token) >= 1 && strlen(token) < 4)
            {
                devices[device_idx].dev_addr = atoi(token);
            }
            else if(strlen(token) >= 4)
            {
                int i = 0;

                for(i = 0; i < 3; i++)
                {
                    hex_decode((char *)(token + 3*i), 1, &devices[device_idx].dev_id[i]);
                    printf("device_id[%d] = %x    \n", i, devices[device_idx].dev_id[i]);
                }
                device_idx++;
            }
            token = strtok(NULL, div);
        }

        if(list_end == 1)
        {
            int it = 0;
            printf("======   list in devices[%d]   ======\n", device_idx);
            for(it = 0; it < device_idx; it++)
            {
                printf("device[%d] addr = %d, id = [%x %x %x]\n", it, devices[it].dev_addr, devices[it].dev_id[0], devices[it].dev_id[1], devices[it].dev_id[2]);
            }

            cmd_id = 12;
            rst_status = 1;
            list_end = 0;
            data_status = 0;
            ipc_send_flag = 1;
        }
    }

    packet_size = strlen((char *)data_buf);

    return 0;
}

int rf_data_parser(PBYTE data_buf)
{

}

BYTE* hex_decode(char *in, int len, BYTE *out)
{
    unsigned int i, t, hn, ln;

    for (t = 0,i = 0; i < len; i+=2,++t) {

            hn = in[i] > '9' ? (in[i]|32) - 'a' + 10 : in[i] - '0';
            ln = in[i+1] > '9' ? (in[i+1]|32) - 'a' + 10 : in[i+1] - '0';

            out[t] = (hn << 4 ) | ln;
            printf("0x%x \n", out[t]);
    }
    return out;
}


int parse_data (PBYTE data_buf, int *cnt)
{
    int ix = 0, index = 0;

    if(data_buf[0] == 0x0D && data_buf[1] == 0x0A)
    {
        memmove(&data_buf[0], &data_buf[2], MAX_PACKET_BUFFER - 2);
        *cnt -= 2;
        if(list_end == 0 && cmd_state == 13)
        {
            list_end = 1;
            return 1;
        }
    }

    for(ix = 0; ix < *cnt; ix++)
    {
        if(data_buf[ix] == 0x0A)
            index++;
    }

    //printf("parse_data ===> cmd_state[%d], index[%d]\n", cmd_state, index);
    if(cmd_state != -1 && cmd_state != 0)
    {
        if(cmd_state == 12)
        {
            if(index >= 3)
            {
                printf("parse_data ===> cmd_state[%d], index[%d]\n", cmd_state, index);
                return 1;
            }
            else
                return 0;
        }
        else
        {
            if(index == 1)
            {
                printf("parse_data ===> cmd_state[%d], index[%d]\n", cmd_state, index);
                return 1;
            }
            else
                return 0;
        }
    }
    else
    {
        if(cmd_state == -1)
        {
            if(index >= 3)
            {
                printf("parse_data ===> cmd_state[%d], index[%d]\n", cmd_state, index);
                return 1;
            }
            else
                return 0;
        }
        else
        {
            if(memcmp(data_buf, AT_ST_HEADER, 8) == 0)
            {
                printf("parse_data ===> cmd_state[%d], index[%d]\n", cmd_state, index);
                return 1;
            }
            else
                return 0;
        }
    }
}

int get_max_fd (int a, int b, int c) {
    int list[NUM_FD], temp, x, y;
    list[0] = a, list[1] = b, list[2] = c;

    // Bubble sort method
    for(x = 0; x < NUM_FD ; x++) {
        for(y = 0; y < (NUM_FD-1); y++) {
            if(list[y] > list[y+1]) {
                temp = list[y+1];
                list[y+1] = list[y];
                list[y] = temp;
            }
        }
    }
    return list[NUM_FD-1];
}


int write_packet (int fd, PBYTE pbuf, int size) {
    int wrtsize = 0;
    int it = 0;
    char msg[100] = {0, };

    if(fd > 0) {
        do {
            wrtsize += write(fd, pbuf+wrtsize, size-wrtsize);
        } while ((size - wrtsize) > 0);

        for(it = 0; it < size; it++) {
            sprintf(msg, "%x ", *(pbuf + it));
        }

        printf("write packet fd(%d), size(%d), data = [%s] \n", fd, size, msg);

        return 0;
    } else {
        return -1;
    }
}

// extract the normal packet after the packet error
int extract_packet (int cnt, PBYTE buf)
{
#if 0
    int index;
    int temp_index;
    int temp_cnt = 0;
    int flag = 0;

    for (index = 1; index < cnt; index++) {
        if (buf[index] == HEADER) {
            temp_cnt = index;
            memmove(&buf[0], &buf[temp_cnt], cnt - temp_cnt);

            cnt -= temp_cnt;
            flag = 1;
            break;
        }
    }
    if (flag == 0) {
        cnt = 0;
    }
#endif
    return cnt;
}

/* AES Encrypt Process */
int encrypt_block(unsigned char* cipherText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key, unsigned char* ivec)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int addLen=0, orgLen=0;
    unsigned long err=0;

    ERR_load_crypto_strings();
    EVP_CIPHER_CTX_init(ctx);
    printf("EVP_CIPHER_CTX_init() ---------------\n");

    if (EVP_EncryptInit(ctx, EVP_aes_192_cbc(), key, ivec) != 1) {
        err = ERR_get_error();
        printf("ERR: EVP_EncryptInit() - %s\n", ERR_error_string (err, NULL));
        return -1;
    }
    printf("EVP_EncryptInit() ---------------\n");
    if (EVP_EncryptUpdate(ctx, cipherText, &orgLen, plainText, plainTextLen) != 1) {
        err = ERR_get_error();
        printf("ERR: EVP_EncryptUpdate() - %s\n", ERR_error_string (err, NULL));

        return -1;
    }
    printf("EVP_EncryptUpdate() ---------------\n");

    if (EVP_EncryptFinal(ctx, cipherText+orgLen, &addLen) != 1) {
        err = ERR_get_error();
        printf("ERR: EVP_EncryptFinal() - %s\n", ERR_error_string (err, NULL));
        return -1;
    }
    printf("EVP_EncryptFinal() ---------------\n");
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    ERR_free_strings();
    return addLen + orgLen;
}

/* AES Decrypt Process */
int decrypt_block(unsigned char* plainText, unsigned char* cipherText, unsigned int cipherTextLen, unsigned char* key, unsigned char *ivec)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned long err=0;
    int toLen=0, outLen=0;

    ERR_load_crypto_strings();
    EVP_CIPHER_CTX_init(ctx);

    if (EVP_DecryptInit(ctx, EVP_aes_192_cbc(), key, ivec) != 1) {
        err = ERR_get_error();
        printf("ERR: EVP_DecryptInit() - %s\n", ERR_error_string (err, NULL));
        return -1;
    }
    if (EVP_DecryptUpdate(ctx, plainText, &toLen, cipherText, cipherTextLen) != 1) {
        err = ERR_get_error();
        printf("ERR: EVP_DecryptUpdate() - %s\n", ERR_error_string (err, NULL));

        return -1;
    }

    if (EVP_DecryptFinal(ctx, &plainText[cipherTextLen], &outLen) != 1) {
        err = ERR_get_error();
        printf("ERR: EVP_DecryptFinal() - %s\n", ERR_error_string (err, NULL));

        return -1;
    }

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    ERR_free_strings();

    return toLen+outLen;
}

