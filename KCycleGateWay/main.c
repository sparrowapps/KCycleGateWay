/*
============================================================================
Name        : main.c
Author      : sparrow
Version     : 1.0
Date        : 2017.07.03
Copyright   : 
Description : 

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
#include "main.h"
#include "logger.h"
#include "base64.h"
#include <jansson.h>
#include <netinet/tcp.h>
#include "crc.h"
// function prototype
static void handle_uart_data(int fd);
static void handle_uart_request(int fd, char *request);
static void handle_socket_data(int fd);
static void handle_socket_request(int fd, char *request);
static void uart_write(int fd, char *msg);
static void http_write( char *msg, int fd, int modem_addr);
static json_t *load_json(const char *jason);
static char * from_json(const char * json, char * key);
static int getBase64DecodeSize(char * base64encode);


static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

// Message queue related code
struct gateway_op {
    enum { OP_WRITE_UART, OP_WRITE_HTTP, OP_READ_SOCKET, OP_READ_UART, OP_EXIT } operation;
    char *message_txt; //
    int socketfd;  //소켓 클라이언트
    int uartfd;    //uart
    int addr; // 모뎀 어드레스 
    int cnt;
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

static int SSLCMD = 0;

static int uart_fd = 0;

char * ssl_server_ip = NULL;

static void *uart_write_threadproc(void *dummy) {
    LOG_DEBUG("uart_write_threadproc start\n");
    while (1) {
        struct gateway_op *message = message_queue_read(&uart_w_queue);

        if ( message->operation == OP_WRITE_UART ) {
            LOG_DEBUG("OP_WRITE_UART : %s",message->message_txt);
            uart_write( uart_fd, message->message_txt );
            free((void *)message->message_txt);
            message_queue_message_free(&uart_w_queue, message);
        } else if ( message->operation == OP_EXIT ) {
            message_queue_message_free(&uart_w_queue, message);
            return NULL;
        }
    }
    return NULL;
}

static void *http_write_threadproc(void *dummy) {
    LOG_DEBUG("http_write_threadproc start\n");
    while (1) {
        struct gateway_op *message = message_queue_read(&https_queue);
        if ( message->operation == OP_WRITE_HTTP ) { 
            
            http_write( message->message_txt , message->uartfd, message->addr);
            free((void *)message->message_txt);
            message_queue_message_free(&https_queue, message);
        } else if ( message->operation == OP_EXIT ) {
            message_queue_message_free(&https_queue, message);
            return NULL;
        }
    }
    return NULL;
}

static void *socket_read_threadproc(void *dummy) {
    LOG_DEBUG("socket_read_threadproc start\n");
    while (1)  {
        struct gateway_op *message = message_queue_read(&socket_queue);
        if (message->operation == OP_READ_SOCKET ) {

            handle_socket_data(message->socketfd);
            message_queue_message_free(&socket_queue, message);
        } else if ( message->operation == OP_EXIT ) {
            message_queue_message_free(&socket_queue, message);
            return NULL;
        }
    }
    return NULL;
}

static void *uart_read_threadproc(void *dummy) {
    LOG_DEBUG("uart_read_threadproc start\n");
    while(1) {
        struct gateway_op *message = message_queue_read(&uart_r_queue);
        if (message->operation == OP_READ_UART ) {
            LOG_DEBUG("uart_ queue read : cnt %d", message->cnt);
            handle_uart_data(message->uartfd);
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

    LOG_DEBUG("thread uart_write_thread join....\n");
    pthread_join(uart_write_thread, NULL);
    LOG_DEBUG("thread uart_read_thread join....\n");
    pthread_join(uart_read_thread, NULL);
    LOG_DEBUG("thread http_write_thread join....\n");
    pthread_join(http_write_thread, NULL);
    LOG_DEBUG("thread socket_read_thread join....\n");
    pthread_join(socket_read_thread, NULL);

    LOG_DEBUG("thread uart_r_queue destry....\n");
    message_queue_destroy(&uart_r_queue);
    LOG_DEBUG("thread uart_w_queue destry....\n");
    message_queue_destroy(&uart_w_queue);
    LOG_DEBUG("thread https_queue destry....\n");
    message_queue_destroy(&https_queue);
    LOG_DEBUG("thread socket_queue destry....\n");
    message_queue_destroy(&socket_queue);

    LOG_DEBUG("threads_destroyed \n");
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

    LOG_DEBUG("handle_socket_data fd %d ", fd);


    if((r = read(fd, socket_data[fd].buf+socket_data[fd].pos, 1024-socket_data[fd].pos)) > 0) {
        LOG_DEBUG("handle_socket_data %s\n",socket_data[fd].buf);
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

        pthread_mutex_lock(&mutex);
        del_socket(fd);
        pthread_mutex_unlock(&mutex);
    }
}

// 소켓 리케스트 처리
// 패턴2 서버에서 소켓으로 먼저 리퀘스트가 올때 whatIsMyjob ssl 전송을 해야 한다.
static void handle_socket_request(int fd, char *request) {
    unsigned char sslUrlBuf[40] = {0, };
    if (!strncmp(request, "YouHaveAJob", strlen("YouHaveAJob"))) {
        char * code = strstr(request, "YouHaveAJob") + strlen("YouHaveAJob");
        LOG_DEBUG("%s\n", request);

        int flag = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
        write(fd,"OK\r\n",4); //ok 응답

        //소켓 제거
        pthread_mutex_lock(&mutex);
        del_socket(fd);
        pthread_mutex_unlock(&mutex);

        sprintf(sslUrlBuf,"/gateway/whatIsMyJob?%s", code);
        LOG_DEBUG("%s\n", sslUrlBuf);
        SSLServerSend(sslUrlBuf, NULL, 0, -1);

    } else {
        pthread_mutex_lock(&mutex);
        del_socket(fd);
        pthread_mutex_unlock(&mutex);
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
// read_packet() 함수를 사용 하지 않는다
static void handle_uart_data(int fd) {
    int r;

    LOG_DEBUG("handle_uart_data");

    if((r = read(fd, uart_data[fd].buf + uart_data[fd].pos, MAX_PACKET_BYTE)) > 0) {
        
        uart_data[fd].pos += r;

        if (uart_data[fd].pos > MAX_PACKET_BYTE) { // wrong packet 
            uart_data[fd].pos = 0;
            memset(uart_data[fd].buf, 0x00, sizeof (uart_data[fd].buf));
            LOG_DEBUG("handle_uart_data wrong packet");
            return;
        }

        if(uart_data[fd].pos >= 2 ) {
            uart_data[fd].buf[uart_data[fd].pos] = '\0';
            uart_data[fd].state = UART_INACTIVE;
            // 수신데이터 처리
            handle_uart_request(fd, uart_data[fd].buf);
            return;
        }
    } else {
        uart_data[fd].state = UART_INACTIVE;
        LOG_DEBUG("handle_uart_data read error %d", r);
    }
}

static void handle_uart_request(int fd, char *request) {
    // parse and cmd process
    
    int uart_cnt = uart_data[fd].pos;

    LOG_DEBUG("handle_uart_request ");
    
    if (parse_data(request , &uart_cnt) == 1) {
        LOG_DEBUG("PARSE OK :");printf("%s\n",request);
        BIO_dump_fp(stdout, request, strlen(request));

        if (uart_cnt >0  || (get_cmd_state() == _AT_LST_ID && get_list_end() == 1) ) {
            if ( data_mode  == _DATA_RF_MODE) {
                check_rf_data(request);
            } else {
                check_uart(request);
            }
        }

        uart_data[fd].pos = 0;
        memset(uart_data[fd].buf, 0x00, sizeof (uart_data[fd].buf));
    } else {
        return;
    }
}

static void uart_write(int fd,  char *msg) {
    int r = write_packet(fd, msg, strlen(msg));
}


// JSON 문자열을 받아서 전역변수 racer_addr[] 배열을 구축 한다.
static void make_racer_addr(char * jason_str)
{
    json_t *root;
    json_error_t error;
    json_t *devicelist;
    root = json_loads(jason_str, 0, &error);
    devicelist = json_object_get(root, "DeviceList");
    racer_count = json_array_size(devicelist);
    LOG_DEBUG("cmd raceStart : racer count %d", racer_count);
    for (int i = 0; i < racer_count; i++)
    {
        json_t *data, *dev_id;
        const char * dev_id_str;

        char decode_dev_id[10] = {0,};
        data = json_array_get(devicelist, i);
        if(!json_is_object(data))
        {
            LOG_DEBUG("error: commit data %d is not an object\n", (int)(i + 1));
            json_decref(root);
        }

        dev_id = json_object_get(data, "DEV_ID");
        if(!json_is_string(dev_id))
        {
            LOG_DEBUG("error: DEV_ID %d: DEV_ID is not a string\n", (int)(i + 1));
        }
        dev_id_str = json_string_value(dev_id);
        memset(decode_dev_id, 0x00, sizeof(decode_dev_id));
        base64_decode(dev_id_str, strlen(dev_id_str) , decode_dev_id);
        int addr = getAddrFromDevices(decode_dev_id);
        
        racer_addr[i] = addr; //레이스 참여 addr을 저장
        LOG_DEBUG("cmd raceStart : idx:%d addr:%d", i, addr);
    }
}

/*
    SSL write 후 응담을 uart로 쏴야 할경우 여기서 처리 해야 한다.
*/
static void http_write( char *msg, int fd, int modem_addr) {
    int outmsglen = 0;

    unsigned char * outmsg = NULL;
    unsigned char * jason_str = NULL;
    
    int r = ssl_write( msg, &outmsg, &outmsglen );

    unsigned char base_decode[MAX_PACKET_BUFFER];
    unsigned char base_encode[MAX_PACKET_BUFFER];
    unsigned char outpacket[MAX_PACKET_BUFFER];
    memset(base_decode, 0x00, sizeof(base_decode));
    memset(base_encode, 0x00, sizeof(base_encode));
    memset(outpacket, 0x00, sizeof(base_encode));

    int outpacketlen = 0;

    //ssl 응답을 처리 하는 함수
    if (outmsg != NULL) {

        jason_str = strstr(outmsg, "\r\n\r\n") + 4;
        jason_str = strstr(jason_str, "\r\n") + 2;

        if ( strncmp(outmsg, "HTTP/1.1 200", strlen("HTTP/1.1 200") ) ) {
            LOG_DEBUG("http response ERROR !!");
            return; 
        }

        LOG_DEBUG("\nJSON STRING Bio_dump");
        BIO_dump_fp(stdout, jason_str, strlen(jason_str));

        char * res = from_json(jason_str, "Result");
        if (res == NULL)
            return;

        // whatIsMyJob 처리
        if (!strcmp(res, "whatIsMyJob")) { // 패턴2
            LOG_DEBUG("recevie : whatIsMyJob\n");
            ///gateway/whatIsMyJob 응답 처리 JobName으로 다시 분기 하여 처리 한다.            
            char * jobname = from_json(jason_str, "JobName");
            if (jobname == NULL)
                return;
            
            if (!strcmp(jobname, "Inspect IR")) {
                LOG_DEBUG("recJobNameevie : %s\n", jobname);
                char * value = from_json(jason_str, "DEV_ID");
                if (value == NULL)
                    return;

                base64_decode(value, strlen(value), base_decode); //디바이스 아이디
                
                LOG_DEBUG("base64_decode after\n");
                BIO_dump_fp(stdout, base_decode, getBase64DecodeSize(value));
                int addr = getAddrFromDevices(base_decode);
                LOG_DEBUG("addr %d\n",addr);
                // ir test 0x02
                unsigned char irvalue = 0x02;
                make_packet(PACKET_CMD_INSPECTION_REQ_S, 0x00, addr, 1, &irvalue, outpacket, &outpacketlen);
                base64_encode(outpacket, outpacketlen , base_encode);
                sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", addr, base_encode);
                LOG_DEBUG("cmd_buffer[_AT_USER_CMD] %s\n",cmd_buffer[_AT_USER_CMD]);
                request_uart_send(_AT_USER_CMD);
            } else if (!strcmp(jobname, "Inspect Wheel")) {
                LOG_DEBUG("recJobNameevie : %s\n", jobname);
                char * value = from_json(jason_str, "DEV_ID");
                if (value == NULL)
                    return;

                base64_decode(value, strlen(value), base_decode);

                int addr = getAddrFromDevices(base_decode);
                // wheel test 0x01
                unsigned char irvalue = 0x01;
                make_packet(PACKET_CMD_INSPECTION_REQ_S, 0x00, addr, 1, &irvalue, outpacket, &outpacketlen);
                base64_encode(outpacket, outpacketlen , base_encode);
                sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", addr, base_encode);
                request_uart_send(_AT_USER_CMD);
            } else if ( !strcmp(jobname, "pairingInfo1") || !strcmp(jobname, "pairingInfo2") || !strcmp(jobname, "pairingInfo3") )  { //pairingInfo
                /*
                GRP_ID : base64(3)
                CHN : 숫자값
                BAND : 숫자값
                DRATE : 숫자값
                COUNT : 숫자값
                PairingInfo : [
                    DEV_ID : base64(3) 
                    DEV_ADDR : 숫자값
                ]
                */
                json_t *root;
                json_error_t error;
                char  *grp_id;
                int chn;
                int band;
                int drate;
                int count;
                int host = 0; // 게이트웨이 번호
                char decode_grp_id[10] = {0,};

                json_t *pairinginfo;
                root = json_loads(jason_str, 0, &error);
                
                json_unpack(root, "{s:s, s:i, s:i, s:i, s:i, s:i }", 
                "GRP_ID", &grp_id, 
                "CHN", &chn, 
                "BAND", &band, 
                "DRATE", &drate, 
                "COUNT", &count,
                "HOST", &host 
                );
        
                LOG_DEBUG("GRP_ID : %s  :  %d", grp_id, strlen(grp_id));

                base64_decode(grp_id, strlen(grp_id) , decode_grp_id);

                LOG_DEBUG("GRP_ID : %02x %02x %02x", decode_grp_id[0], decode_grp_id[1], decode_grp_id[2]);
                LOG_DEBUG("CHN : %d", chn);
                LOG_DEBUG("BAND : %d", band);
                LOG_DEBUG("DRATE : %d", drate);
                LOG_DEBUG("COUNT : %d", count);
                LOG_DEBUG("HOST : %d", host);
                //AT command parameter update

                if ( !strcmp(jobname, "pairingInfo1") ) {
                    sprintf(cmd_buffer[_AT_GRP_ID], AT_GRP_ID_FMT, decode_grp_id[0], decode_grp_id[1], decode_grp_id[2]);
                    sprintf(cmd_buffer[_AT_CHN], AT_CHN_FMT,  chn);
                    sprintf(cmd_buffer[_AT_FBND], AT_FBAND_FMT, band);
                    sprintf(cmd_buffer[_AT_DRATE], AT_DRATE_FMT, drate);
                    sprintf(cmd_buffer[_AT_MADD], AT_MADD_FMT, host);
                    manaual_pairinig_status = _MANUAL_PAIRING_HOST;
                } else {
                    sprintf(cmd_buffer[_AT_GRP_ID], AT_GRPx_ID_FMT, host, decode_grp_id[0], decode_grp_id[1], decode_grp_id[2]);
                    sprintf(cmd_buffer[_AT_CHN], AT_xCHN_FMT, host, chn);
                    sprintf(cmd_buffer[_AT_FBND], AT_FxBAND_FMT,host, band);
                    sprintf(cmd_buffer[_AT_DRATE], AT_DxRATE_FMT,host, drate);
                    manaual_pairinig_status = _MANUAL_PAIRING_STATUS;
                }

                // command 
                LOG_DEBUG("[_AT_GRP_ID] : %s\n", cmd_buffer[_AT_GRP_ID]);
                LOG_DEBUG("[_AT_CHN] : %s\n", cmd_buffer[_AT_CHN]);
                LOG_DEBUG("[_AT_FBND] : %s\n", cmd_buffer[_AT_FBND]);
                LOG_DEBUG("[_AT_DRATE] : %s\n", cmd_buffer[_AT_DRATE]);
                
                // set_cmd_id( _AT_START ); // +++ 전송
                 // 메뉴얼 페어링 스테이터스
                data_mode = _DATA_AT_MODE;

                LOG_DEBUG("total pairing devices count : %d\n", count);
                
                devices_count = count;
                device_idx = 0;

                pairinginfo = json_object_get(root, "PairingInfo");

                for (int i = 0; i < json_array_size(pairinginfo); i++)
                {
                    json_t *data, *dev_id, *dev_addr;
                    const char * dev_id_str;
                    int dev_addr_val;
                    char decode_dev_id[10] = {0,};
                    data = json_array_get(pairinginfo, i);
                    if(!json_is_object(data))
                    {
                        LOG_DEBUG("error: commit data %d is not an object\n", (int)(i + 1));
                        json_decref(root);
                    }

                    dev_id = json_object_get(data, "DEV_ID");
                    if(!json_is_string(dev_id))
                    {
                        LOG_DEBUG("error: DEV_ID %d: DEV_ID is not a string\n", (int)(i + 1));
                    }
                    dev_id_str = json_string_value(dev_id);
                    memset(decode_dev_id, 0x00, sizeof(decode_dev_id));
                    base64_decode(dev_id_str, strlen(dev_id_str) , decode_dev_id);

                    dev_addr = json_object_get(data, "DEV_ADDR");
                    if(!json_is_integer(dev_addr))
                    {
                        LOG_DEBUG("error: DEV_ADDR %d: DEV_ADDR is not a integer\n", (int)(i + 1));
                    }
                    dev_addr_val = json_integer_value(dev_addr);
                    
                    devices[i].dev_id[0] = decode_dev_id[0];
                    devices[i].dev_id[1] = decode_dev_id[1];
                    devices[i].dev_id[2] = decode_dev_id[2];
                    devices[i].dev_addr  = dev_addr_val;

                    LOG_DEBUG("devices[%d] dev_id[%02x, %02x, %02x, dev_addr: %d"
                    ,i,
                    devices[i].dev_id[0],
                    devices[i].dev_id[1],
                    devices[i].dev_id[2],
                    devices[i].dev_addr );
                }
                request_uart_send(_AT_START);

                //페어링 정보 어레이를 jansson  해석을 한다음 AT+CMD로 페어링 정보를 쏴야 한다.
            }else if (!strcmp(jobname, "pairingList")) {
                json_t *root;
                json_error_t error;
                char  *grp_id;

                json_t *pairinginfo;
                root = json_loads(jason_str, 0, &error);
                
                pairinginfo = json_object_get(root, "PairingList");

                for (int i = 0; i < json_array_size(pairinginfo); i++)
                {
                    json_t *data, *dev_id, *dev_addr;
                    const char * dev_id_str;
                    int dev_addr_val;
                    char decode_dev_id[10] = {0,};
                    data = json_array_get(pairinginfo, i);
                    if(!json_is_object(data))
                    {
                        LOG_DEBUG("error: commit data %d is not an object\n", (int)(i + 1));
                        json_decref(root);
                    }

                    dev_id = json_object_get(data, "DEV_ID");
                    if(!json_is_string(dev_id))
                    {
                        LOG_DEBUG("error: DEV_ID %d: DEV_ID is not a string\n", (int)(i + 1));
                    }
                    dev_id_str = json_string_value(dev_id);
                    memset(decode_dev_id, 0x00, sizeof(decode_dev_id));
                    base64_decode(dev_id_str, strlen(dev_id_str) , decode_dev_id);

                    dev_addr = json_object_get(data, "DEV_ADDR");
                    if(!json_is_integer(dev_addr))
                    {
                        LOG_DEBUG("error: DEV_ADDR %d: DEV_ADDR is not a integer\n", (int)(i + 1));
                    }
                    dev_addr_val = json_integer_value(dev_addr);
                    
                    devices[i].dev_id[0] = decode_dev_id[0];
                    devices[i].dev_id[1] = decode_dev_id[1];
                    devices[i].dev_id[2] = decode_dev_id[2];
                    devices[i].dev_addr  = dev_addr_val;

                    LOG_DEBUG("devices[%d] dev_id[%02x, %02x, %02x, dev_addr: %d"
                    ,i,
                    devices[i].dev_id[0],
                    devices[i].dev_id[1],
                    devices[i].dev_id[2],
                    devices[i].dev_addr );
                }

                //전송 하지 않는다. 

            }else if (!strcmp(jobname, "deletePairingInfo")) {
                manaual_pairinig_status = _MANUAL_PAIRING_DELETE;
                
                // set_cmd_id( _AT_START ); // +++ 전송
                 // 메뉴얼 페어링 스테이터스
                data_mode = _DATA_AT_MODE;

                request_uart_send(_AT_START);

            } else if (!strcmp(jobname, "trainingStart")) {
                make_racer_addr(jason_str);
                
                char date_val[5];
                for (int i=0; i< racer_count; i++ ) {
                    make_date_data(date_val);
                    
                    make_packet(PACKET_CMD_TRAININGSTART_S, 0x00, racer_addr[i], 5, date_val, outpacket, &outpacketlen);
                    base64_encode(outpacket, outpacketlen , base_encode);
                    sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", racer_addr[i], base_encode);

                    request_uart_send(_AT_USER_CMD);
                }
                //위에서 이미 전송 했음

            } else if (!strcmp(jobname, "trainingStop")) {
                make_racer_addr(jason_str);

                for (int i=0; i< racer_count; i++ ) {
                    make_packet(PACKET_CMD_TRAININGSTOP_S, 0x00, racer_addr[i], 0, NULL, outpacket, &outpacketlen);
                    base64_encode(outpacket, outpacketlen , base_encode);
                    sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", racer_addr[i], base_encode);

                    request_uart_send(_AT_USER_CMD);
                }
                //위에서 이미 전송 했음
                
            } else if (!strcmp(jobname, "dashStart")) {

                make_racer_addr(jason_str);

                char date_val[5];
                for (int i=0; i< racer_count; i++ ) {
                    make_date_data(date_val);
                    
                    make_packet(PACKET_CMD_DASHSTART_S, 0x00, racer_addr[i], 5, date_val, outpacket, &outpacketlen);
                    base64_encode(outpacket, outpacketlen , base_encode);
                    sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", racer_addr[i], base_encode);

                    request_uart_send(_AT_USER_CMD);

                }
                //위에서 이미 전송 했음
                
            } else if (!strcmp(jobname, "dashStop")) {
                
                make_racer_addr(jason_str);

                char date_val[5];
                for (int i=0; i< racer_count; i++ ) {
                    make_date_data(date_val);
                    
                    make_packet(PACKET_CMD_DASHSTOP_S, 0x00, racer_addr[i], 5, date_val, outpacket, &outpacketlen);
                    base64_encode(outpacket, outpacketlen , base_encode);
                    sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", racer_addr[i], base_encode);

                    request_uart_send(_AT_USER_CMD);
                }
                //위에서 이미 전송 했음
                
                
            } else if (!strcmp(jobname, "raceStart")) {
                // 레이스 디바이스 리스트 확보
                make_racer_addr(jason_str);

                #if 0 //건이 없어서.. 걍 쏜다.
                    for (int i = 0; i< racer_count; i++ ) { // 경기 참여 디바이스에 RACE sTART 전송
                        memset(outpacket, 0x00, sizeof(outpacket));
                        memset(base_encode, 0x00, sizeof(base_encode));
                        outpacketlen = 0;

                        make_packet(PACKET_CMD_RACESTART_S, 0x00, racer_addr[i], 0, NULL, outpacket, &outpacketlen);
                        base64_encode(outpacket, outpacketlen , base_encode);
                        sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", racer_addr[i], base_encode);
                        LOG_DEBUG("cmd PACKET_CMD_RACESTART_GUN_R : cmdbuffer : %s", cmd_buffer[_AT_USER_CMD]);
                        
                        request_uart_send(_AT_USER_CMD);
                    }
                    
                #endif
            } else if (!strcmp(jobname, "raceStartGun")) { //테스트 건이 없어서
                // 레이스 디바이스 리스트 확보
                make_racer_addr(jason_str);
                LOG_DEBUG("RraceStartGun RACER COUNT : %d", racer_count);

                #if 1 //건이 없어서.. 걍 쏜다.
                for (int i = 0; i< racer_count; i++ ) { // 경기 참여 디바이스에 RACE sTART 전송
                    memset(outpacket, 0x00, sizeof(outpacket));
                    memset(base_encode, 0x00, sizeof(base_encode));
                    outpacketlen = 0;

                    make_packet(PACKET_CMD_RACESTART_S, 0x00, racer_addr[i], 0, NULL, outpacket, &outpacketlen);
                    base64_encode(outpacket, outpacketlen , base_encode);
                    sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", racer_addr[i], base_encode);
                    LOG_DEBUG("cmd PACKET_CMD_RACESTART_S : cmdbuffer : %s", cmd_buffer[_AT_USER_CMD]);
                    
                    request_uart_send(_AT_USER_CMD);
                }

                #endif
            } else if (!strcmp(jobname, "raceStop")) {
                
                make_racer_addr(jason_str);

                for (int i=0; i< racer_count; i++ ) {
                    //여기서 집접 모든 디바이스에 브로드 케스트 전송
                    make_packet(PACKET_CMD_RACESTOP_S, 0x00, racer_addr[i], 0, NULL, outpacket, &outpacketlen);
                    base64_encode(outpacket, outpacketlen , base_encode);
                    sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", racer_addr[i], base_encode);
    
                    request_uart_send(_AT_USER_CMD);
                }
                //위에서 이미 전송 했음

            } else if (!strcmp(jobname, "raceResultReady")) {
                char * value = from_json(jason_str, "DEV_ID");
                if (value == NULL)
                    return;

                base64_decode(value, strlen(value), base_decode);

                int addr = getAddrFromDevices(base_decode);

                make_packet(PACKET_CMD_RACERESULT_READY_S, 0x00, addr, 0, NULL, outpacket, &outpacketlen);
                base64_encode(outpacket, outpacketlen , base_encode);
                sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", addr, base_encode);

                request_uart_send(_AT_USER_CMD);
                //위에서 이미 전송 했음

            } else if (!strcmp(jobname, "raceCycleResultRequest")) {
                char * value = from_json(jason_str, "DEV_ID");
                if (value == NULL)
                    return;

                base64_decode(value, strlen(value), base_decode);
                int addr = getAddrFromDevices(base_decode);
                LOG_DEBUG("cmd raceCycleResultRequest : device_addr %d", addr);
                
                make_packet(PACKET_CMD_RACERESULT_REQ_S, 0x00, addr, 0, NULL, outpacket, &outpacketlen);
                base64_encode(outpacket, outpacketlen , base_encode);
                sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", addr, base_encode);
                request_uart_send(_AT_USER_CMD);
            } else if (!strcmp(jobname, "raceLineResultExtra")) {
                char * value = from_json(jason_str, "DEV_ID");
                if (value == NULL)
                    return;

                base64_decode(value, strlen(value), base_decode); //디바이스 아이디
                
                LOG_DEBUG("base64_decode after\n");
                BIO_dump_fp(stdout, base_decode, getBase64DecodeSize(value));
                int addr = getAddrFromDevices(base_decode);
                LOG_DEBUG("층 raceLineResultExtra: device_addr %d\n",addr);

                memset(base_decode, 0x00 , sizeof(base_decode));
                char * idexbytearray = from_json(jason_str, "INDEX");
                if (idexbytearray == NULL)
                    return;
                    
                base64_decode(idexbytearray, strlen(idexbytearray), base_decode); //누락 인덱스 바이트 어레이

                make_packet(PACKET_CMD_RACELINERESULT_EXTRA_S, 0x00, addr, getBase64DecodeSize(idexbytearray), base_decode, outpacket, &outpacketlen);
                base64_encode(outpacket, outpacketlen , base_encode);
                sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", addr, base_encode);
                LOG_DEBUG("cmd_buffer[_AT_USER_CMD] %s\n",cmd_buffer[_AT_USER_CMD]);
                request_uart_send(_AT_USER_CMD);
            } else if (!strcmp(jobname, "logRequest")) {
                char * value = from_json(jason_str, "DEV_ID");
                if (value == NULL)
                    return;

                base64_decode(value, strlen(value), base_decode); //디바이스 아이디
                
                LOG_DEBUG("base64_decode after\n");
                BIO_dump_fp(stdout, base_decode, getBase64DecodeSize(value));
                int addr = getAddrFromDevices(base_decode);
                LOG_DEBUG("cmd logRequest: device_addr %d\n",addr);

                memset(base_decode, 0x00 , sizeof(base_decode));
                char * index = from_json(jason_str, "Index"); // 1바이트 1 ~ 5
                if (index == NULL)
                    return;

                char indexChar = index[0] - 0x31;    

                make_packet(PACKET_CMD_LOG_REQ_S, 0x00, addr, 1, &indexChar, outpacket, &outpacketlen);
                base64_encode(outpacket, outpacketlen , base_encode);
                sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", addr, base_encode);
                LOG_DEBUG("cmd_buffer[_AT_USER_CMD] %s\n",cmd_buffer[_AT_USER_CMD]);
                request_uart_send(_AT_USER_CMD);
            } else if (!strcmp(jobname, "raceResultEnd")) {
                char * value = from_json(jason_str, "DEV_ID");
                if (value == NULL)
                    return;
                
                base64_decode(value, strlen(value), base_decode);
                int addr = getAddrFromDevices(base_decode);
                LOG_DEBUG("cmd raceResultEnd : device_addr %d", addr);
                
                make_packet(PACKET_CMD_RACERESULT_END_S, 0x00, addr, 0, NULL, outpacket, &outpacketlen);
                base64_encode(outpacket, outpacketlen , base_encode);
                sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", addr, base_encode);
                request_uart_send(_AT_USER_CMD);
            } else if (!strcmp(jobname, "irReferenceSet")) {
                char * value = from_json(jason_str, "DEV_ID");
                if (value == NULL)
                    return;
                
                base64_decode(value, strlen(value), base_decode); //디바이스 아이디
                
                LOG_DEBUG("base64_decode after\n");
                BIO_dump_fp(stdout, base_decode, getBase64DecodeSize(value));
                int addr = getAddrFromDevices(base_decode);
                LOG_DEBUG("cmd irReferenceSet: device_addr %d\n",addr);

                memset(base_decode, 0x00 , sizeof(base_decode));
                char * idexbytearray = from_json(jason_str, "IrReferenceSet");
                if (idexbytearray == NULL)
                    return;
                    
                base64_decode(idexbytearray, strlen(idexbytearray), base_decode); 

                make_packet(PACKET_CMD_IR_REF_SET_S, 0x00, addr, getBase64DecodeSize(idexbytearray), base_decode, outpacket, &outpacketlen);
                base64_encode(outpacket, outpacketlen , base_encode);
                sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", addr, base_encode);
                LOG_DEBUG("cmd_buffer[_AT_USER_CMD] %s\n",cmd_buffer[_AT_USER_CMD]);
                request_uart_send(_AT_USER_CMD);
            } else {
                // json 파싱 종료

            }

        } else if (strcmp(res, "inspectionRequest") == 0) { //패턴2
            // 응답 받고 처리 할께 없음
        } else if (strcmp(res, "tranningStart") == 0) { //패턴2
            // 응답 받고 처리 할께 없음
        } else if (strcmp(res, "tranningStop") == 0) { //패턴2
            // 응답 받고 처리 할께 없음
        } else if (strcmp(res, "dashStart") == 0) { //패턴2
            // 응답 받고 처리 할께 없음
        } else if (strcmp(res, "dashStop") == 0) { //패턴2
            // 응답 받고 처리 할께 없음
        } else if (strcmp(res, "raceStart") == 0) { //패턴2
            // 응답 받고 처리 할께 없음
        } else if (strcmp(res, "raceResultReady") == 0) { //패턴2
            // 응답 받고 처리 할께 없음
        }else if (strcmp(res, "logRequest") == 0) { //패턴2
            // 응답 받고 처리 할께 없음
            LOG_DEBUG("res logRequest");
        } else if (strcmp(res, "ping") == 0) {
            LOG_DEBUG("ping %s\n", res);
            char * value = from_json(jason_str, "Value");
            if (value == NULL)
                return;

            LOG_DEBUG("value %s\n", value);
            base64_decode(value, strlen(value), base_decode);
            LOG_DEBUG("value decode : %s\n", base_decode);
            
            make_packet(PACKET_CMD_PING_S, 0x00, modem_addr, getBase64DecodeSize(value), base_decode, outpacket, &outpacketlen);
            
            LOG_DEBUG("vbase64_encode");
            base64_encode(outpacket, outpacketlen , base_encode);

            sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", modem_addr, base_encode);
            LOG_DEBUG("cmd_buffer[_AT_USER_CMD],");
            request_uart_send(_AT_USER_CMD);
        } else if (strcmp(res, "inspectionResult") == 0) {
            
            make_packet(PACKET_CMD_INSPECTION_RES_S, 0x00, modem_addr,  0, NULL, outpacket, &outpacketlen);
            
            base64_encode(outpacket, outpacketlen , base_encode);

            sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", modem_addr, base_encode);
            request_uart_send(_AT_USER_CMD);
        } else if (strcmp(res, "encryptionKeyRequest") == 0) {
            char * value = from_json(jason_str, "Value");
            if (value == NULL)
                return;

            base64_decode(value, strlen(value), base_decode);

            make_packet(PACKET_CMD_ENCKEY_REQ_S, 0x00, modem_addr, getBase64DecodeSize(value), base_decode, outpacket, &outpacketlen);
            
            base64_encode(outpacket, outpacketlen , base_encode);

            sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", modem_addr, base_encode);

            //encrypt key update
            LOG_DEBUG("date + AES192 key\n");
            BIO_dump_fp(stdout, base_decode, getBase64DecodeSize(value));
            memcpy(Key, base_decode + 5, CRL_AES192_KEY); //24 byte key update
            request_uart_send(_AT_USER_CMD);
        } else if (strcmp(res, "logCheckMessage") == 0) {
            char * value = from_json(jason_str, "Value");
            if (value == NULL)
                return;

            base64_decode(value, strlen(value), base_decode);

            make_packet(PACKET_CMD_LOGCHK_S, 0x00, modem_addr, getBase64DecodeSize(value), base_decode, outpacket, &outpacketlen);
            
            base64_encode(outpacket, outpacketlen , base_encode);

            sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", modem_addr, base_encode);
            request_uart_send(_AT_USER_CMD);
        } else if (strcmp(res, "errorCheck") == 0) {
            int outpacketlen = 0;
            make_packet(PACKET_CMD_INSPECTION_RES_S, 0x00, modem_addr, 0, NULL, outpacket, &outpacketlen);
            
            base64_encode(outpacket, outpacketlen , base_encode);

            sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", modem_addr, base_encode);
            request_uart_send(_AT_USER_CMD);
        } else if (strcmp(res, "dashResult") == 0) {
            make_packet(PACKET_CMD_INSPECTION_RES_S, 0x00, modem_addr, 0, NULL, outpacket, &outpacketlen);
            
            base64_encode(outpacket, outpacketlen , base_encode);

            sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", modem_addr, base_encode);
            request_uart_send(_AT_USER_CMD);
        } else if (strcmp(res, "raceStateCheck") == 0) {
            char * value = from_json(jason_str, "Value");
            if (value == NULL)
                return;

            base64_decode(value, strlen(value), base_decode);

            make_packet(PACKET_CMD_RACESTATECHK_S, 0x00, modem_addr, getBase64DecodeSize(value), base_decode, outpacket, &outpacketlen);
            
            base64_encode(outpacket, outpacketlen , base_encode);

            sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", modem_addr, base_encode);
            request_uart_send(_AT_USER_CMD);
        } else if (strcmp(res, "raceLineResult") == 0) {
            // make_packet(PACKET_CMD_RACELINERESULT_S, 0x00, modem_addr, 0, NULL, outpacket, &outpacketlen);
            
            // base64_encode(outpacket, outpacketlen , base_encode);

            // sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", modem_addr, base_encode);

            // 응답 받고 처리 할께 없음
        } else if (strcmp(res, "raceEnd") == 0) { //레이스 종료 메세지 응답
            make_packet(PACKET_CMD_RACE_END_S, 0x00, modem_addr, 0, NULL, outpacket, &outpacketlen);
            
            base64_encode(outpacket, outpacketlen , base_encode);

            sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", modem_addr, base_encode);
            request_uart_send(_AT_USER_CMD);
        }else if (strcmp(res, "raceCycleResult") == 0) {
            // 응답 받고 처리 할께 없음
        } else {
            // json 파싱 종료
        }
        free(outmsg);
    }    
}

void init_uart_data() {
    for (int i = 0; i < FD_SETSIZE; i++) {
        uart_data[i].state = UART_INACTIVE;
    }
}

// JSON 만들기
char * make_json(char * dev_id, char * value) 
{
    json_t* root;
    char * str;

    if (value != NULL) {
        root  = json_pack("{s:s, s:s}", "DEV_ID", dev_id, "Value", value);
    } else {
        root  = json_pack("{s:s}", "DEV_ID", dev_id);
    }
    str = json_dumps(root, JSON_ENCODE_ANY);
    return str;
}

//JSON  문자열에서 value 얻기
json_t *load_json(const char *jason) {
    json_t *root;
    json_error_t error;

    root = json_loads(jason, 0, &error);

    if (root) {
        return root;
    } else {
        LOG_DEBUG("json error on line %d: %s\n", error.line, error.text);
        return (json_t *)NULL;
    }
}

char * from_json(const char * json, char * key)
{
    char * res;
    json_t * root = load_json(json);
    
    if (root != NULL ) {
        json_unpack(root, "{s:s}", key, &res);
        return res;
    } else {
        return NULL;
    }
}

/*
url , 전달 데이터를 주면 서버에 
SSL request JSON을 포함해서 전송 한다.
value 가 없을 경우 데이터 없이 전송 한다.
*/
void SSLServerSend(char *url, char *value, int valuelen, int modem_addr) {

    unsigned char * buf;
    unsigned char base_encode[MAX_HTTPS_PACKET_BUFFER];
    unsigned char base_dev_id[10];
    
    char *json;
    struct gateway_op *message = message_queue_message_alloc_blocking(&https_queue);
    message->operation = OP_WRITE_HTTP;
    buf = malloc(MAX_HTTPS_PACKET_BUFFER);

    // mode_addr to dev_id
    if(modem_addr != -1 ) {
        memset(base_dev_id, 0x00, sizeof(base_dev_id));
        //char * dev_id = getDevIDFromDevices(modem_addr); 
        int idx = getDevicesIndexFromAddr( modem_addr );

        if (devices[idx].dev_id[0] == 0 && devices[idx].dev_id[1] == 0 && devices[idx].dev_id[2] == 0 ) {
            BIO_dump_fp(stdout, (char *)devices, sizeof(devices));
        }

        base64_encode(devices[idx].dev_id, 3, base_dev_id);
        LOG_DEBUG("DEV_ID %x %x %x : DEV_ID base64 encode : %s : addr: %d", devices[idx].dev_id[0], devices[idx].dev_id[1], devices[idx].dev_id[2], base_dev_id, modem_addr);

        if (value != NULL) {
            memset(base_encode, 0x00, sizeof(base_encode));
            base64_encode(value, valuelen , base_encode);
            json = make_json(base_dev_id, base_encode);
        } else {
            json = make_json(base_dev_id, NULL);
        }
            
        if (ssl_server_ip == NULL) {
            sprintf(buf, HTTPS_HEADER, url,  HTTPS_IP_ADDR, HTTPS_PORT_NUM, strlen(json) + 100, json);
        } else {
            sprintf(buf, HTTPS_HEADER, url,  ssl_server_ip, HTTPS_PORT_NUM, strlen(json) + 100, json);
        }
    } else {
        if (ssl_server_ip == NULL) {
            sprintf(buf, HTTPS_HEADER, url,  HTTPS_IP_ADDR, HTTPS_PORT_NUM, 100, "");
        } else {
            sprintf(buf, HTTPS_HEADER, url,  ssl_server_ip, HTTPS_PORT_NUM, 100, "");
        }
    }
    message->message_txt = buf;
    message->addr = modem_addr; //모뎀 어드레스
    message_queue_write(&https_queue, message);
}

void loadPacketNumber()
{
    FILE *fp = NULL;
    
    fp = fopen( "gateway.pn", "r" );
    if( fp == NULL )
    {
        LOG_DEBUG("packet number file not found!");

        for(int i = 0; i < MAX_DEVICES; i++) {
            packetnumberArray[i] = 0;
        }
        gatewayPacketNumber = 0;
    }
    else
    {
        while( !feof( fp ) )
        {
            for(int i = 0; i < MAX_DEVICES; i++) {
                fscanf( fp, "%d\n", &packetnumberArray[i]);
            }
            fscanf( fp, "%d\n", &gatewayPacketNumber);
        }
        fclose( fp );
    }
}

void savePacketNumber()
{
    FILE *fp = fopen("gateway.pn", "w");
    for(int i = 0; i < MAX_DEVICES; i ++) {
        fprintf(fp, "%d\n", packetnumberArray[i]);
    }
    fprintf(fp, "%d\n", gatewayPacketNumber);
    fclose(fp);
}

static void sig_handler(int signal) {
    LOG_DEBUG("End of GateWay Daemon!\n");
    savePacketNumber();
    LOG_DEBUG("Save PacketNumber End!\n");
    threads_destroy();
    exit(0);
}

void request_uart_send(int cmd) 
{
    struct gateway_op *message = message_queue_message_alloc_blocking(&uart_w_queue);
    message->operation = OP_WRITE_UART;

    set_cmd_state(cmd); //이전 전송 메세지를 할당

    unsigned char * buf;
    buf = malloc(MAX_PACKET_BUFFER);
    memcpy(buf, cmd_buffer[cmd], MAX_PACKET_BUFFER);
    message->message_txt = buf;
    message->uartfd = uart_fd;
    LOG_DEBUG("UART SEND TEXT : %s ", buf);
    message_queue_write(&uart_w_queue, message);
}

int getBase64DecodeSize(char * base64encode)
{
    int len = strlen(base64encode);
    int minuscnt = 0;
    if (len >= 4) {
        if (base64encode[len - 1] == '=' && base64encode[len - 2] == '='){
            minuscnt = 2;
        } else if (base64encode[len - 1] == '=') {
            minuscnt = 1;
        } else {
            minuscnt = 0;
        }
    } else {
        LOG_DEBUG("invalid input base64 encode str");
        return -1;
    }
    return (BASE64_DECODE_OUT_SIZE(len) - minuscnt);
}

int main(int argc, char *argv[]) {
    signal(SIGINT, (void *)sig_handler);

    if ( argc == 2 ) {
        ssl_server_ip = malloc(16);
        memset(ssl_server_ip, 0x00 , 16);
        memcpy(ssl_server_ip, argv[1], strlen(argv[1]));
        LOG_DEBUG("SSL Server IP : %s", ssl_server_ip);
    }

    loadPacketNumber();

    main_thread = pthread_self();
    threads_init();

    init_uart_data();

    if (init_wiringPi() == -1) {
        LOG_DEBUG("wirig pi failed\n");
        return -1;
    }

    int server_sockfd, client_sockfd = 0; 
    int client_len;

    fd_set readfds;
    int max_fd, r;
    struct sockaddr_in clientaddr;

    init_fd_masks();

    uart_fd =  open_uart();
    server_sockfd = create_socket(PORT_NUM);
    
    LOG_DEBUG("uart fd %d", uart_fd);
    LOG_DEBUG("server_sockfd fd %d\n",server_sockfd);
    max_fd = uart_fd > server_sockfd ? uart_fd : server_sockfd;
    LOG_DEBUG("maxfd %d\n",max_fd);
    max_fd = mk_fds(&readfds, max_fd);
    LOG_DEBUG("maxfd %d\n",max_fd);

    if (server_sockfd >=0 && uart_fd >= 0 ) {
        while(1) {
            FD_ZERO(&readfds);

            pthread_mutex_lock(&mutex);
            if (server_sockfd) FD_SET(server_sockfd, &readfds);
            if (uart_fd) FD_SET(uart_fd, &readfds);

            max_fd = uart_fd > server_sockfd ? uart_fd : server_sockfd;
            max_fd = mk_fds(&readfds, max_fd);
            pthread_mutex_unlock(&mutex);
            
            r = select(max_fd + 1, &readfds, (fd_set *)0, NULL, NULL);

            if (r < 0 && errno != EINTR) {
                perror("Error in select");
                return -1;
            }
            if (r >= 0) {
                static int cnt = 0;
                if (FD_ISSET(uart_fd, &readfds)) {
                    uart_data[uart_fd].state = UART_READING;
                    
                    // struct gateway_op *message = message_queue_message_alloc_blocking(&uart_r_queue);
                    // message->operation = OP_READ_UART;
                    // message->uartfd = uart_fd;
                    // cnt ++;
                    // message->cnt = cnt;
                    // LOG_DEBUG("UART queeue_write cnt: %d",message->cnt);
                    // message_queue_write(&uart_r_queue, message);

                    handle_uart_data(uart_fd);
                }

                if (FD_ISSET(server_sockfd, &readfds)) {
                    LOG_DEBUG("SOCKET server_sockfd %d, uart_fd %d, max_fd %d\n", server_sockfd, uart_fd, max_fd);
                    client_sockfd = accept(server_sockfd, (struct sockaddr *)&clientaddr, &client_len);
                    if (client_sockfd < 0) {
                        LOG_DEBUG("Failed to accept the connection request from App Framework!\n");
                    } else {
                        
                        // add_socket() / del_socket() 내부 소켓 카운트 증감 보호
                        pthread_mutex_lock(&mutex);
                        int add_socket_res = add_socket(client_sockfd);
                        pthread_mutex_unlock(&mutex);

                        if(add_socket_res == -1) {
                            LOG_DEBUG("Failed to add socket because of the number of socket(%d) !! \n", get_cnt_fd_socket());
                        } else {
                            LOG_DEBUG("App Framework socket connected[fd = %d, cnt_fd = %d]!!!\n", client_sockfd, get_cnt_fd_socket());

                            socket_data[client_sockfd].state = SOCKET_READING;
                            socket_data[client_sockfd].pos = 0;
                            
                            struct gateway_op *message = message_queue_message_alloc_blocking(&socket_queue);
                            LOG_DEBUG("message queue write OP_READ_SOCKET\n");
                            message->operation = OP_READ_SOCKET;
                            message->socketfd = client_sockfd;
                            
                            message_queue_write(&socket_queue, message);
                        }
                    }
                }
            }
        } // while(1)

        del_all_socket();

        close(server_sockfd);
        uart_close(uart_fd);

        if (ssl_server_ip != NULL) {
            free(ssl_server_ip);
        }

        LOG_DEBUG("End of GateWay Daemon!\n");
        threads_destroy();

        return 0;

    } else {
        perror("Error listening on uart or socket");
    }
}
