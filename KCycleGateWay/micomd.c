 
#include "main.h"
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
#include <time.h>
#include "micomd.h"
#include "uart.h"
#include "wiringPi.h"
#include "ssltest.h"
#include "logger.h"
#include "base64.h"
#include "crc.h"

// function prototype
static int extract_packet (unsigned char * inputpacket, 
    char * outcode, 
    char * outsubcode, 
    short * outpn, 
    char * outlen, 
    unsigned char * outvalue,
    int addr);
// common variables for threads

static int fd_masks[MAX_SOCKET_FD];
static int cnt_fd_socket = 0;

int init_flag = 0;
int ap_init_flag = 1;
int mcu_init_flag = 0;
int ipc1_flag = 0;

int ipc_send_count = 0;
int ipc_send_wait = 0;
int ssl_send_flag = 0;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

BYTE SockBuffer[MAX_PACKET_BUFFER];
BYTE MicomBuffer[MAX_PACKET_BUFFER];
BYTE Sock1TempBuf[MAX_SOCKET_FD][MAX_PACKET_BUFFER];
BYTE TempMsgBuf[MAX_PACKET_BUFFER];
int sock1_cnt[MAX_SOCKET_FD];


int cmd_state = -1; // 이전 커맨드 id
int list_end = 0;   // AT+LST_ID? 명령에 응답에 끝 인 경우 1로 세팅
int op_mode = 0;
int packet_size = 0;

BYTE g_dev_id[3] = {0, 0, 0};
int rf_band = -1;
int mod_address = -1;
int rf_channel = -1;
int bcst_status = 0;
int data_rate = -1;
int rand_channel = -1;
PAIR_STATUS_TYPE pair_status = _UNPAIRED; // pair 유무 UNPARED 문자 확인 
DATA_MODE_TYPE data_mode = _DATA_RF_MODE; // AT 커맨드로 데이터를 처리 할때 data_mode 1
RESET_STATUS_TYPE rst_status = _RESET_NONE;  // AT reset 처리 했을때 1

int device_idx = 0; 

MANUAL_PAIRING_STATUS_TYPE manaual_pairinig_status = _MANUAL_PAIRING_NONE;

int _rf_reset = 0; //1 설정 ++++ 전송 하면 AT+RST=1을 수행 한다.

list devices[MAX_DEVICES];
int devices_count = 0; //디바이스 수

// 디바이스 별 패킷넘버 //파일에서 로드 하고 종료할때 저장 해야 한다. 
int packetnumberArray[MAX_DEVICES] = {0,};
int gatewayPacketNumber = 0;
// Key reset 되면 0

unsigned char last_packet_buffer[MAX_DEVICES][MAX_PACKET_BUFFER]; //마지막 만든 패킷 
int last_packet_len[MAX_DEVICES] = {0,};


//레이스 결과 버퍼링 
char race_res_buf[MAX_RACERS][MAX_HTTPS_PACKET_BUFFER];
int busy_flag = 0;
int race_res_offset[MAX_RACERS] = {0, }; //버퍼링 오프셋
int racer_idx[MAX_RACERS] = {-1,}; //addr로 레이서 index를 기롥

int racer_addr[MAX_RACERS]; //레이스 시작 스탑 등에 디바이스 addr보관

int racer_count; //Start / Stop / Dash Start Stop 레이서 카운트

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

BYTE cmd_buffer[MAX_CMD][MAX_PACKET_BUFFER] = 
{
    "++++\r\n",                         //  0
    "AT+ACODE=00 00 00 00\r\n",         //  1
    "AT+MMODE=1\r\n",                   //  2
    "AT+GRP_ID=01 35 46\r\n",           //  3 
    "AT+FBND=3\r\n",                    //  4 
    "AT+MADD=0\r\n",                    //  5 
    "AT+CHN=5\r\n",                     //  6 
    "AT+BCST=1\r\n",                    //  7 
    "AT+DRATE=2\r\n",                   //  8 
    "AT+RNDCH=0\r\n",                   //  9
    "AT+PAIR=1\r\n",                    // 10
    "AT+ID?\r\n",                       // 11
    "AT+RST=1\r\n",                     // 12
    "AT+LST_ID?\r\n",                   // 13
    "AT+REG_#ID=2, 01 23 45\r\n",       // 14
    "AT+GRP_ID?\r\n",                   // 15
    "AT+MADD?\r\n",                     // 16
    "AT+DEL_AID=1\r\n",                 // 17
    "AT+ACK_EN=0\r\n",                  // 18
    "",
};

void init_fd_masks()
{
    memset(fd_masks, -1, MAX_SOCKET_FD);
}

int get_cnt_fd_socket()
{
    return cnt_fd_socket;
}

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

    LOG_DEBUG("del_socket!");

    if(flag == 0) {
        LOG_DEBUG("del_socket error");
        return -1;
    }

    --cnt_fd_socket;

    return i;
}

void del_all_socket()
{
    for (int i=0; i < cnt_fd_socket; i++)
    {
        del_socket(fd_masks[i]);
    }
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

extern char * ssl_server_ip;
// ssl http write 
int ssl_write(unsigned char * msg, unsigned char ** outmsg, int * outmsglen) {
    unsigned char * buf;
    int bytes = 0;

    SSL_OPEN_TO_SERVER sslOpenToServer;

    if (ssl_server_ip != NULL ) {
        if (SSLOpenToServer(&sslOpenToServer, ssl_server_ip, HTTPS_PORT_NUM) != SSL_OPEN_TO_SERVER_SUCCESS)
        {
            puts("SSLOpenToServer fail\n");
            return -1;
        }
    
    } else {
        if (SSLOpenToServer(&sslOpenToServer, HTTPS_IP_ADDR, HTTPS_PORT_NUM) != SSL_OPEN_TO_SERVER_SUCCESS)
        {
            puts("SSLOpenToServer fail\n");
            return -1;
        }
        
    }

    SSL_write(sslOpenToServer.ssl, msg, strlen(msg));
    LOG_DEBUG("\n https request %d bytes\n", strlen(msg));
    BIO_dump_fp(stdout, msg, strlen(msg));

    buf = malloc(MAX_HTTPS_PACKET_BUFFER);
    memset(buf,MAX_HTTPS_PACKET_BUFFER,0x00);

    bytes = SSL_read(sslOpenToServer.ssl, buf, MAX_HTTPS_PACKET_BUFFER);
    buf[bytes] = 0;

    LOG_DEBUG("\n https response %d bytes\n", bytes);
    BIO_dump_fp(stdout, buf, bytes);

    SSLCloseToServer(&sslOpenToServer);

    if (bytes > 0) { 
        *outmsg = buf;
        *outmsglen = bytes;
    } else {
        *outmsg = NULL;
        *outmsglen = 0;
        free(buf);
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
    LOG_DEBUG("RST low.............\n");
    delay(1000);
    digitalWrite(RST, 1);
    LOG_DEBUG("RST high.............\n");

    return 0;
}

// MARK: uart open 
int open_uart() {
    int uart_fd;

    do {
        uart_fd = uart_open();
        if (uart_fd < 0) {
            LOG_DEBUG("UART open failed!\n");
        }
    } while (uart_fd < 0);

    return uart_fd;
}

int create_socket (int portnum)
{
    int fd;
    int state = 0;
    int nSockOpt = 1;
    struct sockaddr_in address;

    do {
        fd = socket(PF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            LOG_DEBUG("Failed to create the server socket!\n");
        }
    } while (fd < 0);

    bzero(&address, sizeof(address));
    address.sin_family = AF_INET;
    //address.sin_addr.s_addr = inet_addr(SOCK_IP_ADDR);
    address.sin_port = htons(portnum);

    // prevent bind error
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &nSockOpt, sizeof(nSockOpt));

    do {
        state = bind(fd, (struct sockaddr *)&address, sizeof(address));
        if (state < 0) {
            LOG_DEBUG("Bind error!\n");
        }
    } while (state < 0);

    do {
        state = listen(fd, 5);
        if (state < 0) {
            LOG_DEBUG("Failed to set the ready state!\n");
        }
    } while (state < 0);

    return fd;
}

int read_packet (int fd, int cnt, PBYTE buf, int fd_index)
{
    int ret = 0;

    if(fd > 0) {
        do {
            ret = read(fd, &buf[cnt], MAX_PACKET_BYTE);
        } while (ret == -1);
        cnt += ret;
        

        return cnt;
    } else {
        LOG_DEBUG("read packet fd error.....[%d]    \n", fd);
        return -1;
    }
}

// rf data 응답처리
int check_rf_data(PBYTE data_buf)
{
    int index = 0;

    if(memcmp(data_buf, AT_PAIR, strlen(AT_PAIR)) == 0)
    {
        LOG_DEBUG("parse REG.START\n");
    }
    else if(memcmp(data_buf, TOKEN_TGT, strlen(TOKEN_TGT)) == 0)
    {
        LOG_DEBUG("parse TGT\n");
    }
    else if(memcmp(data_buf, HEADER, strlen(HEADER)) == 0 || memcmp(data_buf, AT_OK, strlen(AT_OK)) == 0)
    {
        char* token = NULL;
        char div[] = ",:\r\n";

        pair_status = _PAIRED;

        token = strtok((char *)data_buf, div);
        while(token != NULL)
        {
            LOG_DEBUG("token = %s\n", token);
            if(strcmp(token, AT_OK) == 0)
            {
                LOG_DEBUG("parse OK\n");
                cmd_state = _AT_CMD_NONE;
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
                pair_status = _UNPAIRED;
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

        if(op_mode != 1 )
        {
            request_uart_send(_AT_START);
            data_mode = _DATA_AT_MODE;
            LOG_DEBUG("send_message = %s ", cmd_buffer[_AT_START]);
        }
        else 
        {
            if(rst_status == _RESET_STATUS)
            {
                // uart 전송 없음
                rst_status = _RESET_NONE;
                data_mode = _DATA_RF_MODE;
                cmd_state = _AT_USER_CMD;
                LOG_DEBUG("data receiving status................\n");
            }
            else
            {
                // ++++ 전송
                request_uart_send(_AT_START);
                data_mode = _DATA_AT_MODE;
                LOG_DEBUG("AT command mode ....................\n");
            }
        }
    }
    else // addr, , packet
    {
        char* token = NULL;
        char div[] = ",\r\n";
        int check_addr = 0, addr = 0;

        token = strtok((char *)data_buf, div);
        while(token != NULL)
        {
            LOG_DEBUG("token = %s\n", token);
            if(check_addr == 0)
            {
                LOG_DEBUG("token = %s\n", token);
                addr = atoi(token);
                check_addr = 1;
            }
            else 
            {
                check_addr = 0;
                LOG_DEBUG("token = %s\n", token);
                if(memcmp(token, PING_CHECK, strlen(PING_CHECK)) == 0)
                {
                    //버퍼링 중에는 ping 체크가 busy로 날라간다.
                    if (busy_flag != 0 ) {
                        sprintf(cmd_buffer[_AT_USER_CMD], "%d,busy\r\n", addr);
                    } else {
                        sprintf(cmd_buffer[_AT_USER_CMD], "%d,ping\r\n", addr);
                    }

                    request_uart_send(_AT_USER_CMD);
                }
                else
                {
                    LOG_DEBUG("token = %s\n", token);
                    
                    unsigned char base_decode[MAX_PACKET_BUFFER];
                    memset(base_decode, 0x00, sizeof(base_decode));

                    LOG_DEBUG("RF data : %s\n",token);
                    base64_decode(token, strlen(token) , base_decode);

                    LOG_DEBUG("base64 code: 0x%02X ,subcode: 0x%02x\n", base_decode[0], base_decode[1]); 
                    
                    packet_process(base_decode, addr);
                }
            }

            token = strtok(NULL, div);
        }
    }

    return 0;
}

// AT CMD 응답처리
int check_uart (PBYTE data_buf)
{
    int index = 0;

    if(memcmp(data_buf, HEADER, strlen(HEADER)) == 0) // RDY SW
    {
        char* token = NULL;
        char div[] = ",:\r\n";

        pair_status = _PAIRED;

        token = strtok((char *)data_buf, div);
        while(token != NULL)
        {
            LOG_DEBUG("token = %s\n", token);
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
                pair_status = _UNPAIRED;
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

        if(op_mode != 1)
        {
            // cmd_id = _AT_START;
            // ipc_send_flag = 1;
            request_uart_send(_AT_START);
        }
        else 
        {
            if(rst_status == _RESET_STATUS)
            {
                // ipc_send_flag = 0;
                rst_status = _RESET_NONE;
                data_mode = _DATA_RF_MODE;
                cmd_state = _AT_USER_CMD;
                LOG_DEBUG("data receiving status................\n");
            }
            else
            {
                cmd_state = _AT_USER_CMD;
            }
        }
    } // RDY SW end
    else if(memcmp(data_buf, AT_ST_HEADER, strlen(AT_ST_HEADER)) == 0) // AT.START
    {
        // cmd_id = _AT_ACODE;
        // ipc_send_flag = 1;
        data_mode = _DATA_AT_MODE;
        request_uart_send(_AT_ACODE);
    }
    else if(memcmp(data_buf, AT_LOCKED, strlen(AT_LOCKED)) == 0) //LOCKED
    {
        // cmd_id = _AT_ACODE;
        // ipc_send_flag = 1;
        request_uart_send(_AT_ACODE);
    }
    else if(memcmp(data_buf, AT_PAIR, strlen(AT_PAIR)) == 0)// REG.START
    {
        // cmd_id = _AT_CMD_NONE;
        cmd_state = _AT_CMD_NONE;
        // ipc_send_flag = 0;
    }
    else if(memcmp(data_buf, AT_REG_FAIL, strlen(AT_REG_FAIL)) == 0) // REG.FAIL
    {
        // cmd_id = _AT_CMD_NONE;
        cmd_state = _AT_CMD_NONE;
        // ipc_send_flag = 0;
        pair_status = _UNPAIRED;
    }
    else if(memcmp(data_buf, AT_REG_OK, strlen(AT_REG_OK)) == 0)// REG.OK
    {
        // cmd_id = _AT_CMD_NONE;
        cmd_state = _AT_CMD_NONE;
        // ipc_send_flag = 0;
        pair_status = _PAIRED;
    }
    else if(memcmp(data_buf, AT_OK, strlen(AT_OK)) == 0) // OK
    {
        switch(cmd_state)
        {
            case _AT_ACK_EN:
                //cmd_id = _AT_MADD_GET;
                //ipc_send_flag = 1;
                request_uart_send(_AT_MADD_GET);
            break;

            case _AT_ACODE:

                //RF reset
                if (_rf_reset == 1)
                {
                    rst_status = _RESET_STATUS;
                    data_mode = _DATA_RF_MODE;
                    _rf_reset = 0;
                    LOG_DEBUG("AT+RST=1 send..");
                    request_uart_send(_AT_RST);
                    break;
                }

                if (manaual_pairinig_status == _MANUAL_PAIRING_DELETE)
                {
                    //cmd_id = _AT_DEL_ALL_ID;
                    //ipc_send_flag = 1;
                    request_uart_send(_AT_DEL_ALL_ID);
                    break;
                }

                if (manaual_pairinig_status == _MANUAL_PAIRING_STATUS || manaual_pairinig_status == _MANUAL_PAIRING_HOST )
                {
                    // cmd_id = _AT_GRP_ID;
                    // ipc_send_flag = 1;
                    request_uart_send(_AT_GRP_ID);
                    break;
                }

                if(pair_status == _PAIRED)
                {
                    // cmd_id = _AT_ID;
                    // ipc_send_flag = 1;
                    
                    device_idx = 0;
                    request_uart_send(_AT_ID);
                }
                else
                {
                    // cmd_id = _AT_MODE;
                    // ipc_send_flag = 1;
                    request_uart_send(_AT_MODE);
                }
                break;

            case _AT_MODE:
                op_mode = 1;
                {
                    // cmd_id = _AT_FBND;
                    // ipc_send_flag = 1;
                    request_uart_send(_AT_FBND);
                }
                break;

            case _AT_GRP_ID:
                // cmd_id = _AT_FBND;
                // ipc_send_flag = 1;
                request_uart_send(_AT_FBND);
                break;

            case _AT_FBND:
                 if (manaual_pairinig_status == _MANUAL_PAIRING_STATUS) {
                    //  cmd_id = _AT_CHN;
                    request_uart_send(_AT_CHN);
                 } else if (manaual_pairinig_status == _MANUAL_PAIRING_HOST) {               
                    // cmd_id = _AT_MADD;
                    request_uart_send(_AT_MADD);
                 } else {
                    // cmd_id = _AT_CHN;
                    request_uart_send(_AT_CHN);
                 }
                // ipc_send_flag = 1;
                break;

            case _AT_MADD:
                // cmd_id = _AT_CHN;
                // ipc_send_flag = 1;
                request_uart_send(_AT_CHN);
                break;

            case _AT_CHN:
                if (manaual_pairinig_status != _MANUAL_PAIRING_NONE ) {
                    // cmd_id = _AT_DRATE;
                    device_idx = 0;
                    request_uart_send(_AT_DRATE);
                } else {
                    // cmd_id = _AT_BCST;
                    request_uart_send(_AT_BCST);
                }
                // ipc_send_flag = 1;
                break;

            case _AT_BCST:
                bcst_status = 1;
                // cmd_id = _AT_DRATE;
                // ipc_send_flag = 1;
                request_uart_send(_AT_DRATE);
                break;

            case _AT_DRATE:
            case _AT_REG_ID:
                if (manaual_pairinig_status != _MANUAL_PAIRING_NONE ) {
                    LOG_DEBUG("device_idx : %d, %d", device_idx,devices_count);

                    // 디바이스 리스트 를 엎어야 한다.
                    sprintf(cmd_buffer[_AT_REG_ID], AT_REG_ID_FMT, devices[device_idx].dev_addr, 
                        devices[device_idx].dev_id[0], 
                        devices[device_idx].dev_id[1], 
                        devices[device_idx].dev_id[2]);
                        device_idx ++;

                        if (device_idx > devices_count) {
                            LOG_DEBUG("device_idx : %d, %d", device_idx,devices_count);
                            // cmd_id = _AT_RST;
                            rst_status = _RESET_STATUS;
                            data_mode = _DATA_RF_MODE;
                            request_uart_send(_AT_RST);
                        }
                        else {
                            // cmd_id = _AT_REG_ID;
                            request_uart_send(_AT_REG_ID);
                        }
                        
                } else {
                    // cmd_id = _AT_RNDCH;
                    request_uart_send(_AT_RNDCH);
                }
                // ipc_send_flag = 1;
                break;

            case _AT_RNDCH:
                rand_channel = 0;
                // cmd_id = _AT_ID;
                // ipc_send_flag = 1;
                request_uart_send(_AT_ID);
                break;

            case _AT_PAIR:
                // cmd_id = _AT_CMD_NONE;
                cmd_state = _AT_CMD_NONE;
                // ipc_send_flag = 0;
                pair_status = _PAIRED;
                break;
            
            case _AT_DEL_ALL_ID:
                // cmd_id = _AT_RST;
                rst_status = _RESET_STATUS;
                list_end = 0;
                data_mode = _DATA_RF_MODE;
                // ipc_send_flag = 1;
                request_uart_send(_AT_RST);
                break;

            default:
                // ipc_send_flag = 0;
                break;
        }
    }
    else if(cmd_state == _AT_ID) //게이트웨이 모뎀 디바이스 아이디
    {
        int i = 0;
        
        for(i = 0; i < 3; i++)
        {
            hex_decode((char *)(data_buf + 3*i), 1, &g_dev_id[i]);
        
            LOG_DEBUG("device_id[%d] = %02x    \n", i, g_dev_id[i]);
        }
        // cmd_id = _AT_GRP_ID_GET;
        // ipc_send_flag = 1;
        request_uart_send(_AT_GRP_ID_GET);
    }
    else if (cmd_state == _AT_GRP_ID_GET) //GRP_ID  얻기
    {
        int i = 0;
        unsigned char grp_id[3]={0,};
        
        for(i = 0; i < 3; i++)
        {
            hex_decode((char *)(data_buf + 3*i), 1, &grp_id[i]);
        
            LOG_DEBUG("group id[%d] = %02x    \n", i, grp_id[i]);
        }
        // cmd_id = _AT_ACK_EN;
        // ipc_send_flag = 1;
        request_uart_send(_AT_ACK_EN);
    } 
    else if (cmd_state == _AT_MADD_GET) // MADD 얻기
    {
        LOG_DEBUG("MADD : %s", data_buf);

    #if 1
        // cmd_id = _AT_LST_ID; // 리스트 얻기 제거됨
        // ipc_send_flag = 1;
        request_uart_send(_AT_LST_ID);
    #else 
        // 리셋
        // cmd_id = _AT_RST;
        rst_status = _RESET_STATUS;
        list_end = 0;
        data_mode = _DATA_RF_MODE;
        // ipc_send_flag = 1;
        request_uart_send(_AT_RST);
    #endif
        
    }
    else if(cmd_state == _AT_LST_ID)
    {
        char* token = NULL;
        char div[] = ",\r\n";

        token = strtok((char *)data_buf, div);
        while(token != NULL)
        {
            LOG_DEBUG("token = %s   strlen = %d \n", token, strlen(token));

            if (!strcmp(token, "NONE")) { // 페어링 정보가 없는경우
                list_end = 1;
                break; 
            }

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
                    LOG_DEBUG("device_id[%d] = %02x    \n", i, devices[device_idx].dev_id[i]);
                }
                device_idx++;
            }
            token = strtok(NULL, div);
        }

        if(list_end == 1)
        {
            int it = 0;
            LOG_DEBUG("======   list in devices[%d]   ======\n", device_idx);
            for(it = 0; it < device_idx; it++)
            {
                LOG_DEBUG("devices[%d] addr = %d, id = [%02x %02x %02x]\n", it, devices[it].dev_addr, devices[it].dev_id[0], devices[it].dev_id[1], devices[it].dev_id[2]);
            }

            devices_count = device_idx; //장비 개수 

            // cmd_id = _AT_RST;
            rst_status = _RESET_STATUS;
            list_end = 0;
            data_mode = _DATA_RF_MODE;
            // ipc_send_flag = 1;
            request_uart_send(_AT_RST);
        }
    }

    packet_size = strlen((char *)data_buf);

    return 0;
}

// wireless protocol packet process entry point
int packet_process(unsigned char * inputpacket, int addr)
{
    char code;
    char subcode;

    short pn;
    char len;
    //unsigned char valuebuf[MAX_PACKET_BYTE];
    unsigned char  valuebuf[MAX_PACKET_BYTE];
    
    memset(valuebuf, 0x00, MAX_PACKET_BYTE);
    unsigned char outpacket[MAX_PACKET_BUFFER];
    int outpacketlen = 0;

    unsigned char base_encode[MAX_PACKET_BUFFER];
    memset(base_encode, 0x00, sizeof(base_encode));

    // 내아이디 얻기를 해야 함
    LOG_DEBUG("extract_packet\n"); 
    if ( extract_packet(inputpacket, &code, &subcode,  &pn, &len, valuebuf, addr) == 0 ){
        //패킷 넘버 확인
#if 0        
        if (pn < packetnumberArray[addr]) {
            LOG_DEBUG("Packet number Error!");
            return -1;
        } 
#endif
        // 게이트웨이  retry count 초기화
        switch (code)
        {
            case PACKET_CMD_PING_R:
                //todo 내 senderid 를 만들어야 한다.
                LOG_DEBUG("cmd PACKET_CMD_PING_R");

                //서버 전송 리퀘스트
                SSLServerSend("/gateway/ping", valuebuf, len, addr);
                break;

            case PACKET_CMD_INSPECTION_REQ_R: // 패턴2
                LOG_DEBUG("PACKET_CMD_INSPECTION_REQ_R");
                LOG_DEBUG("PACKET_CMD_INSPECTION_REQ_R valuebuf: %x len :%d", *valuebuf, len );
                SSLServerSend("/gateway/inspectionRequest", valuebuf, len, addr);
                break;

            case PACKET_CMD_INSPECTION_RES_R:
                LOG_DEBUG("cmd PACKET_CMD_INSPECTION_RES_R : %x", valuebuf[0]);
            
                SSLServerSend("/gateway/inspectionResult", valuebuf, len, addr);
                break;

            case PACKET_CMD_ENCKEY_REQ_R:
                LOG_DEBUG("cmd PACKET_CMD_ENCKEY_REQ_R");
            
                SSLServerSend("/gateway/encryptionKeyRequest", valuebuf, len, addr);
                break;

            case PACKET_CMD_LOGCHK_R:
                LOG_DEBUG("cmd PACKET_CMD_LOGCHK_R");
            
                SSLServerSend("/gateway/logCheckMessage", valuebuf, len, addr);
                break;

            case PACKET_CMD_ERRORCHK_R:
                LOG_DEBUG("cmd PACKET_CMD_ERRORCHK_R");
            
                SSLServerSend("/gateway/errorCheck", valuebuf, len, addr);
                break;

            case PACKET_CMD_TRAININGSTART_R: //패턴2
                LOG_DEBUG("cmd PACKET_CMD_TRAININGSTART_R");
            
                SSLServerSend("/gateway/tranningStart", valuebuf, len, addr);
                break;

            case PACKET_CMD_TRAININGSTOP_R: //패턴2
                LOG_DEBUG("cmd PACKET_CMD_TRAININGSTOP_R");
            
                SSLServerSend("/gateway/tranningStop", valuebuf, len, addr);
                break;

            case PACKET_CMD_DASHSTART_R: //패턴2
                LOG_DEBUG("cmd PACKET_CMD_DASHSTART_R");
            
                SSLServerSend("/gateway/dashStart", valuebuf, len, addr);
                break;

            case PACKET_CMD_DASHSTOP_R: //패턴2
                LOG_DEBUG("cmd PACKET_CMD_DASHSTOP_R");
            
                SSLServerSend("/gateway/dashStop", valuebuf, len, addr);
                break;

            case PACKET_CMD_DASHRESULT_R:
                LOG_DEBUG("cmd PACKET_CMD_DASHRESULT_R");
            
                SSLServerSend("/gateway/dashResult", valuebuf, len, addr);
                break;

            case PACKET_CMD_RACESTATECHK_R:
                LOG_DEBUG("cmd PACKET_CMD_RACESTATECHK_R");
            
                SSLServerSend("/gateway/raceStateCheck", valuebuf, len, addr);
                break;

            //case PACKET_CMD_RACESTART_R: //패턴2
            // LOG_DEBUG("cmd PACKET_CMD_RACESTART_R");
        
            // SSLServerSend("/gateway/raceStart", valuebuf, len, addr);
            //break;

            case PACKET_CMD_RACESTOP_R: //패턴2
                LOG_DEBUG("cmd PACKET_CMD_RACESTOP_R");
            
                SSLServerSend("/gateway/raceStop", valuebuf, len, addr);
                break;

            case PACKET_CMD_RACE_END_R:
                LOG_DEBUG("cmd PACKET_CMD_RACE_END_R");
            
                SSLServerSend("/gateway/raceEnd", valuebuf, len, addr);
                break;

            case PACKET_CMD_RACERESULT_READY_R: //패턴2
                LOG_DEBUG("cmd PACKET_CMD_RACERESULT_READY_R");
            
                SSLServerSend("/gateway/raceResultReady", valuebuf, len, addr);
                break;

            case PACKET_CMD_RACELINERESULT_EXTRA_R: //패턴2
                LOG_DEBUG("cmd PACKET_CMD_RACELINERESULT_EXTRA_R");
                
                SSLServerSend("/gateway/raceLineResultExtra", valuebuf, len, addr);
                break;

            case PACKET_CMD_LOG_REQ_R: //패턴2
                LOG_DEBUG("cmd PACKET_CMD_LOG_REQ_R");
                
                SSLServerSend("/gateway/logRequest", valuebuf, len, addr);
                break;

            case PACKET_CMD_RACELINERESULT_R:
                LOG_DEBUG("cmd PACKET_CMD_RACELINERESULT_R : len %d", len);
                BIO_dump_fp(stdout, valuebuf, len);
                SSLServerSend("/gateway/raceLineResult", valuebuf, len, addr);
                break;

            case PACKET_CMD_RACERESULT_REQ_R:
                LOG_DEBUG("cmd PACKET_CMD_RACERESULT_REQ_R");
            
                SSLServerSend("/gateway/raceCycleResultRequest", valuebuf, len, addr);
                break;

            case PACKET_CMD_RACERESULT_END_R:
                LOG_DEBUG("cmd PACKET_CMD_RACERESULT_END_R");
                SSLServerSend("/gateway/raceResultEnd", valuebuf, len, addr);
                break;

            case PACKET_CMD_IR_REF_SET_R:
                LOG_DEBUG("cmd PACKET_CMD_IR_REF_SET_R");
                SSLServerSend("/gateway/irReferenceSet", valuebuf, len, addr);
                break;

            //건으로 부터 출발 신호를 받았다.
            case PACKET_CMD_RACESTART_GUN_R: 
            case PACKET_CMD_RACESTART_GUN2_R:
                LOG_DEBUG("cmd PACKET_CMD_RACESTART_GUN_R : racer count %d", racer_count);
                for (int i = 0; i < racer_count; i ++ ){
                    racer_idx[i] = -1;
                    race_res_offset[i] = -1;
                    memset(race_res_buf[i], 0x00, MAX_HTTPS_PACKET_BUFFER);
                }

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
                //건에게 응답
                memset(outpacket, 0x00, sizeof(outpacket));
                memset(base_encode, 0x00, sizeof(base_encode));
                outpacketlen = 0;

                //건이 2가지 커맨드라서 code + 1로 응답 한다.
                if (code == PACKET_CMD_RACESTART_GUN_R) {
                    make_packet(PACKET_CMD_RACESTART_GUN_S, 0x00, addr, 0, NULL, outpacket, &outpacketlen);
                } else {
                    make_packet(PACKET_CMD_RACESTART_GUN2_S, 0x00, addr, 0, NULL, outpacket, &outpacketlen);
                }
                base64_encode(outpacket, outpacketlen , base_encode);
                sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", addr, base_encode);
                LOG_DEBUG("cmd PACKET_CMD_RACESTART_GUN_R : cmdbuffer : %s", cmd_buffer[_AT_USER_CMD]);
                request_uart_send(_AT_USER_CMD);

                // 서버에게 raceStart 전송
                SSLServerSend("/gateway/raceStart", valuebuf, len, -1);
                break;

            case PACKET_CMD_RACECYCLESULT_R:
                //todo buffering 로직 필요
                LOG_DEBUG("cmd PACKET_CMD_RACECYCLESULT_R");

                // 여기서 버퍼링을 하고 디바이스로 바로 응답을 보낸다.
                
                memset(outpacket, 0x00, sizeof(outpacket));
                memset(base_encode, 0x00, sizeof(base_encode));
                outpacketlen = 0;

                // 받은 subcode를 싫어서 uart 응답 전송
                make_packet(PACKET_CMD_RACECYCLESULT_S, subcode, addr, 0, NULL, outpacket, &outpacketlen);
                base64_encode(outpacket, outpacketlen , base_encode);
                sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", addr, base_encode);    

                // 버퍼링이 끝나면 서버로 전송을 하고 끝
                // 디바이스 별로 버퍼링 해야 함
                if (subcode == 0x00) {
                    addRacer(addr);
                    int idx = getRacerIndex(addr);

                    LOG_DEBUG("START buffering ADDR %d\n",addr);
                    memcpy (race_res_buf[idx], valuebuf, RACE_RESULT_PACKET_SIZE);
                    busy_flag = 1;
                } else if (subcode >= 0x80) {
                    //last packet
                    int idx = getRacerIndex(addr);
                    if (race_res_offset[idx] != -1 ) {
                        race_res_offset[idx] = (subcode - 0x80) * RACE_RESULT_PACKET_SIZE;
                        memcpy(race_res_buf[idx] + race_res_offset[idx], valuebuf, len);
                        race_res_offset[idx] = race_res_offset[idx] + len; 
                        LOG_DEBUG("END buffering %02x total size : %d\n" , subcode, race_res_offset[idx] );
                        LOG_DEBUG("SSLServer /gateway/raceCycleResult\n");
                        SSLServerSend("/gateway/raceCycleResult", race_res_buf[idx], race_res_offset[idx], addr);
                        race_res_offset[idx] = -1; //전송 했음
                        removeRacer(addr);
                        busy_flag = 0;
                    }
                } else {
                    //버퍼링
                    int idx = getRacerIndex(addr);
                    race_res_offset[idx] = (subcode) * RACE_RESULT_PACKET_SIZE;

                    LOG_DEBUG("Buffering subcode:%02x offset : %d\n" , subcode, race_res_offset[idx]);
                    memcpy(race_res_buf[idx] + race_res_offset[idx], valuebuf, RACE_RESULT_PACKET_SIZE);
                    
                }
                usleep(1000 * 50);
                request_uart_send(_AT_USER_CMD);
                break;
                
            default:
            //nothing todo
                break;
        }
    } else { 
        LOG_DEBUG("extract packet 실패");
        //nothing to do
    }
    
    return 0;
}

// 입력 받은 패킷을 분해 한다.
static int extract_packet (unsigned char * inputpacket, 
                    char * outcode, 
                    char * outsubcode, 
                    short * outpn, 
                    char * outlen, 
                    unsigned char * outvalue,
                    int addr)
{
    unsigned char dec_out[1000];

    outcode[0] = inputpacket[0];
    outsubcode[0] = inputpacket[1];
    
    // outsenderid[0] = inputpacket[2];
    // outsenderid[1] = inputpacket[3];
    // outsenderid[2] = inputpacket[4];

    //pn = (short)(packetnumber[1] << 8) +  (short)(packetnumber[0]);
    *outpn = (short)inputpacket[5] + (short)(inputpacket[6] << 8);
    *outlen = *(inputpacket + 12);

    if ( addr !=  GUN_ID ) {
    short orgcrc ;
    memcpy(&orgcrc, (void *)(inputpacket + 13 + *outlen), 2);

    
        short crc = crc16(inputpacket, 13 + *outlen );
        if (orgcrc != crc ) {
            LOG_DEBUG("CRC error RCRC :%04x  G CRC:%04x", orgcrc, crc);
            return -1;
        }
    }   
    
    if (validate_ac(inputpacket + 2, *outpn, inputpacket + 2) == 0){
        //plaintext
#ifdef _PACKET_ENCRYPTY
        int decslength = decrypt_block(dec_out, inputpacket + 13, *outlen, Key, IV);
        memcpy(outvalue, dec_out, decslength);
        LOG_DEBUG("plaintext :%s\n", outvalue);
#else 
        memcpy(outvalue, inputpacket + 13, *outlen);
        LOG_DEBUG("plaintext :%s\n", outvalue);
#endif

        return 0;
    } else {
        LOG_DEBUG("AC fail \n");
        return -1;
    }
}

void make_packet(char code, 
                 char subcode,
                 int addr,
                 char len, 
                 char * value, 
                 unsigned char * out_packet,
                 int * outlen)
{
    unsigned char packetbuf[MAX_PACKET_BUFFER];
    packetbuf[0] = code;
    packetbuf[1] = subcode;
    
    unsigned char ac[10];
    unsigned char enc_out[1000];

    int pn = gatewayPacketNumber ++;

    memset(enc_out, 0x00, sizeof(enc_out));
    
    make_ac_code(g_dev_id, pn, ac);
    memcpy(packetbuf + 2, ac, 10);
    
    int encslength = 0;
    if (value != NULL ) {
#ifdef _PACKET_ENCRYPTY        
        encslength = encrypt_block(enc_out, value, (int)len, Key, IV);
        packetbuf[12] = encslength;
        BIO_dump_fp(stdout, enc_out, encslength);
        memcpy(packetbuf + 13, enc_out, encslength);
        LOG_DEBUG("encleng : %d", encslength);
#else
        packetbuf[12] = (int)len;
        memcpy(packetbuf + 13, value, (int)len);
        encslength = len;
#endif        
    }
    
    memcpy(out_packet, packetbuf, 13 + encslength);
    short crc = crc16(packetbuf, 13 + encslength);

    memcpy(out_packet + 13 + encslength, (unsigned char *)&crc, 2); // crc 추가
    BIO_dump_fp(stdout, out_packet, 13 + encslength + 2);
    *outlen = 13 + encslength + 2; //crc size 추가

    //마지막 패킷을 보관 한다.
    memset(last_packet_buffer[addr], 0x00, MAX_PACKET_BUFFER);
    memcpy(last_packet_buffer[addr], out_packet, 13 + encslength + 2);
    last_packet_len[addr] = 13 + encslength + 2;
}

// AC 코드 확인
int validate_ac(char * senderid, short pn, unsigned char * acbuf)
{
#ifdef _PACKET_ENCRYPTY
#error "code not defien"
    unsigned char ac[10];
    
    make_ac_code(senderid, pn, ac);

    if ( memcmp(ac, acbuf, 10) == 0 ) {
        return 0;
    } else {
        return -1;
    }
#else 
    LOG_DEBUG("validate ac end\n");
    return 0;
#endif
}

// AC 코드 생성
void make_ac_code(char * senderid, short pn, unsigned char * out_ac)
{
    unsigned char ac[10];
    unsigned char senderidbuf[3];
    memcpy(senderidbuf, senderid, sizeof(senderidbuf));

    ac[0] = (unsigned char)senderidbuf[0];
    ac[1] = (unsigned char)senderidbuf[1];
    ac[2] = (unsigned char)senderidbuf[2];
    ac[3] = pn % 256;
    ac[4] = pn / 256;

    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned char enc_out[1000];
    unsigned char dec_out[1000];
    unsigned char enc_temp[1000];

    memset(enc_out, 0x00, sizeof(enc_out));
    memset(dec_out, 0x00, sizeof(dec_out));
    memset(enc_temp, 0x00, sizeof(enc_temp));
    memset(digest, 0x00, sizeof(digest));

    int encslength = encrypt_block(enc_out, ac, 5, Key, IV);

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, enc_out, encslength);
    SHA256_Final(digest, &ctx);

    memcpy(ac + 5, digest + 27, 5);
    memcpy(out_ac, ac, sizeof(ac));
}

void make_date_data(char * outtime_val)
{
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    char time_val[5];
    time_val[0] = tm.tm_year + 1900 - 2000;
    time_val[1] = tm.tm_mon;
    time_val[2] = tm.tm_mday;
    time_val[3] = tm.tm_hour;
    time_val[4] = tm.tm_min;

    memcpy(outtime_val, time_val, 5);
}

BYTE* hex_decode(char *in, int len, BYTE *out)
{
    unsigned int i, t, hn, ln;

    for (t = 0,i = 0; i < len; i+=2,++t) {

            hn = in[i] > '9' ? (in[i]|32) - 'a' + 10 : in[i] - '0';
            ln = in[i+1] > '9' ? (in[i+1]|32) - 'a' + 10 : in[i+1] - '0';

            out[t] = (hn << 4 ) | ln;
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
        if(list_end == 0 && cmd_state == _AT_LST_ID)
        {
            // AT+LST_ID?의 응답에
            // 0, 60 00 01<CR><LF>
            // 1, 60 00 08<CR><LF>
            //<CR><LF>  //<---이런 경우에 해당
            list_end = 1;
            return 1;
        }
    }

    // <CR><LF> 의 카운트 얻기
    for(ix = 0; ix < (*cnt) -1; ix++)
    {
        if(data_buf[ix] == 0x0D && data_buf[ix+1] == 0x0A )
            index++;
    }

    if(cmd_state != -1 && cmd_state != _AT_START) //초기 상태와 , ++++ 이 아닌경우
    {
        if(cmd_state == _AT_RST) //AT+RST=1 응답은 4줄 이상
        {
            if(index >= 4)
            {
                return 1;
            }
            else
                return 0;
        }
        else
        {
            if(index == 1) //CR LF 하나
            {
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
            if(index >= 4) //부팅시 4줄 이상
            {
                return 1;
            }
            else
                return 0;
        }
        else // ++++ 인 경우
        {
            if(memcmp(data_buf, AT_ST_HEADER, strlen(AT_ST_HEADER)) == 0) //AT/START
            {
                return 1;
            }
            else
                return 0;
        }
    }
}

// 마지막 명령 확인
int get_cmd_state()
{
    return cmd_state;
}

void set_cmd_state(int cmd)
{
    cmd_state = cmd;
}

int get_list_end()
{
    return list_end;
}


//출전 경기 선수 addr 등록 중복되지 않는다면 racer_count 증가
void addRacer(int addr)
{
    for (int i=0; i<MAX_RACERS; i++) {
        if (racer_idx[i] == addr )
            return;
    }
    for (int i = 0; i < MAX_RACERS; i++) {
        if (racer_idx[i] == -1 ){
            racer_idx[i] = addr;
            return;
        }
    }
}

void removeRacer(int addr)
{
    for (int i=0; i<MAX_RACERS; i++) {
        if (racer_idx[i] == addr ) {
            racer_idx[i] = -1;
            return;
        }
    }
}

//addr로 버퍼링 인덱스를 얻는다.
int getRacerIndex(int addr)
{
    for (int i = 0; i < MAX_RACERS; i++) {
        if (racer_idx[i] == addr ) {
            return i;
        }
    }
    return -1;
}


// 모뎀 어드레스 얻기
int getAddrFromDevices(char * dev_id)
{
    for (int i= 0 ; i < MAX_DEVICES ; i++)
    {
        if (!memcmp(devices[i].dev_id, dev_id, sizeof(devices[0].dev_id))) {
            return devices[i].dev_addr;
        }
    }
    return -1;
}

char * getDevIDFromDevices(int dev_addr)
{
    for (int i= 0 ; i < MAX_DEVICES ; i++)
    {
        if ( dev_addr == devices[i].dev_addr ) {
            return devices[i].dev_id;
        }
    }
    LOG_DEBUG("ERROR not found getDevIDFromDevices");
    return NULL;
}

int getDevicesIndexFromAddr(int dev_addr)
{
    for (int i= 0 ; i < MAX_DEVICES ; i++)
    {
        if ( dev_addr == devices[i].dev_addr ) {
            return i;
        }
    }
    LOG_DEBUG("ERROR not found getDevicesIndexFromAddr");
    return -1;
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
    int w = 0;

    if(fd > 0) {
        do {
            w = write(fd, pbuf+wrtsize, size-wrtsize);
            wrtsize += w;
            if (w <= 0) LOG_DEBUG("write packet minus size(%d)\n", w);

        } while ((size - wrtsize) > 0);

        LOG_DEBUG("write packet fd(%d), size(%d)\n", fd, size);

        return 0;
    } else {
        return -1;
    }
}

/* AES Encrypt Process 
 https://tools.ietf.org/html/rfc3602

 128 CBC 

unsigned char key2[] = {0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b, 0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06};
unsigned char iv[]   = {0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30, 0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41};
unsigned char intext[] = "Single block msg";
0000 - e3 53 77 9c 10 79 ae b8-27 08 94 2d be 77 18 1a   .Sw..y..'..-.w..

패딩을 내부함,, 밖에서 할필요 없음
*/
int encrypt_block(unsigned char* cipherText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key, unsigned char* ivec)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int addLen=0, orgLen=0;
    unsigned long err=0;

    ERR_load_crypto_strings();
    EVP_CIPHER_CTX_init(ctx);

    if (EVP_EncryptInit(ctx, EVP_aes_192_cbc(), key, ivec) != 1) {
        err = ERR_get_error();
        LOG_DEBUG("ERR: EVP_EncryptInit() - %s\n", ERR_error_string (err, NULL));
        return -1;
    }
    
    if (EVP_EncryptUpdate(ctx, cipherText, &orgLen, plainText, plainTextLen) != 1) {
        err = ERR_get_error();
        LOG_DEBUG("ERR: EVP_EncryptUpdate() - %s\n", ERR_error_string (err, NULL));
        return -1;
    }

    if (EVP_EncryptFinal(ctx, cipherText+orgLen, &addLen) != 1) {
        err = ERR_get_error();
        LOG_DEBUG("ERR: EVP_EncryptFinal() - %s\n", ERR_error_string (err, NULL));
        return -1;
    }
    
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
        LOG_DEBUG("ERR: EVP_DecryptInit() - %s\n", ERR_error_string (err, NULL));
        return -1;
    }
    if (EVP_DecryptUpdate(ctx, plainText, &toLen, cipherText, cipherTextLen) != 1) {
        err = ERR_get_error();
        LOG_DEBUG("ERR: EVP_DecryptUpdate() - %s\n", ERR_error_string (err, NULL));
        return -1;
    }

    if (EVP_DecryptFinal(ctx, &plainText[cipherTextLen], &outLen) != 1) {
        err = ERR_get_error();
        LOG_DEBUG("ERR: EVP_DecryptFinal() - %s\n", ERR_error_string (err, NULL));
        return -1;
    }

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    ERR_free_strings();

    return toLen+outLen;
}

int hex2val(const char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';  /* Simple ASCII arithmetic */
    else if (ch >= 'a' && ch <= 'f')
        return 10 + ch - 'a';  /* Because hex-digit a is ten */
    else if (ch >= 'A' && ch <= 'F')
        return 10 + ch - 'A';  /* Because hex-digit A is ten */
    else
        return -1;  /* Not a valid hexadecimal digit */
}

char * hexbuf2buf(const char * hexbuf)
{
    unsigned char * resbuf;
    resbuf = malloc(strlen(hexbuf) / 2);
    for (size_t i = 0, j = 0; i< strlen(hexbuf); i +=2, ++j) {
        int digit1 = hex2val(hexbuf[i]);
        int digit2 = hex2val(hexbuf[i + 1]);

        if (digit1 == -1 || digit2 == -1)
            continue;

        resbuf[j] = (char) (digit1 * 16 + digit2);
    }

    return resbuf;
}
