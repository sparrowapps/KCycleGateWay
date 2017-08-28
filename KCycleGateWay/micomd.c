 
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
#include "micomd.h"
#include "uart.h"
#include "wiringPi.h"
#include "ssltest.h"
#include "logger.h"
#include "base64.h"

#define RST 9
#define PIO 7

#define CRL_AES192_KEY      24
#define CRL_AES_BLOCK       16
#define MAX_DEVICES         256

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
int cmd_state = -1; // 이전 커맨드 id
int list_end = 0;   // 
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
int pair_status = 0; // pair 유무 UNPARED 문자 확인 
int data_status = 0; // AT 커맨드로 데이터를 처리 할때 data_status 1
int rst_status = 0;  // AT reset 처리 했을때 1
int device_idx = 0; 

// 계측기 리스트 
typedef struct list_id {
    BYTE dev_addr;
    BYTE dev_id[3];
} list;

list devices[MAX_DEVICES];

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

// ssl http write 
int ssl_write(unsigned char * msg, unsigned char ** outmsg, int * outmsglen) {
    unsigned char * buf;
    int bytes = 0;

    SSL_OPEN_TO_SERVER sslOpenToServer;

    if (SSLOpenToServer(&sslOpenToServer, HTTPS_IP_ADDR, HTTPS_PORT_NUM) != SSL_OPEN_TO_SERVER_SUCCESS)
    {
        puts("SSLOpenToServer fail\n");
        return -1;
    }

    SSL_write(sslOpenToServer.ssl, msg, strlen(msg));
    BIO_dump_fp(stdout, msg, strlen(msg));

    buf = malloc(MAX_HTTPS_PACKET_BUFFER);
    memset(buf,MAX_HTTPS_PACKET_BUFFER,0x00);

    bytes = SSL_read(sslOpenToServer.ssl, buf, MAX_HTTPS_PACKET_BUFFER);
    buf[bytes] = 0;

    LOG_DEBUG("\n https response %d bytes\n", bytes);
    BIO_dump_fp(stdout, buf, bytes);

    SSLCloseToServer(&sslOpenToServer);

    if (bytes != 0) { 
        *outmsg = buf;
        *outmsglen = bytes;
    } else {
        *outmsg = NULL;
        *outmsglen = 0;
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

int check_rf_data(PBYTE data_buf)
{
    int index = 0;

    if(memcmp(data_buf, AT_PAIR, 9) == 0)
    {
        LOG_DEBUG("parse REG.START\n");
    }
    else if(memcmp(data_buf, TOKEN_TGT, 3) == 0)
    {
        LOG_DEBUG("parse TGT\n");
    }
    else if(memcmp(data_buf, HEADER, 6) == 0 || memcmp(data_buf, AT_OK, 2) == 0)
    {
        char* token = NULL;
        char div[] = ",:\r\n";

        pair_status = 1;

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

        if(op_mode != 1 )
        {
            cmd_id = _AT_START;
            ipc_send_flag = 1;
            data_status = 1;
            LOG_DEBUG("send_message = %s , send_flag = %d\n", cmd_buffer[0], ipc_send_flag);
        }
        else 
        {
            if(rst_status == 1)
            {
                ipc_send_flag = 0;
                rst_status = 0;
                data_status = 0;
                cmd_state = _AT_USER_CMD;
                LOG_DEBUG("data receiving status................\n");
            }
            else
            {
               cmd_state = _AT_USER_CMD;
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
            else {
                LOG_DEBUG("token = %s\n", token);
                if(memcmp(token, PING_CHECK, 4) == 0)
                {
                    LOG_DEBUG("token = %s\n", token);
                    cmd_id = _AT_USER_CMD;
                    sprintf(cmd_buffer[14], "%d,ping\r\n", addr);
                    ipc_send_flag = 1;
                }
                else
                {
                    LOG_DEBUG("token = %s\n", token);
                    // 0100EF000001008505039C01106E950D2C3D178C051136BA50F51BE283
                    unsigned char base_decode[MAX_PACKET_BUFFER];
                    memset(base_decode, 0x00, sizeof(base_decode));

                    LOG_DEBUG("RF data : %s\n",token);
                    base64_decode(token, strlen(token) , base_decode);

                    LOG_DEBUG("base64 decode %02X , %02x\n", base_decode[0], base_decode[1]); 

                    //rf_data_parser(base_decode, addr); //응답 addr을 보내야 한다.
                    packet_process(base_decode, addr);
                }
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

        if(op_mode != 1)
        {
            cmd_id = _AT_START;
            ipc_send_flag = 1;
            LOG_DEBUG("send_message = %s , send_flag = %d\n", cmd_buffer[0], ipc_send_flag);
        }
        else 
        {
            if(rst_status == 1)
            {
                ipc_send_flag = 0;
                rst_status = 0;
                data_status = 0;
                cmd_state = _AT_USER_CMD;
                LOG_DEBUG("data receiving status................\n");
            }
            else
            {
                cmd_state = _AT_USER_CMD;
            }
        }
    }
    else if(memcmp(data_buf, AT_ST_HEADER, 8) == 0)
    {
        cmd_id = _AT_ACODE;
        data_status = 1;
        ipc_send_flag = 1;
    }
    else if(memcmp(data_buf, AT_LOCKED, 6) == 0)
    {
        cmd_id = _AT_ACODE;
        ipc_send_flag = 1;
    }
    else if(memcmp(data_buf, AT_PAIR, 9) == 0)
    {
        cmd_id = _AT_CMD_NONE;
        cmd_state = _AT_CMD_NONE;
        ipc_send_flag = 0;
    }
    else if(memcmp(data_buf, AT_REG_FAIL, 8) == 0)
    {
        cmd_id = _AT_CMD_NONE;
        cmd_state = _AT_CMD_NONE;
        ipc_send_flag = 0;
        pair_status = 0;
    }
    else if(memcmp(data_buf, AT_REG_OK, 6) == 0)
    {
        cmd_id = _AT_CMD_NONE;
        cmd_state = _AT_CMD_NONE;
        ipc_send_flag = 0;
        pair_status = 1;
    }
    else if(memcmp(data_buf, AT_OK, 2) == 0)
    {
        switch(cmd_state)
        {
            case _AT_ACODE:
#if 1
                if(pair_status == 1)
                {
                    cmd_id = _AT_LST_ID;
                    ipc_send_flag = 1;
                    device_idx = 0;
                    //rst_status = 1;
                }
                else
#endif
                {
                    cmd_id = _AT_MODE;
                    ipc_send_flag = 1;
                }
                break;

            case _AT_MODE:
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
                    cmd_id = _AT_FBND;
                    ipc_send_flag = 1;
                }
                break;

            case _AT_GRP_ID:
                grp_id[0] = 0x01;
                grp_id[1] = 0x35;
                grp_id[2] = 0x46;
                cmd_id = _AT_FBND;
                ipc_send_flag = 1;
                break;

            case _AT_FBND:
                rf_band = 3;
                cmd_id = _AT_MADD;
                ipc_send_flag = 1;
                break;

            case _AT_MADD:
                mod_address = 0;
                cmd_id = _AT_CHN;
                ipc_send_flag = 1;
                break;

            case _AT_CHN:
                rf_channel = 5;
                cmd_id = _AT_BCST;
                ipc_send_flag = 1;
                break;

            case _AT_BCST:
                bcst_status = 1;
                cmd_id = _AT_DRATE;
                ipc_send_flag = 1;
                break;

            case _AT_DRATE:
                data_rate = 2;
                cmd_id = _AT_RNDCH;
                ipc_send_flag = 1;
                break;

            case _AT_RNDCH:
                rand_channel = 0;
                cmd_id = _AT_ID;
                ipc_send_flag = 1;
                break;

            case _AT_PAIR:
                cmd_id = _AT_CMD_NONE;
                cmd_state = _AT_CMD_NONE;
                ipc_send_flag = 0;
                pair_status = 1;
                break;

            case _AT_ID:
                {
                    int i = 0;

                    for(i = 0; i < 3; i++)
                    {
                        hex_decode((char *)(data_buf + 3*i), 1, &dev_id[i]);

                        LOG_DEBUG("device_id[%d] = %x  \n", i, dev_id[i]);
                    }
                    cmd_id = _AT_PAIR;
                    ipc_send_flag = 1;
                }
                break;

            default:
                ipc_send_flag = 0;
                break;
        }
    }
    else if(cmd_state == _AT_ID)
    {
        int i = 0;
        
        for(i = 0; i < 3; i++)
        {
            hex_decode((char *)(data_buf + 3*i), 1, &dev_id[i]);
        
            LOG_DEBUG("device_id[%d] = %x    \n", i, dev_id[i]);
        }
        cmd_id = _AT_PAIR;
        ipc_send_flag = 1;
    }
    else if(cmd_state == _AT_LST_ID)
    {
        char* token = NULL;
        char div[] = ",\r\n";

        token = strtok((char *)data_buf, div);
        while(token != NULL)
        {
            LOG_DEBUG("token = %s   strlen = %d \n", token, strlen(token));

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
                    LOG_DEBUG("device_id[%d] = %x    \n", i, devices[device_idx].dev_id[i]);
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
                LOG_DEBUG("device[%d] addr = %d, id = [%x %x %x]\n", it, devices[it].dev_addr, devices[it].dev_id[0], devices[it].dev_id[1], devices[it].dev_id[2]);
            }

            cmd_id = _AT_RST;
            rst_status = 1;
            list_end = 0;
            data_status = 0;
            ipc_send_flag = 1;
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
    char senderid[3];
    short pn;
    char len;
    unsigned char * valuebuf;
    unsigned char * outpacket;

    valuebuf = malloc(MAX_PACKET_BYTE);
    outpacket = malloc(MAX_PACKET_BUFFER);
    memset(valuebuf, 0x00, MAX_PACKET_BYTE);
    memset(outpacket, 0x00, MAX_PACKET_BUFFER);
    int outpacketlen = 0;

    unsigned char base_encode[MAX_PACKET_BUFFER];
    memset(base_encode, 0x00, sizeof(base_encode));

    // 내아이디 얻기를 해야 함

    if ( extract_packet(inputpacket, &code, &subcode, senderid, &pn, &len, &valuebuf) == 0 ){
        switch (code)
        {
            case PACKET_CMD_PING_R:
            //todo 내 senderid 를 만들어야 한다.
                LOG_DEBUG("cmd PACKET_CMD_PING_R");
                outpacketlen = 0;

                senderid[0] = 0x00;
                senderid[1] = 0x00;
                senderid[2] = 0x01;
                make_packet(PACKET_CMD_PING_S, 0x00, senderid, 0, 5, "HELLO", &outpacket, &outpacketlen);
                
                BIO_dump_fp(stdout, outpacket, outpacketlen);
                
                base64_encode(outpacket, outpacketlen , base_encode);
                LOG_DEBUG("outpacketlen : %d", outpacketlen);
                ipc_send_flag = 1;
                sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", addr, base_encode);
                LOG_DEBUG("cmd_buffer : %s", cmd_buffer[_AT_USER_CMD]);
                cmd_id = _AT_USER_CMD;
                break;
        
            case PACKET_CMD_INSPECTION_REQ_R:
                //IR_LINE 성공 여부 기록
                if (valuebuf[0] == 0) {
                    //바퀴 인식 실패, IR인식 실패
                } else if (valuebuf[0] == 1) {
                    //바퀴 인식 성공, IR인식 실패
                } else if (valuebuf[0] == 2) {
                    //바퀴 인식 실패, IR인식 성공
                } else {
                    //성공, 성공
                }

                //응답 valuebuf ?? --> 0x00

                outpacketlen = 0;
                make_packet(PACKET_CMD_INSPECTION_REQ_S, 0x00, senderid, 0, 1, 0x00, &outpacket, &outpacketlen);
                
                base64_encode(outpacket, outpacketlen , base_encode);
                
                ipc_send_flag = 1;
                sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", addr, base_encode);
                cmd_id = _AT_USER_CMD;
                break;

            case PACKET_CMD_INSPECTION_RES_S:
                // todo 서버에 인크립션키를 요청 한다. 

                // 응답
                outpacketlen = 0;
                make_packet(PACKET_CMD_INSPECTION_RES_S, 0x00, senderid, 0, 0, NULL, &outpacket, &outpacketlen);
                
                base64_encode(outpacket, outpacketlen , base_encode);
                
                ipc_send_flag = 1;
                sprintf(cmd_buffer[_AT_USER_CMD], "%d,%s\r\n", addr, base_encode);
                cmd_id = _AT_USER_CMD;
                break;                

            default:
                //nothing todo
                break;
        }
    }

    free(valuebuf);
    free(outpacket);
    return 0;
}

// 입력 받은 패킷을 분해 한다.
int extract_packet (unsigned char * inputpacket, 
                    char * outcode, 
                    char * outsubcode, 
                    char * outsenderid, 
                    short * outpn, 
                    char * outlen, 
                    unsigned char ** outvalue)
{
    unsigned char dec_out[1000];

    outcode[0] = inputpacket[0];
    outsubcode[0] = inputpacket[1];
    
    outsenderid[0] = inputpacket[2];
    outsenderid[1] = inputpacket[3];
    outsenderid[2] = inputpacket[4];

    //pn = (short)(packetnumber[1] << 8) +  (short)(packetnumber[0]);
    *outpn = (short)inputpacket[5] + (short)(inputpacket[6] << 8);

    if (validate_ac(inputpacket + 2, *outpn, inputpacket + 2) == 0){
        *outlen = *(inputpacket + 12);
        
        //plaintext
#ifdef _PACKET_ENCRYPTY
        int decslength = decrypt_block(dec_out, inputpacket + 13, *outlen, Key, IV);
        memcpy(*outvalue, dec_out, decslength);
        LOG_DEBUG("plaintext :%s\n", *outvalue);
#else 
        memcpy(*outvalue, inputpacket + 13, *outlen);
        LOG_DEBUG("plaintext :%s\n", *outvalue);
#endif

        return 0;
    } else {
        LOG_DEBUG("AC fail \n");
        return -1;
    }
}

void make_packet(char code, 
                 char subcode, 
                 char * senderid, 
                 short pn, 
                 char len, 
                 char * value, 
                 unsigned char ** out_packet,
                 int * outlen)
{
    unsigned char packetbuf[MAX_PACKET_BUFFER];
    packetbuf[0] = code;
    packetbuf[1] = subcode;
    
    unsigned char * ac;
    unsigned char enc_out[1000];

    memset(enc_out, 0x00, sizeof(enc_out));
    ac = malloc(10);
    make_ac_code(senderid, pn, &ac);
    memcpy(packetbuf + 2, ac, 10);
    free(ac);

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
#endif        
    }
    BIO_dump_fp(stdout, packetbuf, 13 + encslength);
    memcpy(*out_packet, packetbuf, 13 + encslength);
    
    *outlen = 13 + encslength;
}

// AC 코드 확인
int validate_ac(char * senderid, short pn, unsigned char * acbuf)
{
#ifdef _PACKET_ENCRYPTY
    unsigned char * ac;
    ac = malloc(10);
    make_ac_code(senderid, pn, &ac);

    if ( memcmp(ac, acbuf, 10) == 0 ) {
        free (ac);
        return 0;
    } else {
        free(ac);
        return -1;
    }
#else 
    return 0;
#endif
}

// AC 코드 생성
void make_ac_code(char * senderid, short pn, unsigned char ** out_ac)
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
    memcpy(*out_ac, ac, sizeof(ac));
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
        if(list_end == 0 && cmd_state == _AT_LST_ID)
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

    LOG_DEBUG("parse_data ===> cmd_state[%d], index[%d]\n", cmd_state, index);
    if(cmd_state != -1 && cmd_state != _AT_START)
    {
        if(cmd_state == _AT_RST)
        {
            if(index >= 3)
            {
                LOG_DEBUG("parse_data ===> cmd_state[%d], index[%d]\n", cmd_state, index);
                return 1;
            }
            else
                return 0;
        }
        else
        {
            if(index == 1)
            {
                LOG_DEBUG("parse_data ===> cmd_state[%d], index[%d]\n", cmd_state, index);
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
            LOG_DEBUG("parse_data ===> cmd_state[%d], index[%d]\n", cmd_state, index);
            if(index >= 3)
            {
                LOG_DEBUG("parse_data ===> cmd_state[%d], index[%d]\n", cmd_state, index);
                return 1;
            }
            else
                return 0;
        }
        else
        {
            if(memcmp(data_buf, AT_ST_HEADER, 8) == 0)
            {
                LOG_DEBUG("parse_data ===> cmd_state[%d], index[%d]\n", cmd_state, index);
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


/*
← "++++<CR><LF>”
→ “AT.START<CR><LF>”
← "AT+ACODE=00 00 00 00<CR><LF>”
→ “OK<CR><LF>”
   --> rf모듈과 AT 커맨드를 쓰겠다.

← AT+LST_ID?<CR><LF>
→ “50 00 1F<CR><LF>”
   --> 내 아이디를 얻는다.

계측기 ID 리스트 구축
← AT+LST_ID?<CR><LF> 
→ “0,30 00 1F<CR><LF>” 
→ “<CR><LF>”
   --> 페어링된 아이디 리스트를 얻는다.

← "AT+RST=1<CR><LF>”
→ “OK<CR><LF>”
→ ”RDY SW:BA05.0<CR><LF>”
→ ”BAND:3,CHN:0,DRATE:2,MODE:0<CR><LF>” → ”UNPAIRED<CR><LF>”
→ ”<CR><LF>”
   -->무선통신 모드로 전환


   페어링 리스트를 확인 없으면 
   페어링 정보를 얻어다가
   페어링 정보를 저장 한다.
   페어링 정보를 서버가 주면 페어링 정보를 AT커맨드로 갱신한다.

*/

#if 0
// 이전 main code
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
