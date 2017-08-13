#ifndef _MICOM_H_
#define _MICOM_H_

typedef unsigned char          BYTE;
typedef unsigned char*         PBYTE;
typedef unsigned short         WORD;
typedef unsigned long long     LONG;
typedef unsigned long int      DWORD;
typedef signed long int        INT32;

#define SOCK_IP_ADDR           "127.0.0.1"
#define PORT_NUM               8443

#define HTTPS_IP_ADDR          "160.100.1.147"
#define HTTPS_PORT_NUM         "443"

/* fd index */
#define UART                   1
#define SOCKET                 2


#define TOKEN_TGT             "TGT"
#define TOKEN_GID             "GID"
#define TOKEN_CH              "CH"
#define TOKEN_DR              "DR"
#define TOKEN_MADD            "M.ADD"
#define TOKEN_DADD            "D.ADD"
#define TOKEN_BCST            "BCST"

#define HEADER                 "RDY SW"
#define AT_ST_HEADER           "AT.START"
#define AT_LOCKED              "LOCKED"
#define AT_PAIR                "REG.START"
#define AT_REG_FAIL            "REG.FAIL"
#define AT_REG_OK              "REG.OK"
#define AT_OK                  "OK"
#define TOKEN_BAND             "BAND"
#define TOKEN_CHN              "CHN"
#define TOKEN_DRATE            "DRATE"
#define TOKEN_MODE             "MODE"
#define TOKEN_UNPAIR           "UNPAIRED"
#define PING_CHECK             "ping"

#define MAX_SOCKET_FD          0xFF

#define MAX_PACKET_BYTE        256
#define MAX_PACKET_BUFFER      2048
#define NUM_FD                 7    // the number of file descriptors
#define MAX_QUEUE_SIZE         1024
#define MAX_MASK_BYTE          11
#define MAX_CMD                20

#define MAX_HTTPS_PACKET_BUFFER 4096

#define HTTP_MSG_WHATISMYJOB    "GET /gateway/whatismyjob?jobno=%s HTTP/1.1\n\
Host: %s:%s\n\
Connection: keep-alive\n\
Cache-Control: max-age=0\n\
Upgrade-Insecure-Requests: 1\n\
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n\
Accept-Encoding: gzip, deflate, sdch, br\n\
Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.6,en;q=0.4\n\
Cookie: JSESSIONID=5EBE4E35EBC10452C92EC291149B798F\n\
\n\
"

#define HTTP_MSG_CHANGESTATUS_ALLOFF    "GET /gateway/changeStatusAllOff HTTP/1.1\n\
Host: %s:%s\n\
Connection: keep-alive\n\
Cache-Control: max-age=0\n\
Upgrade-Insecure-Requests: 1\n\
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n\
Accept-Encoding: gzip, deflate, sdch, br\n\
Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.6,en;q=0.4\n\
Cookie: JSESSIONID=5EBE4E35EBC10452C92EC291149B798F\n\
\n\
"

#define HTTP_MSG_HELLO   "POST /gateway/hello HTTP/1.1\n\
Host: %s:%s\n\
Connection: keep-alive\n\
Cache-Control: max-age=0\n\
Upgrade-Insecure-Requests: 1\n\
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n\
Accept-Encoding: gzip, deflate, sdch, br\n\
Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.6,en;q=0.4\n\
Cookie: JSESSIONID=5EBE4E35EBC10452C92EC291149B798F\n\
Content-Length: 61\n\
Content-Type: application/json\n\
\n\
{\"data\":\"01020304050607080910111213141516171819202122232425\"}\
"

typedef enum AT_CMD {
    _AT_START = 0,
    _AT_ACODE = 1,
    _AT_MODE  = 2,
    _AT_GRP_ID = 3,
    _AT_FBND  = 4,
    _AT_MADD  = 5,
    _AT_CHN   = 6, 
    _AT_BCST  = 7,
    _AT_DRATE = 8,
    _AT_RNDCH = 9,
    _AT_PAIR  = 10,
    _AT_ID    = 11,
    _AT_RST   = 12,
    _AT_LST_ID = 13,
    _AT_USER_CMD = 14,
} AT_CMD_TYPE;

#define PACKET_CMD_PING_R           0x01
#define PACKET_CMD_PING_S           0x02

#define PACKET_CMD_INSPECTION_R     0x03
#define PACKET_CMD_INSPECTION_S     0x04

#define PACKET_CMD_ENCKEYREQMSG_R   0x05
#define PACKET_CMD_ENCKEYREQMSG_S   0x06

#define PACKET_CMD_ENCKEYRESMSG_R   0x07
#define PACKET_CMD_ENCKEYRESMSG_S   0x08

#define PACKET_CMD_LOGCHK_R         0x09
#define PACKET_CMD_LOGCHK_S         0x0A

#define PACKET_CMD_PAIRINGINFO_R    0x0B
#define PACKET_CMD_PAIRINGINFO_S    0x0C

#define PACKET_CMD_ERRORCHK_R       0x0D
#define PACKET_CMD_ERRORCHK_S       0x0E

#define PACKET_CMD_TRAININGSTART_R  0x10
#define PACKET_CMD_TRAININGSTART_S  0x11

#define PACKET_CMD_TRAININGSTOP_R   0x12
#define PACKET_CMD_TRAININGSTOP_S   0x13

#define PACKET_CMD_DASHSTART_R      0x14
#define PACKET_CMD_DASHSTART_S      0x15

#define PACKET_CMD_DASHSTOP_R       0x16
#define PACKET_CMD_DASHSTOP_S       0x17

#define PACKET_CMD_DASHRESULT_R     0x18
#define PACKET_CMD_DASHRESULT_S     0x19

#define PACKET_CMD_RACESTATECHK_R   0x30
#define PACKET_CMD_RACESTATECHK_S   0x31
#define PACKET_CMD_RACESTATECHK2_R  0x32

#define PACKET_CMD_RACESTARTTIME_R  0x33
#define PACKET_CMD_RACESTARTTIME_S  0x34

#define PACKET_CMD_RACELINERESULT_R 0x35
#define PACKET_CMD_RACELINERESULT_S 0x36

#define PACKET_CMD_RACECYCLESULT_R  0x37
#define PACKET_CMD_RACECYCLESULT_S  0x38

int create_socket (int portnum);
int read_packet (int fd, int cnt, PBYTE buf, int fd_index);
int check_socket (PBYTE data_buf, WORD size, int fd);
int check_rf_data(PBYTE data_buf);
int check_uart (PBYTE data_buf);
int rf_data_parser(PBYTE data_buf);
BYTE* hex_decode(char *in, int len, BYTE *out);
int parse_data (PBYTE data_buf, int *cnt);
int get_max_fd (int a, int b, int c);
void send_socket_control_data(PBYTE data_buf, int length);
int write_packet (int fd, PBYTE pbuf, int size);

int encrypt_block(unsigned char* cipherText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key, unsigned char* ivec);
int decrypt_block(unsigned char* plainText, unsigned char* cipherText, unsigned int cipherTextLen, unsigned char* key, unsigned char* ivec);
int ssl_write(unsigned char * msg, unsigned char ** outmsg, int * outmsglen);
int init_wiringPi();
int open_uart();

int del_socket(int fd);
int mk_fds(fd_set *fds, int fd_max);
int add_socket(int fd);

//packet
void make_packet(char code, 
                 char subcode, 
                 char * senderid, 
                 short pn, 
                 char len, 
                 char * value, 
                 unsigned char ** out_packet,
                 int * outlen);

int validate_ac(char * senderid, short pn, unsigned char * acbuf);
void make_ac_code(char * senderid, short pn, unsigned char ** out_ac);
char * hexbuf2buf(const char * hexbuf);
int hex2val(const char ch);

int extract_packet (unsigned char * inputpacket, char * outcode, char * outsubcode, char * outsenderid, short * outpn, char * outlen, unsigned char ** outvalue);
void aestest();
#endif /* _MICOM_H_ */

