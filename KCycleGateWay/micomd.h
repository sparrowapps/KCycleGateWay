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

#define HTTPS_IP_ADDR          "192.168.11.15" //"160.100.1.147"
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

#define MAX_HTTPS_PACKET_BUFFER 8192
#define MAX_RACERS              9 //경기당 최대 선수
#define RACE_RESULT_PACKET_SIZE (4*35)

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

//HTTPS 헤더 뼈다귀 url, IP, PORT, json string
#define HTTPS_HEADER "POST %s HTTP/1.1\n\
Host: %s:%s\n\
Connection: keep-alive\n\
Cache-Control: max-age=0\n\
Upgrade-Insecure-Requests: 1\n\
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n\
Accept-Encoding: gzip, deflate, sdch, br\n\
Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.6,en;q=0.4\n\
Cookie: JSESSIONID=5EBE4E35EBC10452C92EC291149B798F\n\
Content-Length: %d\n\
Content-Type: application/json\n\
\n\
%s\
"
/*
    "++++\r\n",                         //  0
    "AT+ACODE=00 00 00 00\r\n",         //  1
    "AT+MMODE=1\r\n",                   //  2
    "AT+GRP_ID=%02X %02X %02X\r\n",     //  3 
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
    "AT+REG_#ID=2, 01 23 45\r\n"        // 14
    "",
*/

#define AT_GRP_ID_FMT   "AT+GRP_ID=%02X %02X %02X\r\n"
#define AT_FBAND_FMT    "AT+FBND=%d\r\n"
#define AT_CHN_FMT      "AT+CHN=%d\r\n"
#define AT_DRATE_FMT    "AT+DRATE=%d\r\n"
#define AT_REG_ID_FMT   "AT+REG_#ID=%d,%02X %02X %02X\r\n"

#define AT_GRPx_ID_FMT   "AT+GRP%d_ID=%02X %02X %02X\r\n"
#define AT_FxBAND_FMT    "AT+F%dBND=%d\r\n"
#define AT_xCHN_FMT      "AT+%dCHN=%d\r\n"
#define AT_DxRATE_FMT    "AT+D%dRATE=%d\r\n"

typedef enum AT_CMD {               
    _AT_START    = 0,       
    _AT_ACODE    = 1,       
    _AT_MODE     = 2,       
    _AT_GRP_ID   = 3,       
    _AT_FBND     = 4,       
    _AT_MADD     = 5,       
    _AT_CHN      = 6, 
    _AT_BCST     = 7,
    _AT_DRATE    = 8,
    _AT_RNDCH    = 9,
    _AT_PAIR     = 10,       
    _AT_ID       = 11,
    _AT_RST      = 12,
    _AT_LST_ID   = 13,
    _AT_REG_ID   = 14,
    _AT_GRP_ID_GET = 15,
    _AT_MADD_GET   = 16,
    _AT_USER_CMD = 17, 
    _AT_CMD_NONE = 19, 
} AT_CMD_TYPE;          

typedef enum DATA_STATUS {
    _DATA_RF_MODE = 0,
    _DATA_AT_MODE = 1
} DATA_STATUS_TYPE;

typedef enum PAIR_STATUS {
    _UNPAIRED = 0,
    _PAIRED = 1,
} PAIR_STATUS_TYPE;

typedef enum REST_STATUS {
    _RESET_NONE = 0,
    _RESET_STATUS = 1,
} RESET_STATUS_TYPE;

typedef enum MANUAL_PAIRING_STATUS {
    _MANUAL_PAIRING_NONE = 0,
    _MANUAL_PAIRING_STATUS = 1,
} MANUAL_PAIRING_STATUS_TYPE;

// 계측기 리스트 
typedef struct list_id {
    BYTE dev_addr;
    BYTE dev_id[3];
} list;

// suffix _R receive (디바이스로 부터 받는다.)
// suffix _S send    (게이트 웨이가 전송)
#define PACKET_CMD_PING_R           0x01
#define PACKET_CMD_PING_S           0x02

#define PACKET_CMD_INSPECTION_REQ_S 0x03
#define PACKET_CMD_INSPECTION_REQ_R 0x04

#define PACKET_CMD_INSPECTION_RES_R 0x05
#define PACKET_CMD_INSPECTION_RES_S 0x06

#define PACKET_CMD_ENCKEY_REQ_R     0x07
#define PACKET_CMD_ENCKEY_REQ_S     0x08

#define PACKET_CMD_LOGCHK_R         0x09
#define PACKET_CMD_LOGCHK_S         0x0A

#define PACKET_CMD_ERRORCHK_R       0x0D
#define PACKET_CMD_ERRORCHK_S       0x0E

#define PACKET_CMD_TRAININGSTART_S  0x10
#define PACKET_CMD_TRAININGSTART_R  0x11

#define PACKET_CMD_TRAININGSTOP_S   0x12
#define PACKET_CMD_TRAININGSTOP_R   0x13

#define PACKET_CMD_DASHSTART_S      0x14
#define PACKET_CMD_DASHSTART_R      0x15

#define PACKET_CMD_DASHSTOP_S       0x16
#define PACKET_CMD_DASHSTOP_R       0x17

#define PACKET_CMD_DASHRESULT_R     0x18
#define PACKET_CMD_DASHRESULT_S     0x19

#define PACKET_CMD_RACESTATECHK_R   0x30
#define PACKET_CMD_RACESTATECHK_S   0x31

// GUN에서 출발 명령을 받으면 디바이스에게 PACKET_CMD_RACESTART_S 전송 하는 기능을 수행 한다.
#define PACKET_CMD_RACESTART_GUN_R  0xA0
#define PACKET_CMD_RACESTART_GUN_S  0xA1
#define PACKET_CMD_RACESTART_GUN2_R  0xA2
#define PACKET_CMD_RACESTART_GUN2_S  0xA3


#define PACKET_CMD_RACESTART_S      0x32
#define PACKET_CMD_RACESTART_R      0x33

#define PACKET_CMD_RACESTOP_S       0x34
#define PACKET_CMD_RACESTOP_R       0x35

// 경기가 끝났음을 디바이스가 서버에 알린다.
#define PACKET_CMD_RACE_END_R       0x36
#define PACKET_CMD_RACE_END_S       0x37

#define PACKET_CMD_RACELINERESULT_R 0x40
#define PACKET_CMD_RACELINERESULT_S 0x41

// cycle result loop 이후 누락된 라인 결과를 전송
#define PACKET_CMD_RACELINERESULT_EXTRA_S 0x42
#define PACKET_CMD_RACELINERESULT_EXTRA_R 0x43

#define PACKET_CMD_RACERESULT_READY_S 0x44
#define PACKET_CMD_RACERESULT_READY_R 0x45

#define PACKET_CMD_RACERESULT_REQ_S 0x46
#define PACKET_CMD_RACERESULT_REQ_R 0x47

#define PACKET_CMD_RACECYCLESULT_R  0x48
#define PACKET_CMD_RACECYCLESULT_S  0x49

#define RST 9
#define PIO 7

#define CRL_AES192_KEY      24
#define CRL_AES_BLOCK       16
#define MAX_DEVICES         256


int create_socket (int portnum);
int read_packet (int fd, int cnt, PBYTE buf, int fd_index);
int check_socket (PBYTE data_buf, WORD size, int fd);
int check_rf_data(PBYTE data_buf);
int check_uart (PBYTE data_buf);

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
                 int addr,
                 char len, 
                 char * value, 
                 unsigned char * out_packet,
                 int * outlen);

int validate_ac(char * senderid, short pn, unsigned char * acbuf);
void make_ac_code(char * senderid, short pn, unsigned char * out_ac);
char * hexbuf2buf(const char * hexbuf);
int hex2val(const char ch);

int extract_packet (unsigned char * inputpacket, char * outcode, char * outsubcode, char * outsenderid, short * outpn, char * outlen, unsigned char * outvalue);
int packet_process(unsigned char * inputpacket, int addr);

int getAddrFromDevices(char * dev_id);
char * getDevIDFromDevices(int dev_addr);
void make_date_data(char * outtime_val);

void putRacer(int addr);
int getRacerIndex(int addr);

//micomd extern global variable
extern int cnt_fd_socket;
extern int list_end;
extern int cmd_state;
extern DATA_STATUS_TYPE data_status;
extern int fd_masks[MAX_SOCKET_FD];
extern unsigned char cmd_buffer[MAX_CMD][MAX_PACKET_BUFFER];
extern int cmd_id;
extern int ipc_send_flag;
extern BYTE dev_id[3];
extern unsigned char Key[CRL_AES192_KEY];
extern list devices[MAX_DEVICES]; // 페어링 정보를 여기에 넣는다.
extern int devices_count;
extern MANUAL_PAIRING_STATUS_TYPE manaual_pairinig_status;

extern int packetnumberArray[MAX_DEVICES];
extern int gatewayPacketNumber;
extern int device_idx;

extern char race_res_buf[MAX_RACERS][MAX_HTTPS_PACKET_BUFFER];
extern int race_res_offset[MAX_RACERS]; //버퍼링 오프셋
extern int racer_idx[MAX_RACERS]; //addr로 레이서 index를 기롥
extern int racer_count;
extern int racer_addr[MAX_RACERS];
#endif /* _MICOM_H_ */

