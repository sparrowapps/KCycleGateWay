/*
 ============================================================================
 Name        : ssltest.h
 Author      : pjh
 Version     : 1.0
 Date        : 2017.05.18
 Copyright   : 막 쓰세요~
 Description : openssl api를 사용한 ssl test
 	 	 	 	 springboot를 사용한 tomcat과 test되었음
 ============================================================================
 */

#include <string.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct SSLOpenToServer_st {
    SSL_CTX *ctx;
    SSL *ssl;
    int socketDescriptor;
    char hostName[16];
    char portNumber[10];
} SSL_OPEN_TO_SERVER;

// SSLOpenToServer return code
# define SSL_OPEN_TO_SERVER_SUCCESS							1
# define SSL_OPEN_TO_SERVER_FAIL_TO_NEW_SSL_CTX				2
# define SSL_OPEN_TO_SERVER_FAIL_TO_GET_HOST_BY_NAME		3
# define SSL_OPEN_TO_SERVER_FAIL_TO_CREATE_SOCKET			4
# define SSL_OPEN_TO_SERVER_FAIL_TO_CONNECT					5
# define SSL_OPEN_TO_SERVER_FAIL_TO_NEW_SSL					6
# define SSL_OPEN_TO_SERVER_FAIL_TO_HANDSHAKE				7

int SSLOpenToServer(SSL_OPEN_TO_SERVER *sslOpenToServer, char *hostName, char *portNumber);
void SSLCloseToServer(SSL_OPEN_TO_SERVER *sslOpenToServer);
