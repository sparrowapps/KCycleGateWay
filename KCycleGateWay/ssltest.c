/*
 ============================================================================
 Name        : ssltest.c
 Author      : pjh
 Version     : 1.0
 Date        : 2017.05.18
 Copyright   : 막 쓰세요~
 Description : openssl api를 사용한 ssl test
                                 springboot를 사용한 tomcat과 test되었음
 ============================================================================
 */

#include "ssltest.h"

int SSLOpenToServer(SSL_OPEN_TO_SERVER *sslOpenToServer, char *hostName, char *portNumber)
{
       SSL_METHOD *method;

    strcpy(sslOpenToServer->hostName, hostName);
    strcpy(sslOpenToServer->portNumber, portNumber);


       // SSL library init
    SSL_library_init();
 
       // crypto에서 모든 algrithm을 load
       OpenSSL_add_all_algorithms();

       // error message를 load
       SSL_load_error_strings();

       // TLS1(=SSL3)를 사용한다고 설정
       method = TLSv1_2_client_method();

 
       // create SSL context
       sslOpenToServer->ctx = SSL_CTX_new(method);
       

	if ( sslOpenToServer->ctx == NULL )
       {
              ERR_print_errors_fp(stderr);
              return SSL_OPEN_TO_SERVER_FAIL_TO_NEW_SSL_CTX;
       }

    {
        struct hostent *host;
        struct sockaddr_in addr;
        int port;

 
        if ( (host = gethostbyname(sslOpenToServer->hostName)) == NULL )
        {
            perror(sslOpenToServer->hostName);
                  return SSL_OPEN_TO_SERVER_FAIL_TO_GET_HOST_BY_NAME;
        }
              port = atoi(sslOpenToServer->portNumber);
              sslOpenToServer->socketDescriptor = socket(PF_INET, SOCK_STREAM, 0);
        if ( sslOpenToServer->socketDescriptor == -1 )
        {
            perror(sslOpenToServer->hostName);
                  return SSL_OPEN_TO_SERVER_FAIL_TO_CREATE_SOCKET;
        }
 
        bzero(&addr, sizeof(addr));

        addr.sin_family = AF_INET;

        addr.sin_port = htons(port);
 
        
        //addr.sin_addr.s_addr = *(long*)(host->h_addr);
        addr.sin_addr.s_addr = *(long*)(host->h_addr_list[0]);
        if ( connect(sslOpenToServer->socketDescriptor, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
        {
            close(sslOpenToServer->socketDescriptor);
            perror(sslOpenToServer->hostName);
                  return SSL_OPEN_TO_SERVER_FAIL_TO_CONNECT;
        }
    }

    // create SSL connection
    sslOpenToServer->ssl = SSL_new(sslOpenToServer->ctx);      /* create new SSL connection state */
    if (sslOpenToServer->ssl == NULL)
    {
        ERR_print_errors_fp(stderr);
              return SSL_OPEN_TO_SERVER_FAIL_TO_NEW_SSL;
    }

    // SSL에서 사용할 socket 정보 전달
    SSL_set_fd(sslOpenToServer->ssl, sslOpenToServer->socketDescriptor);    /* attach the socket descriptor */

    // SSL handshake
    if ( SSL_connect(sslOpenToServer->ssl) == -1 )
    {
        ERR_print_errors_fp(stderr);
              return SSL_OPEN_TO_SERVER_FAIL_TO_HANDSHAKE;
    }

    // log : cipher suite
       printf("Cipher suite : %s\n", SSL_get_cipher(sslOpenToServer->ssl));

    return SSL_OPEN_TO_SERVER_SUCCESS;
}

void SSLCloseToServer(SSL_OPEN_TO_SERVER *sslOpenToServer)
{
       if (sslOpenToServer->ssl != NULL)
       {
              SSL_free(sslOpenToServer->ssl);        /* release connection state */
              sslOpenToServer->ssl = NULL;
       }
       if (sslOpenToServer->socketDescriptor != -1)
       {
              close(sslOpenToServer->socketDescriptor);         /* close socket */
              sslOpenToServer->socketDescriptor = -1;
       }
       if (sslOpenToServer->ctx != NULL)
       {
              SSL_CTX_free(sslOpenToServer->ctx);        /* release context */
              sslOpenToServer->ctx = NULL;
       }
}

