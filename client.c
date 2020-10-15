#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <openssl/ssl.h>

int init_ctx(
    SSL_CTX** ctx);

int del_ctx(SSL_CTX* ctx);

int init_ssl(
    SSL** ssl, 
    SSL_CTX * const ctx, 
    int sock);

int del_ssl(SSL* ssl);

int main(int argc, char **argv)
{
    SSL_CTX * ctx;
    SSL * ssl;
    struct sockaddr_rc addr = { 0 };
    int s, status;
    char buf[1024];
    char dest[18] = "B8:27:EB:BD:05:2B";

    init_ctx(&ctx);

    // allocate a socket
    s = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);

    // set the connection parameters (who to connect to)
    addr.rc_family = AF_BLUETOOTH;
    addr.rc_channel = (uint8_t) 1;
    str2ba( dest, &addr.rc_bdaddr );

    // connect to server
    status = connect(s, (struct sockaddr *)&addr, sizeof(addr));
    
    init_ssl(&ssl,ctx,s);
    
    SSL_connect(ssl);

    // send a message
    if( status == 0 ) {
        status = SSL_write(ssl, "hello!", 6);
    }

    SSL_read(ssl,buf,1024);

    puts(buf);

    if( status < 0 ) perror("uh oh");

    del_ssl(ssl);
    del_ctx(ctx);
    return 0;
}

int init_ctx(
    SSL_CTX** ctx)
{
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    *ctx = SSL_CTX_new(TLS_client_method());
    return 0;
}

int del_ctx(SSL_CTX* ctx)
{
    SSL_CTX_free(ctx);
    return 0;
}

int init_ssl(
    SSL** ssl, 
    SSL_CTX * const ctx, 
    int sock)
{
    *ssl = SSL_new(ctx);
    SSL_set_fd(*ssl,sock);
    return 0;
}

int del_ssl(SSL* ssl)
{
    SSL_shutdown(ssl);
    close(SSL_get_fd(ssl));
    SSL_free(ssl);
    return 0;
}
