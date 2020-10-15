#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <openssl/ssl.h>

int init_ctx(
    SSL_CTX** ctx, 
    const char * const cert_path, 
    const char * const key_path);

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
    struct sockaddr_rc loc_addr = { 0 }, rem_addr = { 0 };
    char buf[1024] = { 0 };
    int s, client, bytes_read;
    socklen_t opt = sizeof(rem_addr);

    // allocate socket
    s = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);

    init_ctx(&ctx,"cert.pem","key.pem");

    // bind socket to port 1 of the first available 
    // local bluetooth adapter
    loc_addr.rc_family = AF_BLUETOOTH;
    loc_addr.rc_bdaddr = *BDADDR_ANY;
    loc_addr.rc_channel = (uint8_t) 1;
    bind(s, (struct sockaddr *)&loc_addr, sizeof(loc_addr));

    // put socket into listening mode
    listen(s, 1);

    // accept one connection
    client = accept(s, (struct sockaddr *)&rem_addr, &opt);

    init_ssl(&ssl,ctx,client);

    ba2str( &rem_addr.rc_bdaddr, buf );
    fprintf(stderr, "accepted connection from %s\n", buf);
    memset(buf, 0, sizeof(buf));

    SSL_accept(ssl);

    // read data from the client
    int bytes = SSL_read(ssl,buf,1024);
    SSL_write(ssl,buf,bytes);

    del_ssl(ssl);
    del_ctx(ctx);

    // close connection
    close(s);
    return 0;
}

int init_ctx(
    SSL_CTX** ctx, 
    const char * const cert_path, 
    const char * const key_path)
{
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate_file(*ctx,cert_path,SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(*ctx,key_path,SSL_FILETYPE_PEM);
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