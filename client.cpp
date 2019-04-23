#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
/* 
 * hostname: url or ip:port to connect
 * ca_pem : Cert of CA
 * cert_pem : 
 * cert_pem my Certificate
 * key_pem : my private key
*/
int client(const char *hostname, const char *ca_pem, const char *cert_pem, const char *key_pem) {
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    int bytes;
    X509 *cert = NULL;
    X509_NAME *certname = NULL;
    int port = 
    // char *hostname, *portnum;

    SSL_library_init();
    if (!(ctx = SSL_CTX_new(TLS_client_method())))
    {
        fprintf(stderr, "Cannot create a client context\n");
        return NULL;
    }

    // #TODO :Give bunch of certificates.....

    /* Load the client's CA file location */
    if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1)
    {
        fprintf(stderr, "Cannot load CA's certificate file\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Load the client's certificate */
    if (SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Cannot load client's certificate file\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Load the client's key */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Cannot load client's key file\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Verify that the client's certificate and the key match */
    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        fprintf(stderr, "Client's certificate and key don't match\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        abort();
    }
    server = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long *)(host->h_addr);
    int tt = sizeof(addr);
    if (connect(server, (struct sockaddr *)&addr, (socklen_t)tt) != 0)
    {
        close(server);
        perror(hostname);
        SSL_CTX_free(ctx);
        exit(1);
    }
    SSL_set_fd(ssl, server);
 
    if (SSL_connect(ssl) == -1) /* perform the connection */ 
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    cert = SSL_get_peer_certificate(ssl);
    certname = X509_NAME_new();
    certname = X509_get_subject_name(cert);
    X509_NAME_print_ex_fp(stdout, certname, 0, 0);
}
