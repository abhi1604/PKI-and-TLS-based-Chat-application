#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

int main(int argc, char*argv[]) {
    X509 *cert = NULL;
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL *ssl;
    int server = 0;
    
    char *dest_url 
                   = "https://localhost:5002";
                // = argv[1];
    const char *hostName = 
    "127.0.0.1";
    // "localhost";
    int port = 5002;
    if(argc!=5) {
        fprintf(stdout, "%s ip:port ca.pem cert.pem key.pem\n", argv[0]);
        return -1;
    }
    const char *ca_pem = argv[2];
    const char *cert_pem = argv[3];
    const char *key_pem = argv[4];

    SSL_library_init();

    method = SSLv23_client_method();
    
    if(!method) {
        fprintf(stderr, "Cannot create TLS_client_method\n");
        return -1;
    }
    
    /* Create New SSL Context */
    if (!(ctx = SSL_CTX_new(method)))
    {
        fprintf(stderr, "Cannot create a client context\n");
        return -1;
    }

    /* Load the CA's certificate */
    if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1)
    {
        fprintf(stderr, "Cannot load CA's certificate file\n");
        SSL_CTX_free(ctx);
        return -1;
    }

    /* Load the client's certificate */
    if (SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Cannot load client's certificate file\n");
        SSL_CTX_free(ctx);
        return -1;
    }

    /* Load the client's key */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Cannot load client's key file\n");
        SSL_CTX_free(ctx);
        return -1;
    }

    /* Verify that the client's certificate and the key match */
    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        fprintf(stderr, "Client's certificate and key don't match\n");
        SSL_CTX_free(ctx);
        return -1;
    }

    /* We won't handle incomplete read/writes due to renegotiation */
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    /* Specify that we need to verify the server's certificate 
     * SSL_VERIFY_FAIL_IF_NO_PEER_CERT: Request Client Verification and if verification fails then donot proceed
    */

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);


    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostName)) == NULL)
    {
        perror(hostName);
        return -1;
    }
    server = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    int tt = sizeof(addr);

    if (connect(server, (struct sockaddr *)&addr, (socklen_t)tt) != 0) {
        close(server);
        perror(hostName);
        fprintf(stdout, "cannot create COnnection to server\n");
        return -1;
    }

    printf("connected TO server, establishing ssl handshake\n");

    ssl = SSL_new(ctx);
    
    SSL_set_fd(ssl, server);

    if (SSL_connect(ssl) != 1)
        fprintf(stderr, "Error: Could not build a SSL session to: %s.\n", dest_url);
    else
        fprintf(stdout, "Successfully enabled SSL/TLS session to: %s.\n", dest_url);
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if (cert != NULL)
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line); /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);      /* free the malloc'ed string */
        X509_free(cert); /* free the malloc'ed certificate copy */
    }
    char *msg = "Hi, I am client";
    SSL_write(ssl, msg, strlen(msg));
    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}
