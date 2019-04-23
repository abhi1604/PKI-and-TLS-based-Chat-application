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

#define BUFSIZE 128

int main(int argc, char*argv[]) {
    static char buffer[BUFSIZE];
    struct sockaddr_in sin;
    socklen_t sin_len;
    SSL_CTX *ctx;
    SSL *ssl;
    int listen_fd, net_fd, rc, len;
    int val;


    // X509 *cert = NULL;
    const SSL_METHOD *method;
    int server = 0;
    
    int port_num = 5002;
    if(argc!=5) {
        fprintf(stdout, "%s port ca.pem cert.pem key.pem\n", argv[0]);
        return -1;
    }
    const char *ca_pem = argv[2];
    const char *cert_pem = argv[3];
    const char *key_pem = argv[4];

    SSL_library_init();

    method = SSLv23_server_method();
    
    if(!method) {
        fprintf(stderr, "Cannot create TLS_server_method\n");
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

    SSL_CTX_set_verify(ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       NULL);
    
    SSL_CTX_set_verify_depth(ctx, 1);


    /* Create a socket */
    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Cannot create a socket\n");
        SSL_CTX_free(ctx);
        return -1;
    }

    /* We don't want bind() to fail with EBUSY */
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
        fprintf(stderr, "Could not set SO_REUSEADDR on the socket\n");
        SSL_CTX_free(ctx);
        return -1;
    }

    /* Fill up the server's socket structure */
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(port_num);

    /* Bind the socket to the specified port number */
    if (bind(listen_fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        fprintf(stderr, "Could not bind the socket\n");
        SSL_CTX_free(ctx);
        return -1;
    }

    /* Specify that this is a listener socket */
    if (listen(listen_fd, SOMAXCONN) < 0) {
        fprintf(stderr, "Failed to listen on this socket\n");
        SSL_CTX_free(ctx);
        return -1;
    }

    /* Get to work */
    while (1) {
        /* Hold on till we can an incoming connection */
        sin_len = sizeof(sin);
        if ((net_fd = accept(listen_fd, (struct sockaddr *)&sin, &sin_len)) < 0) {
            fprintf(stderr, "Failed to accept connection\n");
            continue;
        }

        /* Get an SSL handle from the context */
        if (!(ssl = SSL_new(ctx))) {
            fprintf(stderr, "Could not get an SSL handle from the context\n");
            close(net_fd);
            continue;
        }

        /* Associate the newly accepted connection with this handle */
        SSL_set_fd(ssl, net_fd);

        /* Now perform handshake */
        if ((rc = SSL_accept(ssl)) != 1) {
            fprintf(stderr, "Could not perform SSL handshake\n");
            if (rc != 0) {
                SSL_shutdown(ssl);
            }
            SSL_free(ssl);
            continue;
        }

        /* Print success connection message on the server */
        printf("SSL handshake successful with %s:%d\n", inet_ntoa(sin.sin_addr),
            ntohs(sin.sin_port));

        /* Echo server... */
        while ((len = SSL_read(ssl, buffer, BUFSIZE)) != 0) {
            if (len < 0) {
                fprintf(stderr, "SSL read on socket failed\n");
                break;
            } else if ((rc = SSL_write(ssl, buffer, len)) != len) {

                break;
            }
        }

        /* Echo write */
        if ((rc = SSL_write(ssl, buffer, len)) != len) {
            if (rc < 0) {
                fprintf(stderr, "SSL write on socket failed\n");
                SSL_shutdown(ssl);
            }
            SSL_free(ssl);
            continue;
        }

        /* Successfully echoed, print on our screen as well */
        printf("%s", buffer);

        /* Cleanup the SSL handle */
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    printf("REACHED HERE....\n");
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}
