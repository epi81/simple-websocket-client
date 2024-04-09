#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>

// #define HOST "echo.websocket.org"
// #define PATH "/"

#define HOST "demo.piesocket.com"
#define PATH "/v3/channel_123?api_key=VCXCEuvhGcBDP7XhiJJUDvR1e1D3eiVjgZ9VRiaV&notify_self"
#define PORT 443

// Function to generate a random 4-byte mask value
// void generate_mask(uint8_t mask[4]) {
//     // Implement your random mask generation logic here
//     // For simplicity, this example generates a fixed mask value
//     mask[0] = 0x12;
//     mask[1] = 0x34;
//     mask[2] = 0x56;
//     mask[3] = 0x78;
// }

// // Function to send a WebSocket binary message frame
// void send_binary_message(SSL *ssl, const void *data, size_t data_length) {
//     char frame[512]; // Adjust the frame size as needed
//     int frame_size = 0;

//     // Set the opcode for binary frame
//     frame[frame_size++] = 0x82;

//     // Set the payload length
//     if (data_length <= 125) {
//         // For payloads up to 125 bytes, use a single byte
//         frame[frame_size++] = (uint8_t)data_length;
//     } else if (data_length <= 65535) {
//         // For payloads from 126 to 65535 bytes, use two bytes (16-bit unsigned integer)
//         frame[frame_size++] = 126;
//         frame[frame_size++] = (uint8_t)((data_length >> 8) & 0xFF);
//         frame[frame_size++] = (uint8_t)(data_length & 0xFF);
//     } else {
//         // For longer payloads, use eight bytes (64-bit unsigned integer), but this is not currently implemented
//         fprintf(stderr, "ERROR: message too long\n");
//         exit(EXIT_FAILURE);
//     }

//     // Copy the data into the frame
//     memcpy(&frame[frame_size], data, data_length);
//     frame_size += data_length;

//     // Send the frame
//     if (SSL_write(ssl, frame, frame_size) <= 0) {
//         fprintf(stderr, "ERROR: sending binary message\n");
//         exit(EXIT_FAILURE);
//     }
// }

// Function to create a ping frame with a string message
void create_ping_frame(const char *message, uint8_t frame[], size_t *frame_length) {
    size_t message_length = strlen(message);

    // Set the frame length
    *frame_length = 6 + message_length;

    // // Text frame mode
    // frame[0] = 0x81; 
    // frame[1] = 0x80 | (uint8_t)message_length; // Masked + Payload length (masked)
    // memcpy(&frame[2], message, message_length);

    // Binary frame mode
    frame[0] = 0x82; 
    frame[1] = 0x80 | (uint8_t)message_length; // Masked + Payload length (masked)
    memcpy(&frame[2], message, message_length);

    // Masked frame mode
    // uint8_t mask[4];
    // generate_mask(mask);
    // frame[0] = 0x89; // FIN + RSV1-3 + Opcode (Ping), masked frame
    // frame[1] = 0x80 | (uint8_t)message_length; // Masked + Payload length (masked)

    // Apply the mask to the message
    // for (size_t i = 0; i < message_length; i++) {
    //     frame[i + 6] = message[i] ^ mask[i % 4];
    // }

    // Set the mask value in the frame
    // memcpy(&frame[2], mask, 4);
}

void *ping_thread(void *arg) {
    SSL *ssl = (SSL *)arg;

    while (1) {
        char ping_frame[256]; // Adjust the frame size as needed
        size_t frame_length;
        const char *message = "ping"; // max size:128
        create_ping_frame(message, (uint8_t *)ping_frame, &frame_length);

        int ret = SSL_write(ssl, ping_frame, frame_length);
        if (ret <= 0) {
            fprintf(stderr, "ERROR: sending ping\n");
            break;
        }
        sleep(5); // Send ping every 5 seconds
    }

    return NULL;
}

const char *get_tls_version_name(int tls_version) {
    switch (tls_version) {
        case 0x0300:
            return "SSLv3";
        case 0x0301:
            return "TLSv1.0";
        case 0x0302:
            return "TLSv1.1";
        case 0x0303:
            return "TLSv1.2";
        case 0x0304:
            return "TLSv1.3";
        default:
            return "Unknown";
    }
}

int create_socket(const char *host, int port) {
    struct sockaddr_in serv_addr;
    struct hostent *server;
    int sockfd;

    // Get server IP address
    server = gethostbyname(host);
    if (server == NULL) {
        fprintf(stderr, "ERROR [line %d]: no such host\n", __LINE__);
        exit(1);
    }

    // Create a socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "ERROR [line %d]: opening socket\n", __LINE__);
        exit(1);
    }

    // Set up the server address structure
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(port);

    // Connect to server
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "ERROR [line %d]: connecting\n", __LINE__);
        close(sockfd);
        exit(1);
    }

    return sockfd;
}

SSL_CTX *create_ssl_context(int tls_version) {
    SSL_CTX *ssl_ctx;

    // Create an SSL context
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (ssl_ctx == NULL) {
        fprintf(stderr, "ERROR [line %d]: creating SSL context\n", __LINE__);
        exit(1);
    }

    // Set TLS version
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_3);
    SSL_CTX_set_min_proto_version(ssl_ctx, tls_version);

    // Disable SSL certificate verification
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

    // Set cipher suite
    SSL_CTX_set_cipher_list(ssl_ctx, "DEFAULT");
    // SSL_CTX_set_cipher_list(ssl_ctx, "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!DSS");

    return ssl_ctx;
}

SSL *create_ssl_object(int sockfd, SSL_CTX *ssl_ctx) {
    SSL *ssl;

    // Create an SSL object and bind it to the socket
    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        fprintf(stderr, "ERROR [line %d]: creating SSL object\n", __LINE__);
        close(sockfd);
        SSL_CTX_free(ssl_ctx);
        exit(1);
    }
    if (!SSL_set_fd(ssl, sockfd)) {
        fprintf(stderr, "ERROR [line %d]: binding SSL to socket\n", __LINE__);
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        exit(1);
    }

    return ssl;
}

int perform_ssl_handshake(SSL *ssl, int sockfd) {
    // Attempt SSL handshake
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "ERROR [line %d]: performing SSL handshake with %s failed\n", __LINE__, get_tls_version_name(SSL_CTX_get_min_proto_version(SSL_get_SSL_CTX(ssl))));
        ERR_print_errors_fp(stderr); // Print error stack
        close(sockfd);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(SSL_get_SSL_CTX(ssl));
        return -1;
    }
    return 0;
}

void send_websocket_handshake(SSL *ssl, const char *request) {
    int n = SSL_write(ssl, request, strlen(request));
    if (n < 0) {
        fprintf(stderr, "ERROR [line %d]: writing to socket\n", __LINE__);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(SSL_get_SSL_CTX(ssl));
        exit(1);
    }
}

void read_server_response(SSL *ssl) {
    char buffer[256];

    printf("\n******************* Response Header *******************\n");
    while (1) {
        bzero(buffer, sizeof(buffer));
        int ret = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (ret <= 0) {
            fprintf(stderr, "ERROR [line %d]: reading from socket: %d\n", __LINE__, SSL_get_error(ssl, ret));
            return;
        }
        printf("%s", buffer);
        if( ret >5 
            && buffer[ret-4]=='\r' 
            && buffer[ret-3]=='\n' 
            && buffer[ret-2]=='\r' 
            && buffer[ret-1]=='\n' 
        ){
            break;
        }
    }

    printf("\n******************* Data ******************* \n");

    while (1) {
        bzero(buffer, sizeof(buffer));
        int ret = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (ret <= 0) {
            fprintf(stderr, "ERROR [line %d]: reading from socket: %d\n", __LINE__, SSL_get_error(ssl, ret));
            break;
        }
        printf("Server response[size=%02x frame=%02x len=%02x]: %s\n", ret, buffer[0]&0xff, (int)buffer[1], buffer+2);
    }
}

int main() {
    int sockfd;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    char request[512];
    sprintf(request, "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
                     "Sec-WebSocket-Version: 13\r\n\r\n",
                     PATH, HOST);

    // Initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    for (int tls_version = 0x0304; tls_version >= 0x0300; tls_version--) {
        sockfd = create_socket(HOST, PORT);
        ssl_ctx = create_ssl_context(tls_version);
        ssl = create_ssl_object(sockfd, ssl_ctx);

        if (perform_ssl_handshake(ssl, sockfd) != 0) {
            close(sockfd);
            continue; // Continue to the next TLS version on handshake failure
        }

        printf("TLS handshake succeeded with version: %s\n", get_tls_version_name(tls_version));

        // Start ping thread
        pthread_t ping_thread_id;
        pthread_create(&ping_thread_id, NULL, ping_thread, ssl);

        send_websocket_handshake(ssl, request);
        read_server_response(ssl);

        // Close SSL connection
        SSL_shutdown(ssl);
        SSL_free(ssl);

        // Clean up OpenSSL
        SSL_CTX_free(ssl_ctx);
        EVP_cleanup();
        ERR_free_strings();

        close(sockfd);
        break; // Exit loop after successful connection
    }

    return 0;
}
