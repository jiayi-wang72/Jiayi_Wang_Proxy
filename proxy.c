

/**
 * @file proxy.c
 * @brief A caching proxy that can handle concurrent client request
 *
 * The cache uses LRU eviction policy, storing up to 1024 * 1024 bytes of
 * web responses to respond to clients more quickly. The proxy is able to
 * handle multiple concurrent client requests by using different threads.
 * Thread synchronization is accomplished by using pthread_mutex_lock function.
 *
 * @author Jiayi Wang
 */
#include "cache.h"
#include "csapp.h"
#include "http_parser.h"

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>

/*
 * Debug macros, which can be enabled by adding -DDEBUG in the Makefile
 * Use these if you find them useful, or delete them if not
 */
#ifdef DEBUG
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dbg_assert(...)
#define dbg_printf(...)
#endif

/* The mutex used for locking and unlocking */
pthread_mutex_t mutex;

/*
 * String to use for the User-Agent header.
 * Don't forget to terminate with \r\n
 */

static const char *header_user_agent = "User-Agent: Mozilla/5.0"
                                       " (X11; Linux x86_64; rv:3.10.0)"
                                       " Gecko/20191101 Firefox/63.0.1\r\n";

/* Typedef for convenience */
typedef struct sockaddr SA;

/* Information about a connected client. */
typedef struct {
    struct sockaddr_in addr; // Socket address
    socklen_t addrlen;       // Socket address length
    int connfd;              // Client connection file descriptor
    char host[MAXLINE];      // Client host
    char serv[MAXLINE];      // Client service (port)
} client_info;

/* struct that packs things to pass in to serve function */
typedef struct {
    client_info *client;
    cache_t *cache;
} serve_t;

cache_t **cptr;
client_info **clptr;

void *serve(void *client);
void sigint_handler(int sig);

/** @brief
 * This main function starts the proxy and uses a while loop to take in
 * client requests and serve clients by calling on serve
 *
 * @param[in] argc Argument number
 * @param[in] argv Arguments
 * */
int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, sigint_handler);

    int listenfd;

    if (argc != 2) {
        exit(1);
    }

    // open the listen file descriptor
    listenfd = open_listenfd(argv[1]);
    if (listenfd < 0) {
        exit(1);
    }

    cache_t *cache = cache_init();
    cptr = &cache;

    // proxy main body
    while (true) {

        // wait to get client information ready
        client_info *client = Malloc(sizeof(client_info));
        clptr = &client;
        client->addrlen = sizeof(client->addr);
        client->connfd =
            accept(listenfd, (SA *)&client->addr, &client->addrlen);

        if (client->connfd < 0) {
            perror("accept");
            Free(client);
            continue;
        }

        // client information is ready, prepare to serve
        serve_t *arg = Malloc(sizeof(serve_t));
        arg->cache = cache;
        arg->client = client;
        pthread_t tid;

        // peer thread to serve the client
        pthread_create(&tid, NULL, &serve, (void *)arg);
    }

    // proxy should never reach this line
    return 0;
}

/** @brief clienterror function that sends error message back to client
 * citation: tiny.c from proxy lab handout files
 * clienterror - returns an error message to the client
 *
 * @param[in] fd File Descriptor number to write to
 * @param[in] errnum Displayer error number
 * @param[in] shortmsg The short error message
 * @param[in] longmsg The long error message
 */
void clienterror(int fd, const char *errnum, const char *shortmsg,
                 const char *longmsg) {
    char buf[MAXLINE];
    char body[MAXBUF];
    size_t buflen;
    size_t bodylen;

    /* Build the HTTP response body */
    bodylen = snprintf(body, MAXBUF,
                       "<!DOCTYPE html>\r\n"
                       "<html>\r\n"
                       "<head><title>Tiny Error</title></head>\r\n"
                       "<body bgcolor=\"ffffff\">\r\n"
                       "<h1>%s: %s</h1>\r\n"
                       "<p>%s</p>\r\n"
                       "<hr /><em>The Tiny Web server</em>\r\n"
                       "</body></html>\r\n",
                       errnum, shortmsg, longmsg);
    if (bodylen >= MAXBUF) {
        return; // Overflow!
    }

    /* Build the HTTP response headers */
    buflen = snprintf(buf, MAXLINE,
                      "HTTP/1.0 %s %s\r\n"
                      "Content-Type: text/html\r\n"
                      "Content-Length: %zu\r\n\r\n",
                      errnum, shortmsg, bodylen);
    if (buflen >= MAXLINE) {
        return; // Overflow!
    }

    /* Write the headers */
    if (rio_writen(fd, buf, buflen) < 0) {
        fprintf(stderr, "Error writing error response headers to client\n");
        return;
    }

    /* Write the body */
    if (rio_writen(fd, body, bodylen) < 0) {
        fprintf(stderr, "Error writing error response body to client\n");
        return;
    }
}

/** @brief read request header function
 * citation: tiny.c from proxy lab handout files
 * check for potential error in request and header
 *
 * @param[in] client A pointer to client_info
 * @param[in] hparser A pointer to the parser we are using
 *
 * @return true if there's an error
 * @return false if there's no error
 */
bool read_requesthdrs(client_info *client, parser_t *hparser) {

    const char *myhost;
    const char *myuri;
    const char *mymethod;
    // parse the request and get host, port, and uri
    if (parser_retrieve(hparser, HOST, &myhost) < 0) {
        // parsing host has problem
        return false;
    }

    if (parser_retrieve(hparser, URI, &myuri) < 0) {
        // parsing uri has problem
        return false;
    }

    if (parser_retrieve(hparser, METHOD, &mymethod) < 0) {
        return false;
    }

    if (strcmp(mymethod, "GET")) {
        clienterror(client->connfd, "501", "Not Implemented",
                    "Proxy does not implement this method");
        return false;
    }

    return true;
}

/** @brief
 * This funtion takes in a struct that contains the client information and
 * the cache used to store web responses and serves the client
 *
 * @param[in] argp A pointer to the struct that contains client and cache
 * */
void *serve(void *argp) {

    // get information from argp
    client_info *client = ((serve_t *)argp)->client;
    cache_t *cache = ((serve_t *)argp)->cache;
    pthread_detach(pthread_self());

    size_t n;
    char buf[MAXLINE];
    rio_t c_rio;
    rio_t s_rio;
    int clientfd;

    getnameinfo((SA *)&client->addr, client->addrlen, client->host,
                sizeof(client->host), client->serv, sizeof(client->serv), 0);

    const char *myhost;
    const char *myport;
    const char *myuri;
    // const char *myversion;
    char info[MAXLINE] = {0};
    int prevn = 0;

    parser_t *hparser = parser_new();
    rio_readinitb(&c_rio, client->connfd);

    // bool version = true;

    size_t agent_len = strlen(header_user_agent);
    char *connection = "Connection: close\r\n";
    size_t con_len = strlen(connection);
    char *pcon = "Proxy-Connection: close\r\n";
    size_t pcon_len = strlen(pcon);

    // read client request
    while ((n = rio_readlineb(&c_rio, buf, RIO_BUFSIZE)) > 0) {
        if (!strncmp(buf, "User-Agent", 10)) {
            memcpy(info + prevn, header_user_agent, agent_len);
            prevn += agent_len;
        } else if (!strncmp(buf, "Connection", 10)) {
            memcpy(info + prevn, connection, con_len);
            prevn += con_len;
        } else if (!strncmp(buf, "Proxy-Connection", 10)) {
            memcpy(info + prevn, pcon, pcon_len);
            prevn += pcon_len;
        } else {
            memcpy(info + prevn, buf, n);
            prevn += n;
        }

        if (buf[0] == '\r' && buf[1] == '\n') {
            prevn += n;
            break;
        }

        // make sure the HTTP request is of version 1.0
        if (parser_parse_line(hparser, buf) == REQUEST) {
            *(info + prevn - 3) = '0';
        }
    }

    // read the request headers and return false if there's an error
    if (!read_requesthdrs(client, hparser)) {
        close(client->connfd);
        Free(client);
        Free(argp);
        return NULL;
    }

    parser_retrieve(hparser, HOST, &myhost);
    if (parser_retrieve(hparser, PORT, &myport) < 0) {
        // default port number is 80
        myport = "80";
    }
    parser_retrieve(hparser, URI, &myuri);

    // leave the serve if there's an error getting requests
    if (prevn == 0) {
        close(client->connfd);
        Free(client);
        Free(argp);
        parser_free(hparser);
        return NULL;
    }

    // copy URI in order to search in cache
    int uri_len = strlen(myuri);
    char *lookup_key = Malloc(uri_len + 1);
    strcpy(lookup_key, myuri);

    // search for current request in cache
    pthread_mutex_lock(&mutex);
    block_t *res = cache_lookup(cache, lookup_key, uri_len);
    if (res != NULL) {
        res->count += 1;
    }
    pthread_mutex_unlock(&mutex);
    Free(lookup_key);

    // if res != NULL, response is in the cache
    if (res != NULL) {

        // write request back to client and leave the serve
        int len = res->object_size;
        rio_writen(client->connfd, *(res->value), len);
        pthread_mutex_lock(&mutex);
        res->count -= 1;
        if (res->count == 0) {
            Free(*(res->key));
            Free(res->key);
            Free(*(res->value));
            Free(res->value);
            Free(res);
        }
        pthread_mutex_unlock(&mutex);
        close(client->connfd);
        Free(client);
        Free(argp);
        parser_free(hparser);
        return NULL;
    }

    char *inf = Malloc(uri_len + 1);
    strcpy(inf, myuri);

    // request not in cache
    clientfd = open_clientfd(myhost, myport);
    if (clientfd == -1) {
        close(client->connfd);
        parser_free(hparser);
        Free(client);
        Free(argp);
        Free(inf);
        return NULL;
    }
    parser_free(hparser);

    rio_readinitb(&s_rio, clientfd);
    // send request to server
    rio_writen(clientfd, info, prevn);

    int rprevn = 0;
    char response[MAX_OBJECT_SIZE];

    // read request from server and write back to client
    while ((n = rio_readnb(&s_rio, buf, RIO_BUFSIZE)) != 0) {
        rio_writen(client->connfd, buf, n);

        // copy the response to "response"
        if (rprevn + n <= MAX_OBJECT_SIZE) {
            memcpy(response + rprevn, buf, n);
        }
        rprevn += n;
    }

    char *resp = Malloc(rprevn + 1);

    // if size under MAX_OBJECT_SIZE, store in cache
    if (rprevn <= MAX_OBJECT_SIZE) {
        memcpy(resp, response, rprevn);
        pthread_mutex_lock(&mutex);
        int add_res = cache_add(cache, resp, inf, rprevn, uri_len);
        if (add_res < 0) {
            Free(inf);
            Free(resp);
        }
        pthread_mutex_unlock(&mutex);
    } else {
        Free(inf);
        Free(resp);
    }

    // clean up and leave
    close(clientfd);
    close(client->connfd);
    Free(client);
    Free(argp);
    return NULL;
}

/** @brief
 * SIGINT handler that frees the cache memory and current client_info pointer
 *
 * @param[in] sig Signal number
 * @pre there should be only one thread running
 * */
void sigint_handler(int sig) {
    cache_t *cache = *cptr;
    cache_free(cache);
    client_info *client = *clptr;
    Free(client);
    exit(0);
}
