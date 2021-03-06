/*
 * SOURCE FILE: network.c - Implementation of functions in network.h
 *
 * PROGRAM: 8005-ass2
 *
 * DATE: Dec. 2, 2017
 *
 * FUNCTIONS:
 * void network_init(void);
 * void network_cleanup(void);
 * void process_packet(const unsigned char * const buffer, const size_t bufsize, struct client *src);
 * unsigned char *exchangeKeys(struct client *clientEntry);
 * bool receiveAndVerifyKey(const int * const sock, unsigned char *buffer, const size_t bufSize, const size_t keyLen, const size_t hmacLen);
 * void startClient(const char *ip, const char *portString, const unsigned long long worker_count, const unsigned long connection_length);
 * void startServer(void);
 * size_t addClient(int sock);
 * void initClientStruct(struct client *newClient, int sock);
 * void *eventLoop(void *epollfd);
 * void sendEncryptedUserData(const unsigned char *mesg, const size_t mesgLen, struct client *dest);
 * void decryptReceivedUserData(const unsigned char *mesg, const size_t mesgLen, struct client *src);
 * void sendReliablePacket(const unsigned char *mesg, const size_t mesgLen, struct client *dest);
 * void handleIncomingConnection(void);
 * void handleSocketError(struct client *entry);
 * void handleIncomingPacket(struct client *src);
 * int16_t readPacketLength(const int sock);
 * void sendSigningKey(const int sock, const unsigned char *key, const size_t keyLen);
 * void sendEphemeralKey(const int sock, const unsigned char *key, const size_t keyLen, const unsigned char *hmac, const size_t hmacLen);
 * void readSigningKey(const int sock, struct client *clientEntry, const size_t keyLen);
 * void *performClientActions(void *args);
 *
 * DESIGNER: John Agapeyev
 *
 * PROGRAMMER: John Agapeyev, Benedict Lo
 */
/*
 *Copyright (C) 2017 John Agapeyev
 *
 *This program is free software: you can redistribute it and/or modify
 *it under the terms of the GNU General Public License as published by
 *the Free Software Foundation, either version 3 of the License, or
 *(at your option) any later version.
 *
 *This program is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU General Public License for more details.
 *
 *You should have received a copy of the GNU General Public License
 *along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *cryptepoll is licensed under the GNU General Public License version 3
 *with the addition of the following special exception:
 *
 ***
 In addition, as a special exception, the copyright holders give
 permission to link the code of portions of this program with the
 OpenSSL library under certain conditions as described in each
 individual source file, and distribute linked combinations
 including the two.
 You must obey the GNU General Public License in all respects
 for all of the code used other than OpenSSL.  If you modify
 file(s) with this exception, you may extend this exception to your
 version of the file(s), but you are not obligated to do so.  If you
 do not wish to do so, delete this exception statement from your
 version.  If you delete this exception statement from all source
 files in the program, then also delete it here.
 ***
 *
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include "network.h"
#include "epoll.h"
#include "socket.h"
#include "crypto.h"
#include "macro.h"
#include "main.h"
#include "select.h"

EVP_PKEY *LongTermSigningKey = NULL;
bool isServer;
bool isNormal;
bool isSelect;
bool isEpoll;
struct client **clientList;
size_t clientCount;
size_t clientMax;
unsigned short port;
int listenSock;
int maxfd;

pthread_mutex_t clientLock;
pthread_mutex_t selectLock;

fd_set rdsetbackup;
fd_set wrsetbackup;

pthread_mutex_t *cvmuts;
pthread_cond_t *cvs;
int *epolls;
int iCli = 0;

/*
 * FUNCTION: network_init
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void network_init(void);
 *
 * RETURNS:
 * void
 *
 * NOTES:
 * Initializes network state for the application
 */
void network_init(void) {
    initCrypto();
    LongTermSigningKey = generateECKey();
    clientList = checked_calloc(10000, sizeof(struct client *));
    clientCount = 1;
    clientMax = 10000;
    pthread_mutex_init(&clientLock, NULL);
    pthread_mutex_init(&selectLock, NULL);

    FD_ZERO(&rdsetbackup);
    FD_ZERO(&wrsetbackup);


    const size_t core_count = sysconf(_SC_NPROCESSORS_ONLN);

    cvmuts = checked_calloc(core_count, sizeof(pthread_mutex_t));
    cvs = checked_calloc(core_count, sizeof(pthread_cond_t));
    epolls = checked_calloc(core_count + 1, sizeof(int));

    for (size_t i = 0; i < core_count; ++i) {
        pthread_mutex_init(cvmuts + i, NULL);
        pthread_cond_init(cvs + i, NULL);
        epolls[i] = createEpollFd();
    }
}

/*
 * FUNCTION: network_cleanup
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void network_cleanup(void);
 *
 * RETURNS:
 * void
 */
void network_cleanup(void) {
    if (LongTermSigningKey) {
        EVP_PKEY_free(LongTermSigningKey);
    }
    for (size_t i = 0; i < clientMax; ++i) {
        if (clientList[i]) {
            OPENSSL_clear_free(clientList[i]->sharedKey, SYMMETRIC_KEY_SIZE);
            EVP_PKEY_free(clientList[i]->signingKey);
            free(clientList[i]);
            pthread_mutex_destroy(clientList[i]->lock);
            free(clientList[i]->lock);
        }
    }
    pthread_mutex_destroy(&clientLock);
    pthread_mutex_destroy(&selectLock);
    free(clientList);
    cleanupCrypto();

    const size_t core_count = sysconf(_SC_NPROCESSORS_ONLN);

    for (size_t i = 0; i < core_count; ++i) {
        pthread_mutex_destroy(cvmuts + i);
        pthread_cond_destroy(cvs + i);
        close(epolls[i]);
    }
    close(epolls[core_count + 1]);

    free(cvmuts);
    free(cvs);
    free(epolls);
}

/*
 * FUNCTION: process_packet
 *
 * DATE:
 * Feb. 25, 2018
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void process_packet(const unsigned char * const buffer, const size_t bufsize, struct client *src);
 *
 * PARAMETERS:
 * const unsigned char *const buffer - The buffer containing the buffer
 * const size_T bufsize - The size of the packet buffer
 * struct client *src - The client struct of who sent the packet
 *
 * RETURNS:
 * void
 *
 * NOTES:
 * Handles packet echo and getting average packet response time.
 */
void process_packet(const unsigned char * const buffer, const size_t bufsize, struct client *src) {
    debug_print("Received packet of size %zu\n", bufsize);
    debug_print_buffer("Raw hex output: ", buffer, bufsize);

#ifndef NDEBUG
    debug_print("\nText output: ");
    for (size_t i = 0; i < bufsize; ++i) {
        fprintf(stderr, "%c", buffer[i]);
    }
    fprintf(stderr, "\n");
#endif

    struct timespec start;
    clock_gettime(CLOCK_REALTIME, &start);

    uint64_t responseTime = (start.tv_sec * 1000 * 1000) + (start.tv_nsec / 1000);
    responseTime -= src->startUs;

    if (src->averageUs == 0 || src->packetCount == 0) {
        src->averageUs = responseTime;
    } else {
        src->averageUs = src->averageUs * (src->packetCount - 1)
            / src->packetCount + responseTime / src->packetCount;
    }

    if (isServer) {
        //Echo the packet
        sendEncryptedUserData(buffer, bufsize, src);
    }
}

/*
 * FUNCTION: exchangeKeys
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * unsigned char *exchangeKeys(const int * const sock);
 *
 * PARAMETERS:
 * const int * const sock - A pointer to the client struct's socket member
 *
 * RETURNS:
 * unsigned char * - An allocated buffer containing the shared secret
 *
 * NOTES:
 * Keys are exchanged in the following order:
 * Server signing key
 * Server ephemeral key
 * Client signing key
 * Client ephemeral key
 *
 * All keys sent are public keys.
 * All ephemeral keys are validated with an HMAC generated with the previously sent signing key.
 * Application relies on Trust-On-First-Use policy, so no authentication of keys is performed.
 */
unsigned char *exchangeKeys(struct client *clientEntry) {
    size_t pubKeyLen;
    unsigned char *signPubKey = getPublicKey(LongTermSigningKey, &pubKeyLen);

    EVP_PKEY *ephemeralKey = generateECKey();
    size_t ephemeralPubKeyLen;
    unsigned char *ephemeralPubKey = getPublicKey(ephemeralKey, &ephemeralPubKeyLen);

    size_t hmaclen = 0;
    unsigned char *hmac = generateHMAC_Buffer(ephemeralPubKey, ephemeralPubKeyLen, &hmaclen, signPubKey, pubKeyLen);

    unsigned char *sharedSecret = NULL;

    if (isServer) {
        sendSigningKey(clientEntry->socket, signPubKey, pubKeyLen);
        sendEphemeralKey(clientEntry->socket, ephemeralPubKey, ephemeralPubKeyLen, hmac, hmaclen);
        readSigningKey(clientEntry->socket, clientEntry, pubKeyLen);

        uint16_t packetLength = ephemeralPubKeyLen + hmaclen + sizeof(uint16_t);
        unsigned char mesgBuffer[packetLength];

        if (!receiveAndVerifyKey(&clientEntry->socket, mesgBuffer, packetLength, ephemeralPubKeyLen, hmaclen)) {
            fatal_error("HMAC verification");
        }

        EVP_PKEY *clientPubKey = setPublicKey(mesgBuffer + sizeof(uint16_t), ephemeralPubKeyLen);

        sharedSecret = getSharedSecret(ephemeralKey, clientPubKey);

        EVP_PKEY_free(clientPubKey);
    } else {
        readSigningKey(clientEntry->socket, clientEntry, pubKeyLen);

        uint16_t packetLength = ephemeralPubKeyLen + hmaclen + sizeof(uint16_t);

        unsigned char mesgBuffer[packetLength];

        if (!receiveAndVerifyKey(&clientEntry->socket, mesgBuffer, packetLength, ephemeralPubKeyLen, hmaclen)) {
            fatal_error("HMAC verification");
        }

        EVP_PKEY *serverPubKey = setPublicKey(mesgBuffer + sizeof(uint16_t), ephemeralPubKeyLen);

        sendSigningKey(clientEntry->socket, signPubKey, pubKeyLen);
        sendEphemeralKey(clientEntry->socket, ephemeralPubKey, ephemeralPubKeyLen, hmac, hmaclen);

        sharedSecret = getSharedSecret(ephemeralKey, serverPubKey);

        EVP_PKEY_free(serverPubKey);
    }
    clientEntry->sharedKey = sharedSecret;

    OPENSSL_free(signPubKey);
    OPENSSL_free(ephemeralPubKey);
    OPENSSL_free(hmac);
    EVP_PKEY_free(ephemeralKey);

    return sharedSecret;
}

/*
 * FUNCTION: receiveAndVerifyKey
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * bool receiveAndVerifyKey(const int * const sock, unsigned char *buffer, const size_t bufSize, const size_t keyLen, const size_t hmacLen);
 *
 * PARAMETERS:
 * const int *sock - A pointer to a client struct's socket member
 * unsigned char *buffer - A buffer containing the key and hmac
 * const size_t bufSize - The size of the buffer
 * const size_t keyLen - The length of the key
 * const size_t hmacLen - The length of the HMAC
 *
 * RETURNS:
 * bool - Whether the hmac for the key is valid
 */
bool receiveAndVerifyKey(const int * const sock, unsigned char *buffer, const size_t bufSize, const size_t keyLen, const size_t hmacLen) {
    assert(bufSize >= keyLen + hmacLen + sizeof(uint16_t));

    size_t n = singleEpollReadInstance(*sock, buffer, bufSize);
    assert(n >= keyLen);

    debug_print_buffer("Received ephemeral key: ", buffer, n);

    EVP_PKEY *serverPubKey = setPublicKey(buffer + sizeof(uint16_t), keyLen);

    struct client *entry = container_entry(sock, struct client, socket);

    bool rtn = verifyHMAC_PKEY(buffer + sizeof(uint16_t), keyLen, buffer + sizeof(uint16_t) + keyLen, hmacLen, entry->signingKey);

    EVP_PKEY_free(serverPubKey);
    return rtn;
}

/*
 * FUNCTION: performClientActions
 *
 * DATE:
 * Feb. 25, 2018
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void *performClientActions(void *args);
 *
 * PARAMETERS:
 * void *args - Thread args, see network.h for struct client_args definition.
 *
 * RETURNS:
 * void * - Required by interface, unused
 *
 * NOTES:
 * Repeatedly connects and initializes clients for the sake of testing large numbers of connections.
 */
void *performClientActions(void *args) {
    const char *ip = ((struct client_args *) args)->ip;
    const char *portString = ((struct client_args *) args)->portString;

    unsigned long long worker_count = ((struct client_args *) args)->worker_count;
    for (unsigned long long i = 0; i < worker_count; ++i) {
        int serverSock = establishConnection(ip, portString);
        if (serverSock == -1) {
            fatal_error("Unable to connect to server\n");
        }

        setNonBlocking(serverSock);
        setSocketBuffers(serverSock);

        size_t clientNum = addClient(serverSock);

        pthread_mutex_lock(&clientLock);
        struct client *serverEntry = clientList[clientNum];
        pthread_mutex_unlock(&clientLock);

        unsigned char *sharedSecret = exchangeKeys(serverEntry);

        printf("Handshake complete on socket %d\n", serverSock);

        debug_print_buffer("Shared secret: ", sharedSecret, SYMMETRIC_KEY_SIZE);

        if (isNormal){

        } else if(isSelect){
            createSelectFd(&rdsetbackup, serverSock, &maxfd);
            createSelectFd(&wrsetbackup, serverSock, &maxfd);
        } else if (isEpoll) {
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE | EPOLLOUT;
            ev.data.ptr = serverEntry;

            const size_t core_count = sysconf(_SC_NPROCESSORS_ONLN);

            addEpollSocket(epolls[iCli], serverSock, &ev);

            pthread_cond_signal(cvs + iCli);

            iCli = (iCli + 1) % core_count;
        }
    }
    return NULL;
}

/*
 * FUNCTION: startClient
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void startClient(const char *ip, const char *portString, const unsigned long long worker_count, const unsigned long connection_length);
 *
 * PARAMETERS:
 * const char *ip - A string containing the ip address to connect to
 * const char *portString - A string containing the port number to connect to
 * const unsigned long long worker_count - The total number of workers to use
 * const unsigned long connection_length - The number of seconds to keep the connection active
 *
 * RETURNS:
 * void
 */
void startClient(const char *ip, const char *portString, const unsigned long long worker_count, const unsigned long connection_length) {
    network_init();

    pthread_t workerThreads[worker_count];

    struct client_args *testArgs = checked_malloc(sizeof(struct client_args));
    testArgs->ip = ip;
    testArgs->portString = portString;
    testArgs->connection_length = connection_length;
    testArgs->epollfd = 0;

    const size_t core_count = sysconf(_SC_NPROCESSORS_ONLN);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    cpu_set_t cpus;

    struct sched_param sc;
    sc.sched_priority = 0;

    pthread_t readThreads[core_count];
    for (size_t i = 0; i < core_count; ++i) {
        CPU_ZERO(&cpus);
        CPU_SET(i % core_count, &cpus);
        pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
        pthread_create(&readThreads[i], &attr, eventLoop, &(int){i % core_count});
        pthread_setschedparam(readThreads[i], SCHED_BATCH, &sc);
    }
    for (size_t i = 0; i < core_count; ++i) {
        if (i == core_count - 1) {
            testArgs->worker_count = (worker_count / core_count) + (worker_count % core_count);
        } else {
            testArgs->worker_count = worker_count / core_count;
        }
        CPU_ZERO(&cpus);
        CPU_SET(i % core_count, &cpus);
        pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
        if (pthread_create(workerThreads + i, &attr, performClientActions, testArgs) != 0) {
            printf("%lu\n", i);
            perror("pthread create");
            for (unsigned long long j = 0; j < i; ++j) {
                pthread_kill(workerThreads[j], SIGKILL);
            }
            break;
        }
        pthread_setschedparam(workerThreads[i], SCHED_BATCH, &sc);
    }
    pthread_attr_destroy(&attr);
    for (unsigned long long i = 0; i < core_count; ++i) {
        pthread_join(workerThreads[i], NULL);
    }

    sleep(connection_length);
    isRunning = false;

    for (unsigned long long i = 0; i < core_count; ++i) {
        pthread_kill(readThreads[i], SIGKILL);
        pthread_join(readThreads[i], NULL);
    }

    free(testArgs);
    network_cleanup();
}


/*
 * FUNCTION: startServer
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev, Benedict Lo
 *
 * INTERFACE:
 * void startServer(void)
 *
 * RETURNS:
 * void
 *
 * NOTES:
 * Performs similar functions to startClient, except for the inital connection.
 * Writes stats to file for further inspection and analysis.
 */
void startServer(void) {
    const size_t core_count = sysconf(_SC_NPROCESSORS_ONLN);
    network_init();
    if (isNormal) {

    } else if (isSelect) {
        createSelectFd(&rdsetbackup, listenSock, &maxfd);
    } else if (isEpoll) {
        epolls[core_count] = createEpollFd();

        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE;
        ev.data.ptr = NULL;

        for (size_t i = 0; i < core_count; ++i) {
            addEpollSocket(epolls[i], listenSock, &ev);
        }

        addEpollSocket(epolls[core_count], listenSock, &ev);
    }
    setNonBlocking(listenSock);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    cpu_set_t cpus;

    pthread_t threads[core_count];
    for (size_t i = 0; i < core_count; ++i) {
        CPU_ZERO(&cpus);
        CPU_SET(i % core_count, &cpus);
        pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
        pthread_create(&threads[i], &attr, eventLoop, &(int){i % core_count});
    }
    pthread_attr_destroy(&attr);

    eventLoop(&(int){core_count});

    for (size_t i = 0; i < core_count; ++i) {
        pthread_kill(threads[i], SIGINT);
        pthread_join(threads[i], NULL);
    }

    FILE* fp;
    fp = fopen("stats","w");
    for (size_t i = 0; i < clientMax; ++i) {
        if (clientList[i]) {
            fprintf(fp,"Socket: %d\n", clientList[i]->socket);
            fprintf(fp,"Packet count: %ld\n", clientList[i]->packetCount);
            fprintf(fp,"Bytes sent: %ld\n", clientList[i]->bytesSent);
            fprintf(fp,"Average response in micro: %ld\n", clientList[i]->averageUs);
        }
    }

    fclose(fp);

    network_cleanup();
}

/*
 * FUNCTION: eventLoop
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev, Benedict Lo
 *
 * PROGRAMMER:
 * John Agapeyev, Benedict Lo
 *
 * INTERFACE:
 * void *eventLoop(void *epollfd)
 *
 * PARAMETERS:
 * void *epollfd - The position in the epoll array
 *
 * RETURNS:
 * void * - Required by pthread interface, ignored.
 *
 * NOTES:
 * Both client and server read threads run this function.
 * Uses traditional multithreading, select, and epoll, depending on command args
 */
void *eventLoop(void *epollfd) {
    int pos = *((int *)epollfd);

    if (isNormal) {
        while (isRunning) {
            if (isServer ){
                handleIncomingConnection();
            }
            pthread_mutex_lock(&clientLock);
            size_t tmpCount = clientMax;
            pthread_mutex_unlock(&clientLock);
            for (size_t l = 0; l < tmpCount; ++l) {
                pthread_mutex_lock(&clientLock);
                struct client *src = clientList[l];
                pthread_mutex_unlock(&clientLock);

                if (src && src->enabled && src->signingKey && src->sharedKey) {
                    if (isServer) {
                        if (!pthread_mutex_trylock(src->lock)) {
                            /*int16_t len;
                              int n = recv(src->socket, &len, sizeof(int16_t), MSG_PEEK);
                              if (n == -1) {
                              pthread_mutex_unlock(src->lock);
                              continue;
                              }*/
                            handleIncomingPacket(src);
                            pthread_mutex_unlock(src->lock);
                        } else {
                            sched_yield();
                            continue;
                        }
                    } else {
                        unsigned char data[MAX_INPUT_SIZE];
                        //pthread_mutex_lock(src->lock);
                        sendEncryptedUserData(data, MAX_INPUT_SIZE, src);
                        //pthread_mutex_unlock(src->lock);
                    }
                }
            }
        }
    } else if (isSelect) {
        while (isRunning) {
            fd_set rdset;
            fd_set wrset;
            pthread_mutex_lock(&selectLock);
            int myMax = maxfd;
            memcpy(&rdset, &rdsetbackup, sizeof(fd_set));
            memcpy(&wrset, &wrsetbackup, sizeof(fd_set));
            pthread_mutex_unlock(&selectLock);
            waitForSelectEvent(&rdset, &wrset, myMax);
            if (FD_ISSET(listenSock, &rdset)) {
                handleIncomingConnection();
            }
            pthread_mutex_lock(&clientLock);
            size_t tempCount = clientMax;
            pthread_mutex_unlock(&clientLock);
            for (size_t i = 0; i < tempCount; ++i) {
                pthread_mutex_lock(&clientLock);
                struct client *src = clientList[i];
                pthread_mutex_unlock(&clientLock);
                if (src && src->enabled) {
                    if (FD_ISSET(src->socket, &rdset)) {
                        //Need to do this unlock/lock pattern since incoming packet can call socket error
                        //Which also locks client lock
                        //So doing this temp unlock prevents deadlock
                        pthread_mutex_lock(src->lock);
                        //pthread_mutex_unlock(&clientLock);
                        handleIncomingPacket(src);
                        //pthread_mutex_lock(&clientLock);
                        pthread_mutex_unlock(src->lock);
                    }
                    if (FD_ISSET(src->socket, &wrset)) {
                        unsigned char data[MAX_INPUT_SIZE];
                        sendEncryptedUserData(data, MAX_INPUT_SIZE, src);
                    }
                }
            }
            //pthread_mutex_unlock(&clientLock);
        }
    } else if(isEpoll) {
        struct epoll_event *eventList = checked_calloc(MAX_EPOLL_EVENTS, sizeof(struct epoll_event));

        const size_t core_count = sysconf(_SC_NPROCESSORS_ONLN);

        int efd = epolls[pos];

        if (pos < (int) core_count) {
            pthread_cond_wait(cvs + pos, cvmuts + pos);
        }

        while (isRunning) {
            int n = waitForEpollEvent(efd, eventList);
            //n can't be -1 because the handling for that is done in waitForEpollEvent
            assert(n != -1);
            for (int i = 0; i < n; ++i) {
                if (unlikely(eventList[i].events & EPOLLERR || eventList[i].events & EPOLLHUP
                            || eventList[i].events & EPOLLRDHUP)) {
                    handleSocketError(eventList[i].data.ptr);
                } else {
                    if (likely(eventList[i].events & EPOLLIN)) {
                        if (eventList[i].data.ptr) {
                            //Regular read connection
                            //pthread_mutex_lock(((struct client *) eventList[i].data.ptr)->lock);
                            handleIncomingPacket(eventList[i].data.ptr);
                            //pthread_mutex_unlock(((struct client *) eventList[i].data.ptr)->lock);
                        } else {
                            //Null data pointer means listen socket has incoming connection
                            handleIncomingConnection();
                        }
                    }
                    if (likely(eventList[i].events & EPOLLOUT)) {
                        unsigned char data[MAX_INPUT_SIZE];
                        sendEncryptedUserData(data, MAX_INPUT_SIZE, eventList[i].data.ptr);
                    }
                }
            }
        }
        free(eventList);
    }
    return NULL;
}

/*
 * FUNCTION: addClient
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * size_t addClient(int sock)
 *
 * PARAMETERS:
 * int sock - The new client's socket
 *
 * RETURNS:
 * size_t - The index of the newly created client entry
 */
size_t addClient(int sock) {
    pthread_mutex_lock(&clientLock);
    bool foundEntry = false;
    for (size_t i = 0; i < clientMax; ++i) {
        if (clientList[i] && clientList[i]->enabled == false) {
            initClientStruct(clientList[i], sock);
            assert(clientList[i]->enabled);
            foundEntry = true;
            pthread_mutex_unlock(&clientLock);
            return i;
        }
        if (clientList[i] == NULL) {
            clientList[i] = checked_malloc(sizeof(struct client));
            initClientStruct(clientList[i], sock);
            assert(clientList[i]->enabled);
            foundEntry = true;
            ++clientCount;
            pthread_mutex_unlock(&clientLock);
            return i;
        }
    }
    if (!foundEntry) {
        clientList = checked_realloc(clientList, sizeof(struct client *) * clientMax * 2);
        memset(clientList + clientMax, 0, sizeof(struct client *) * clientMax);
        clientList[clientMax] = checked_malloc(sizeof(struct client));
        initClientStruct(clientList[clientMax], sock);
        clientMax *= 2;
    }
    ++clientCount;
    size_t result = clientCount - 2;
    pthread_mutex_unlock(&clientLock);
    //Subtract 2: 1 for incremented client count, 1 for dummy value
    return result;
}

/*
 * FUNCTION: initClientStruct
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void initClientStruct(struct client *newClient, int sock)
 *
 * PARAMETERS:
 * struct client *newClient - A pointer to the new client's struct
 * int sock - The new client's socket
 *
 * RETURNS:
 * void
 */
void initClientStruct(struct client *newClient, int sock) {
    newClient->socket = sock;
    newClient->sharedKey = NULL;
    newClient->signingKey = NULL;
    newClient->lock = checked_malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(newClient->lock, NULL);
    newClient->enabled = true;

    newClient->packetCount = 0;
    newClient->bytesSent = 0;
    newClient->averageUs = 0;
    newClient->startUs = 0;
}

/*
 * FUNCTION: sendEncryptedUserData
 *
 * DATE:
 * Feb. 25, 2018
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void sendEncryptedUserData(const unsigned char *mesg, const size_t mesgLen, struct client *dest);
 *
 * PARAMETERS:
 * const unsigned char *mesg - The message to send
 * const size_t mesgLen - The length of the given message
 * struct client *dest - A client struct containing the destination of the packet
 *
 * RETURNS:
 * void
 *
 * NOTES:
 * This function transforms the plaintext mesg into its ciphertext, and handles appending control values.
 * Packet structure is as follows:
 * Packet Length : ciphertext : IV : TAG
 */
void sendEncryptedUserData(const unsigned char *mesg, const size_t mesgLen, struct client *dest) {
    /*
     * Mesg buffer that will be sent
     * mesgLen is self-explanatory
     * IV_SIZE is self-explanatory
     * TAG_SIZE is for the GCM tag
     * sizeof calls are related to header specific lengths
     */
    unsigned char out[sizeof(uint16_t) + mesgLen + IV_SIZE + TAG_SIZE];

    unsigned char iv[IV_SIZE];
    fillRandom(iv, IV_SIZE);

    uint16_t packetLength = mesgLen + IV_SIZE + TAG_SIZE;

    //Needs to store packet length and iv
    unsigned char aad[sizeof(uint16_t) + IV_SIZE];

    memcpy(aad, &packetLength, sizeof(uint16_t));
    memcpy(aad + sizeof(uint16_t), iv, IV_SIZE);

    //Encrypt message and place it immediately following length field
    size_t cipherLen = encrypt_aead(mesg, mesgLen, aad, sizeof(uint16_t) + IV_SIZE, dest->sharedKey, iv,
            out + sizeof(uint16_t), out + sizeof(uint16_t) + mesgLen + IV_SIZE);

    assert(cipherLen == mesgLen);

    //Write packet length to start of packet buffer
    memcpy(out, &packetLength, sizeof(uint16_t));

    //Write the IV into the buffer
    memcpy(out + sizeof(uint16_t) + cipherLen, iv, IV_SIZE);

    debug_print("Sending packet of length: %zu\n", packetLength + sizeof(uint16_t));
    debug_print_buffer("Sent tag: ", out + sizeof(uint16_t) + mesgLen + IV_SIZE, TAG_SIZE);
    debug_print_buffer("Sending packets with contents: ", out, packetLength + sizeof(uint16_t));

    //Write the packet to the socket
    rawSend(dest->socket, out, packetLength + sizeof(uint16_t));

    struct timespec start;

    clock_gettime(CLOCK_REALTIME, &start);

    dest->packetCount++;
    dest->bytesSent += packetLength + sizeof(uint16_t);
    dest->startUs = (start.tv_sec * 1000 * 1000) + (start.tv_nsec / 1000);
}

/*
 * FUNCTION: decryptReceivedUserData
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void decryptReceivedUserData(const unsigned char *mesg, const size_t mesgLen, struct client *src);
 *
 * PARAMETERS:
 * const unsigned char *mesg - The received packet
 * const size_t mesgLen - The length of the packet
 * struct client *src - The source address of the packet
 *
 * RETURNS:
 * void
 *
 * NOTES:
 * This function only validates the TAG, and decrypts the ciphertext, before passing it off.
 * No response is given for an invalid TAG.
 */
void decryptReceivedUserData(const unsigned char *mesg, const size_t mesgLen, struct client *src) {
    assert(mesgLen > IV_SIZE + TAG_SIZE);

    debug_print_buffer("Received tag: ", mesg + mesgLen - TAG_SIZE, TAG_SIZE);

    unsigned char aad[sizeof(uint16_t) + IV_SIZE];
    memcpy(aad, mesg, sizeof(uint16_t));
    memcpy(aad + sizeof(uint16_t), mesg + mesgLen - TAG_SIZE - IV_SIZE, IV_SIZE);

    unsigned char plain[mesgLen];
    ssize_t plainLen = decrypt_aead(mesg + sizeof(uint16_t), mesgLen - TAG_SIZE - IV_SIZE - sizeof(uint16_t), aad, sizeof(uint16_t) + IV_SIZE,
            src->sharedKey, mesg + mesgLen - TAG_SIZE - IV_SIZE, mesg + mesgLen - TAG_SIZE, plain);

    if (unlikely(plainLen == -1)) {
        fprintf(stderr, "Packet tag failed to verify, dropping...\n");
    } else {
        process_packet(plain, plainLen, src);
    }
}

/*
 * FUNCTION: handleIncomingConnection
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev, Benedict Lo
 *
 * INTERFACE:
 * void handleIncomingConnection(void);
 *
 * RETURNS:
 * void
 *
 * NOTES:
 * Adds an incoming connection to the client list, and initiates the handshake.
 */
void handleIncomingConnection(void) {
    for(;;) {
        int sock = accept(listenSock, NULL, NULL);
        if (sock == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                //No incoming connections, ignore the error
                break;
            }
            fatal_error("accept");
        }

        setNonBlocking(sock);
        setSocketBuffers(sock);

        size_t newClientIndex = addClient(sock);
        pthread_mutex_lock(&clientLock);
        struct client *newClientEntry = clientList[newClientIndex];
        pthread_mutex_unlock(&clientLock);

        unsigned char *secretKey = exchangeKeys(newClientEntry);
        debug_print_buffer("Shared secret: ", secretKey, HASH_SIZE);

        if(isNormal){

        } else if(isSelect){
            createSelectFd(&rdsetbackup, sock, &maxfd);
        } else if(isEpoll){
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE;
            ev.data.ptr = newClientEntry;

            const size_t core_count = sysconf(_SC_NPROCESSORS_ONLN);

            pthread_mutex_lock(&clientLock);
            addEpollSocket(epolls[iCli], sock, &ev);

            pthread_cond_signal(cvs + iCli);

            iCli = (iCli + 1) % core_count;
            pthread_mutex_unlock(&clientLock);
        }
    }
}

/*
 * FUNCTION: handleSocketError
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void handleSocketError(struct client *entry);
 *
 * PARAMETERS:
 * struct client *entry - The client that had the error
 *
 * RETURNS:
 * void
 */
void handleSocketError(struct client *entry) {
    pthread_mutex_lock(&clientLock);
    int sock = (entry) ? entry->socket : listenSock;
    fprintf(stderr, "Disconnection/error on socket %d\n", sock);

    //Don't need to deregister socket from epoll
    close(sock);

    entry->enabled = false;

    pthread_mutex_unlock(&clientLock);
}

/*
 * FUNCTION: readPacketLength
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev, Benedict Lo
 *
 * INTERFACE:
 * uint16_t readPacketLength(const int sock);
 *
 * PARAMETERS:
 * const int sock - The socket to read from
 *
 * RETURNS:
 * uint16_t - The length of the new packet
 *
 * NOTES:
 * All packets have their first 2 bytes set as their length.
 * This function reads only those two bytes, and returns them.
 * This allows a staggered read to accurately receive dynamic length packets.
 */
int16_t readPacketLength(const int sock) {
    int16_t sizeToRead = 0;
    int n;
    if (isNormal) {
        n = readNBytes(sock, (unsigned char *) &sizeToRead, sizeof(int16_t));
    } else {
        n = spinRead(sock, (unsigned char *) &sizeToRead, sizeof(int16_t));
    }
    if (n == -1) {
        return -1;
    }
    if (n == 0) {
        return 0;
    }
    if (n == 1) {
        return -1;
    }
    return sizeToRead;
}

/*
 * FUNCTION: handleIncomingPacket
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void handleIncomingPacket(struct client *src);
 *
 * PARAMETERS:
 * struct client *src - The source of the incoming packet
 *
 * RETURNS:
 * void
 *
 * NOTES:
 * Handles the staggered and full read, before passing the packet off.
 */
void handleIncomingPacket(struct client *src) {
    const int sock = src->socket;
    unsigned char buffer[MAX_PACKET_SIZE];
    for (;;) {
        int16_t sizeToRead = readPacketLength(sock);
        if (sizeToRead == -1) {
            //Client has left us
            handleSocketError(src);
            break;
        }
        if (sizeToRead == 0) {
            break;
        }
        memcpy(buffer, &sizeToRead, sizeof(uint16_t));
        ssize_t len;
        errno = 0;
        len = spinRead(sock, buffer + sizeof(uint16_t), sizeToRead);
        if (len == 0) {
            return;
        }
        if (len == -1) {
            handleSocketError(src);
            return;
        }
        debug_print_buffer("Raw Received packet: ", buffer, sizeToRead + sizeof(uint16_t));
        decryptReceivedUserData(buffer, sizeToRead + sizeof(uint16_t), src);
        break;
    }
}

/*
 * FUNCTION: sendSigningKey
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void sendSigningKey(const int sock, const unsigned char *key, const size_t keyLen);
 *
 * PARAMETERS:
 * const int sock - The socket to send over
 * const unsigned char *key - The key to send
 * const size_t keyLen - The length of the key
 *
 * RETURNS:
 * void
 */
void sendSigningKey(const int sock, const unsigned char *key, const size_t keyLen) {
    uint16_t packetLength = keyLen + sizeof(uint16_t);
    unsigned char tmpSigningKeyBuffer[packetLength];

    memcpy(tmpSigningKeyBuffer, &packetLength, sizeof(uint16_t));
    memcpy(tmpSigningKeyBuffer + sizeof(uint16_t), key, keyLen);

    debug_print_buffer("Sent signing key: ", tmpSigningKeyBuffer, packetLength);

    debug_print_buffer("Actual signing key: ", key, keyLen);
    rawSend(sock, tmpSigningKeyBuffer, packetLength);
}

/*
 * FUNCTION: sendEphemeralKey
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void sendEphemeralKey(const int sock, struct client *clientEntry, const unsigned char *key, const size_t keyLen, const unsigned char *hmac, const size_t hmacLen);
 *
 * PARAMETERS:
 * const int sock - The socket to send over
 * struct client *clientEntry - The client to send to
 * const unsigned char *key - The key to send
 * const size_t keyLen - The length of the key
 * const unsigned char *hmac - The HMAC for the key
 * const size_t hmacLen - The length of the HMAC
 *
 * RETURNS:
 * void
 */
void sendEphemeralKey(const int sock, const unsigned char *key, const size_t keyLen, const unsigned char *hmac, const size_t hmacLen) {
    uint16_t packetLength = keyLen + hmacLen + sizeof(uint16_t);

    unsigned char mesgBuffer[packetLength];
    memcpy(mesgBuffer, &packetLength, sizeof(uint16_t));
    memcpy(mesgBuffer + sizeof(uint16_t), key, keyLen);
    memcpy(mesgBuffer + sizeof(uint16_t) + keyLen, hmac, hmacLen);

    debug_print_buffer("Sent ephemeral key: ", mesgBuffer, packetLength);

    rawSend(sock, mesgBuffer, packetLength);
}

/*
 * FUNCTION: readSigningKey
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void readSigningKey(const int sock, struct client *clientEntry, const size_t keyLen);
 *
 * PARAMETERS:
 * const int sock - The socket to read from
 * struct client *clientEntry - The client who sent the key
 * const size_t keyLen - The length of the key
 *
 * RETURNS:
 * void
 */
void readSigningKey(const int sock, struct client *clientEntry, const size_t keyLen) {
    const uint16_t packetLength = keyLen + sizeof(uint16_t);
    unsigned char mesgBuffer[packetLength];
    size_t n = singleEpollReadInstance(sock, mesgBuffer, packetLength);

    debug_print_buffer("Received signing key: ", mesgBuffer, packetLength);

    clientEntry->signingKey = setPublicKey(mesgBuffer + sizeof(uint16_t), n - sizeof(uint16_t));
}
