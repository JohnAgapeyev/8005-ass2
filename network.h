/*
 * HEADER FILE: network.h - Main networking functions
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
 * PROGRAMMER: John Agapeyev
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
#ifndef NETWORK_H
#define NETWORK_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <openssl/evp.h>
#include "crypto.h"

struct client {
    int socket;
    unsigned char *sharedKey;
    EVP_PKEY *signingKey;
    bool enabled;
    pthread_mutex_t *lock;
    uint64_t packetCount;
    uint64_t bytesSent;
    uint64_t averageUs;
    uint64_t startUs;
};

struct client_args {
    const char *ip;
    const char *portString;
    unsigned long connection_length;
    int epollfd;
    unsigned long long worker_count;
};

/*
 * Length is 2 bytes
 * IV is 16
 * Tag size is 16
 * Remainder is text
 * Want the outgoing packet to be 4096 max, aka page size
 */
#define MAX_INPUT_SIZE (uint16_t)(4096 - IV_SIZE - TAG_SIZE - sizeof(uint16_t))
#define MAX_PACKET_SIZE MAX_INPUT_SIZE + IV_SIZE + TAG_SIZE + sizeof(uint16_t)

extern bool isServer;
extern bool isNormal;
extern bool isSelect;
extern bool isEpoll;
extern EVP_PKEY *LongTermSigningKey;
extern struct client **clientList;
extern size_t clientCount;
extern unsigned short port;
extern int listenSock;
extern pthread_mutex_t selectLock;

void network_init(void);
void network_cleanup(void);
void process_packet(const unsigned char * const buffer, const size_t bufsize, struct client *src);
unsigned char *exchangeKeys(struct client *clientEntry);
bool receiveAndVerifyKey(const int * const sock, unsigned char *buffer, const size_t bufSize, const size_t keyLen, const size_t hmacLen);
void startClient(const char *ip, const char *portString, const unsigned long long worker_count, const unsigned long connection_length);
void startServer(void);
size_t addClient(int sock);
void initClientStruct(struct client *newClient, int sock);
void *eventLoop(void *epollfd);
void sendEncryptedUserData(const unsigned char *mesg, const size_t mesgLen, struct client *dest);
void decryptReceivedUserData(const unsigned char *mesg, const size_t mesgLen, struct client *src);
void sendReliablePacket(const unsigned char *mesg, const size_t mesgLen, struct client *dest);
void handleIncomingConnection(void);
void handleSocketError(struct client *entry);
void handleIncomingPacket(struct client *src);
int16_t readPacketLength(const int sock);
void sendSigningKey(const int sock, const unsigned char *key, const size_t keyLen);
void sendEphemeralKey(const int sock, const unsigned char *key, const size_t keyLen, const unsigned char *hmac, const size_t hmacLen);
void readSigningKey(const int sock, struct client *clientEntry, const size_t keyLen);
void *performClientActions(void *args);

#endif
