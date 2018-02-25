/*
 * SOURCE FILE: select.h - Select setup and wrappers
 *
 * PROGRAM: 8005-ass2
 *
 * DATE: Feb. 24, 2018
 *
 * FUNCTIONS:
 * void createSelectFd(fd_set *fd, int newfd, int *maxfd)
 * int waitForselectEvent(fd_set *rdset, fd_set *rwset, int maxfd)
 *
 * DESIGNER: Benedict Lo
 *           John Agapeyev
 *
 * PROGRAMMER: Benedict Lo
 *             John Agapeyev
 */
#ifndef select_h
#define select_h

#include <sys/select.h>
#include <stdio.h>
#include <sys/types.h>

void createSelectFd(fd_set* fd, int newfd, int* maxfd);
size_t singleSelectReadInstance(const int sock, unsigned char *buffer, size_t bufSize, fd_set* fd, int* maxfd);

#endif
