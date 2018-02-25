/*
 * SOURCE FILE: select.c - Implementation of functions declared in select.h
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
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/select.h>
#include "select.h"
#include <errno.h>
#include "main.h"
#include "macro.h"
#include "socket.h"

/*
 * FUNCTION: createSelectFd
 *
 * DATE:
 * Feb. 24, 2018
 *
 * DESIGNER:
 * Benedict Lo
 * John Agapeyev
 *
 * PROGRAMMER:
 * Benedict Lo
 * John Agapeyev
 *
 * INTERFACE:
 * int createSelectFd(fd_set *fd, int newfd, int *maxfd);
 *
 * PARAMETERS:
 * fd_set *fd - The fdset that the new file desciptor is being added to
 * int newfd -  The new file desciptor
 * int *maxfd - max file descriptor in the set
 *
 * RETURNS:
 * void
 */
void createSelectFd(fd_set *fd, int newfd, int *maxfd){
    pthread_mutex_lock(&selectLock);
    FD_SET(newfd, fd);
    if (newfd > *maxfd) {
        *maxfd = newfd;
    }
    pthread_mutex_unlock(&selectLock);
}
/*
 * FUNCTION: waitForSelectEvent
 *
 * DATE:
 * Feb. 24, 2018
 *
 * DESIGNER:
 * Benedict Lo
 * John Agapeyev
 *
 * PROGRAMMER:
 * Benedict Lo
 * John Agapeyev
 *
 * INTERFACE:
 * int waitForSelectEvent(fd_set *rdset, fd_set *rwset, int maxfd);
 *
 * PARAMETERS:
 * fd_set *rdset - The fdset for reads
 * fd_set *rwset - The fdset for writes
 * int maxfd - max fild descriptor in the set
 *
 * RETURNS:
 * int - The Select file descriptor
 */
int waitForSelectEvent(fd_set *rdset, fd_set *rwset, int maxfd){
    struct timeval wait;
    wait.tv_sec = 0;
    wait.tv_usec = 5;

    int n;
    if ((n = select(maxfd + 1, rdset, rwset, NULL, &wait)) < 0) {
        if (errno == EINTR || errno == EBADF) {
            //Interrupted by signal, ignore it
            return 0;
        }
        fatal_error("select wait");
    }
    return n;
}
