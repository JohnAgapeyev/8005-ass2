#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/select.h>
#include "select.h"
#include <errno.h>
#include "main.h"
#include "macro.h"
#include "socket.h"

int createSelectFd(fd_set* fd, int newfd, int* maxfd){
    FD_SET(newfd, fd);
    if(newfd > *maxfd){
        *maxfd = newfd;
    }
    return newfd;
}

void waitForSelectEvent(fd_set * fd, int * maxfd){
    int n;

    if((n = select(*maxfd+1,fd, NULL, NULL, NULL)) < 0){
        perror("select error");
    }

}

size_t singleSelectReadInstance(const int sock, unsigned char *buffer, const size_t bufSize, fd_set* fd, int* maxfd ){
    createSelectFd(fd, sock, maxfd);

    size_t n = 0;
    int i;
    waitForSelectEvent(fd, maxfd);
    int max = *maxfd;
    for(i = 0; i <= max ; i++){
        if(FD_ISSET(i, fd)){
            if(i == sock){
                n = readNBytes(sock, buffer, bufSize);
            } else {
            }
        }
    }
    return n;
}
