#ifndef select_h
#define select_h

#include <sys/select.h>
#include <stdio.h>
#include <sys/types.h>

#define MAX_SELECT 20

void createSelectFd(fd_set* fd, int newfd, int* maxfd);
//for a blocking call
size_t singleSelectReadInstance(const int sock, unsigned char *buffer, size_t bufSize, fd_set* fd, int* maxfd);
int waitForSelectEvent(fd_set *rdset, fd_set *rwset, int maxfd);

#endif
