#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern int __real_bind(int, const struct sockaddr *, socklen_t);

static int helper(int sockfd, char *host, char *port) {
  pid_t child;
  int status;

  switch (child = fork()) {
    case -1:
      return -1;
    case 0:
      close(STDOUT_FILENO);
      close(STDERR_FILENO);
      if (dup2(sockfd, STDIN_FILENO) == STDIN_FILENO)
        execle(HELPER, HELPER, host, port, NULL, NULL);
      exit(1);
  }

  if (waitpid(child, &status, 0) == child)
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
      return 0;

  return -1;
}

int __wrap_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  char host[46], port[6];
  int result;

  result = __real_bind(sockfd, addr, addrlen);
  if (result >= 0 || errno != EACCES)
    return result;

  if (getnameinfo(addr, addrlen, host, sizeof(host), port, sizeof(port),
                  NI_NUMERICHOST | NI_NUMERICSERV) == 0)
    if (atoi(port) < IPPORT_RESERVED)
      if (helper(sockfd, host, port) == 0)
        return 0;

  errno = EACCES;
  return -1;
}
