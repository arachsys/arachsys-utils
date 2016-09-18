#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

int __real_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  static int (*bind)(int, const struct sockaddr *, socklen_t);

  if (!bind)
    bind = dlsym(RTLD_NEXT, "bind");

  if (bind)
    return bind(sockfd, addr, addrlen);

  errno = EACCES;
  return -1;
}
