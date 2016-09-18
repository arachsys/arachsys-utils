#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

void usage(char *progname) {
  fprintf(stderr, "Usage: %s ADDRESS [PORT]\n", progname);
  exit(EX_USAGE);
}

int main(int argc, char **argv) {
  struct addrinfo hints, *requested;
  int sock;

  if (argc < 2 || argc > 3)
    usage(argv[0]);

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;
  if (getaddrinfo(argv[1], argv[2], &hints, &requested) || !requested)
    return EXIT_FAILURE;

  sock = socket(requested->ai_family, SOCK_DGRAM, 0);
  if (sock < 0 || bind(sock, requested->ai_addr, requested->ai_addrlen) < 0)
    return EXIT_FAILURE;

  close(sock);
  freeaddrinfo(requested);
  return EXIT_SUCCESS;
}
