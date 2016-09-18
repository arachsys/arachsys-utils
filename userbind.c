#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

#define CONFIG "/etc/addresses"

char *progname;

struct sockaddr *compare(struct sockaddr *a, struct sockaddr *b, char *mask) {
  unsigned char *as, *bs;
  unsigned int bits = -1;
  char *invalid;

  if (a->sa_family != b->sa_family)
    return NULL;

  if (mask && *mask)
    if (bits = strtol(mask, &invalid, 10), *invalid)
      return NULL;

  switch (a->sa_family) {
    case AF_INET:
      as = (unsigned char *) &((struct sockaddr_in *) a)->sin_addr.s_addr;
      bs = (unsigned char *) &((struct sockaddr_in *) b)->sin_addr.s_addr;
      bits = bits < 32 ? bits : 32;
      break;
    case AF_INET6:
      as = (unsigned char *) ((struct sockaddr_in6 *) a)->sin6_addr.s6_addr;
      bs = (unsigned char *) ((struct sockaddr_in6 *) b)->sin6_addr.s6_addr;
      bits = bits < 128 ? bits : 128;
      break;
    default:
      return NULL;
  }

  while (bits >= 8) {
    if (*as++ != *bs++)
      return NULL;
    bits -= 8;
  }

  return (*as >> (8 - bits)) == (*bs >> (8 - bits)) ? a : NULL;
}

void error(int status, int errnum, char *format, ...) {
  va_list args;

  fprintf(stderr, "%s: ", progname);
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  if (errnum != 0)
    fprintf(stderr, ": %s\n", strerror(errnum));
  else
    fputc('\n', stderr);
  if (status != 0)
    exit(status);
}

char *getuser(uid_t uid) {
  struct passwd *passwd;
  char *user;

  user = getenv("USER");
  user = user ? user : getenv("LOGNAME");
  user = user ? user : getlogin();
  if (!user || !(passwd = getpwnam(user)) || passwd->pw_uid != uid) {
    if (!(passwd = getpwuid(uid)))
      error(1, 0, "Failed to validate your username");
    user = passwd->pw_name;
  }
  endpwent();
  return user;
}

char *match(char *line, uid_t uid, char *user) {
  char *entry;

  if (strtol(line, &entry, 10) != uid || entry == line) {
    if (strncmp(line, user, strlen(user)))
      return NULL;
    entry = line + strlen(user);
  }

  return entry[0] == ':' ? entry + 1 : NULL;
}

struct addrinfo *permitted(struct addrinfo *requested, uid_t uid) {
  FILE *config;
  struct addrinfo *entry, hints, *result = NULL;
  char *host, *line = NULL, *mask, *user;
  size_t size;

  hints.ai_family = requested->ai_family;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;

  user = getuser(uid);
  if (!(config = fopen(CONFIG, "r")))
    error(1, 0, "Failed to open %s", CONFIG);

  while (!result && getline(&line, &size, config) >= 0) {
    if (!(host = match(line, uid, user)))
      continue;
    host[strcspn(host, "\n")] = 0;
    if ((mask = strchr(host, '/')))
      *mask++ = 0;
    if (getaddrinfo(host, NULL, &hints, &entry) || !entry)
      continue;
    if (compare(requested->ai_addr, entry->ai_addr, mask))
      result = requested;
    freeaddrinfo(entry);
  }

  free(line);
  fclose(config);
  return result;
}

void usage(void) {
  fprintf(stderr, "\
Usage: %s ADDRESS PORT < SOCKET\n\
Bind the socket passed as standard input to a privileged port PORT on IPv4\n\
or IPv6 address ADDRESS if permitted for the invoking user in %s.\n\
", progname, CONFIG);
  exit(EX_USAGE);
}

int main(int argc, char **argv) {
  struct addrinfo hints, *requested;
  int null;
  uid_t uid;

  progname = argv[0];

  if ((null = open("/dev/null", O_RDWR)) < 0)
    error(1, 0, "Failed to open /dev/null");
  if (fcntl(STDOUT_FILENO, F_GETFD) < 0)
    dup2(null, STDOUT_FILENO);
  if (fcntl(STDERR_FILENO, F_GETFD) < 0)
    dup2(null, STDERR_FILENO);
  if (null != STDIN_FILENO)
    if (null != STDOUT_FILENO)
      if (null != STDERR_FILENO)
        close(null);

  if (argc != 3)
    usage();

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;
  if (getaddrinfo(argv[1], argv[2], &hints, &requested) || !requested)
    error(1, 0, "Bad host address");

  uid = getuid();
  if (uid != 0 && !permitted(requested, uid))
    error(1, 0, "Permission denied");

  if (bind(STDIN_FILENO, requested->ai_addr, requested->ai_addrlen) < 0)
    error(1, errno, "bind");

  freeaddrinfo(requested);
  return EXIT_SUCCESS;
}
