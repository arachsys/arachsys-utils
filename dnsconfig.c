#include <err.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>

#include "dnsconfig.h"

void timeout(int signal) {
  errx(1, "Configuration lock timed out");
}

int usage(const char *progname) {
  fprintf(stderr, "\
Usage: %s [OPTIONS] DOMAIN\n\
Options:\n\
  -r  read mode: list existing records to STDOUT\n\
  -s  strict checking: abort immediately on input errors\n\
  -w  write mode: read replacement records from STDIN\n\
", progname);
  return 64;
}

int main(int argc, char **argv) {
  int dir, fd, option, read = 0, strict = 0, write = 0;
  struct passwd *dns = getpwnam("dns");
  uid_t uid = getuid();
  FILE *old, *new;

  while ((option = getopt(argc, argv, ":rsw")) > 0)
    switch (option) {
      case 'r':
        read = 1;
        break;
      case 's':
        strict = 1;
        break;
      case 'w':
        write = 1;
        break;
      default:
        return usage(argv[0]);
    }

  if (argc != optind + 1)
    return usage(argv[0]);
  if (!strcmp(argv[optind], "."))
    argv[optind][0] = 0;

  if (!dns || setgid(dns->pw_gid) < 0 || setuid(dns->pw_uid) < 0)
    errx(1, "Failed to drop privileges");
  if (chdir("/etc/dns") < 0)
    err(1, "chdir /etc/dns");

  signal(SIGALRM, timeout);
  signal(SIGTSTP, SIG_IGN);
  alarm(5);

  if (!check_name(argv[optind], 0))
    errx(1, "Invalid domain name");
  if (uid && !auth_name(argv[optind], uid))
    errx(1, "Domain does not belong to you");

  if ((dir = open(".", O_RDONLY | O_DIRECTORY)) < 0)
    err(1, "open /etc/dns");
  if (write && flock(dir, LOCK_EX) < 0)
    err(1, "flock /etc/dns");

  if (!(old = fopen("data", "r")))
    err(1, "open");

  if (write) {
    if ((fd = open(".", O_TMPFILE | O_WRONLY, 0600)) < 0)
      err(1, "open");
    if (!(new = fdopen(fd, "w")))
      err(1, "fdopen");
  }

  if (read) {
    filter(argv[optind], 0, old, stdout, 0, 0);
    rewind(old);
  }

  if (write) {
    filter(argv[optind], 0, old, 0, new, 0);
    if (filter(argv[optind], uid, stdin, new, 0, strict ? 2 : 1))
      return 2;
    if (fflush(new) < 0)
      err(1, "fflush");
    if (fsync(fileno(new)) < 0)
      err(1, "fsync");

    if (linkat(fileno(new), "", dir, "data.new", AT_EMPTY_PATH) < 0)
      err(1, "linkat");
    if (rename("data.new", "data") < 0)
      err(1, "rename");
    fclose(new);
  }

  fclose(old);
  return 0;
}
