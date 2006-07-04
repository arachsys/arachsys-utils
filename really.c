#include <sys/types.h>
#include <errno.h>
#include <grp.h>
#include <libgen.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: really command [args]\n");
    exit(1);
  }
  setuid(0);
  setgid(0);
  initgroups("root", 0);
  execvp(argv[1], argv + 1);
  fprintf(stderr, "%s: %s: %s\n", basename(argv[0]), argv[1], strerror(errno));
  exit(1);
}
