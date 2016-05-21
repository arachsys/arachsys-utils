#include <errno.h>
#include <error.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s command [args]\n", argv[0]);
    exit(1);
  }
  setuid(0);
  setgid(0);
  initgroups("root", 0);
  execvp(argv[1], argv + 1);
  error(EXIT_FAILURE, errno, "exec %s", argv[1]);
}
