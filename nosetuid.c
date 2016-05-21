#include <sys/prctl.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s command [args]\n", argv[0]);
    exit(1);
  }
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  execvp(argv[1], argv + 1);
  error(EXIT_FAILURE, errno, "exec %s", argv[1]);
}
