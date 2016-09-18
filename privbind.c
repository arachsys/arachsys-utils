#include <linux/capability.h>
#include <sys/prctl.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern int capget(cap_user_header_t header, cap_user_data_t data);
extern int capset(cap_user_header_t header, const cap_user_data_t data);

int main(int argc, char **argv) {
  struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
  struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];

  if (argc < 2) {
    fprintf(stderr, "Usage: %s COMMAND [ARGS]\n", argv[0]);
    exit(1);
  }

  prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
  if (setgid(getgid()) < 0 || setuid(getuid()) < 0)
    error(EXIT_FAILURE, 0, "Failed to drop privileges");

  capget(&header, data);
  data[CAP_NET_BIND_SERVICE >> 5].inheritable
    = 1 << (CAP_NET_BIND_SERVICE & 31);
  capset(&header, data);
  prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_BIND_SERVICE, 0, 0);

  execvp(argv[1], argv + 1);
  error(EXIT_FAILURE, errno, "exec %s", argv[1]);
}
