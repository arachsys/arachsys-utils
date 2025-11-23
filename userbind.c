#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

static const struct __user_cap_header_struct head = {
  .version = _LINUX_CAPABILITY_VERSION_3,
};

static struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];

static int wrapper(void) {
  char *name, *shell = getenv("SHELL");
  char *command = getenv("SSH_ORIGINAL_COMMAND");

  if (!command || !command[0])
    command = NULL;
  else if (!(command = strdup(command)))
    err(1, "strdup");

  if (!shell || !shell[0])
    shell = "/bin/sh";
  else if (!(shell = strdup(shell)))
    err(1, "strdup");

  unsetenv("SSH_ORIGINAL_COMMAND");

  if ((name = strrchr(shell, '/'))) {
    if (asprintf(&name, "-%s", name + 1) < 0)
      err(1, "asprintf");
  } else if (asprintf(&name, "-%s", shell) < 0) {
    err(1, "asprintf");
  }

  if (command)
    execl(shell, name + 1, "-c", command, NULL);
  else
    execl(shell, name, NULL);
  err(1, "execl");
}

int main(int argc, char **argv) {
  char *path;
  int fd;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s ( --ssh | CMD... )\n", argv[0]);
    return 64;
  }

  if (asprintf(&path, "/run/netns/user-%u", getuid()) < 0)
    err(1, "asprintf");
  if ((fd = open(path, O_RDONLY)) < 0 && errno != ENOENT)
    err(1, "%s", path);
  free(path);

  if (fd >= 0) {
    if (setns(fd, CLONE_NEWNET) < 0)
      err(1, "setns");
    close(fd);

    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0)
      err(1, "prctl PR_SET_KEEPCAPS");
    if (setgid(getgid()) < 0 || setuid(getuid()) < 0)
      err(1, "setuid");

    if (syscall(SYS_capget, &head, data) < 0)
      err(1, "capget");
    data[CAP_NET_BIND_SERVICE >> 5].inheritable
      |= 1U << (CAP_NET_BIND_SERVICE & 31);
    if (syscall(SYS_capset, &head, data) < 0)
      err(1, "capset");

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE,
          CAP_NET_BIND_SERVICE, 0, 0) < 0)
      err(1, "prctl PR_CAP_AMBIENT_RAISE");
  } else if (setgid(getgid()) < 0 || setuid(getuid()) < 0) {
    err(1, "setuid");
  }

  if (!strcmp(argv[1], "--ssh"))
    return wrapper();
  execvp(argv[1], argv + 1);
  err(1, "exec %s", argv[1]);
}
