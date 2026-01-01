#include <err.h>
#include <pwd.h>
#include <regex.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static regex_t regex_ns, regex_txt;
static size_t capacity, count, size;
static char **domains, *line;

static int compare(const void *a, const void *b) {
  return strcmp(*(const char **) a, *(const char **) b);
}

int main(void) {
  struct passwd *dns = getpwnam("dns");
  uid_t uid = getuid();
  FILE *data;

  if (!dns || setgid(dns->pw_gid) < 0 || setuid(dns->pw_uid) < 0)
    errx(1, "Failed to drop privileges");
  if (chdir("/etc/dns") < 0)
    err(1, "chdir /etc/dns");

  if (uid == 0 && regcomp(&regex_ns, "^\\.([-.0-9_a-z]*):",
        REG_EXTENDED | REG_ICASE) < 0)
    errx(1, "regcomp: Failed to compile NS pattern");

  if (uid != 0 && regcomp(&regex_ns,
        "^[.&]([-.0-9_a-z]*):([-0-9_a-z]+)\\.[a-z]\\.ns\\.arachsys\\.net(:|$)",
        REG_EXTENDED | REG_ICASE) < 0)
    errx(1, "regcomp: Failed to compile NS pattern");

  if (uid != 0 && regcomp(&regex_txt,
        "^'([-.0-9_a-z]*):ARACHSYS[\t ]+USER[\t ]+([-0-9_a-z]+)(:|$)",
        REG_EXTENDED | REG_ICASE) < 0)
    errx(1, "regcomp: Failed to compile TXT pattern");

  if (!(data = fopen("data", "r")))
    err(1, "open");

  while (getline(&line, &size, data) >= 0) {
    char *domain = NULL, *username = NULL;
    regmatch_t match[4];

    for (size_t i = strlen(line); i-- > 0; line[i] = 0)
      if (line[i] != '\t' && line[i] != '\n' && line[i] != ' ')
        break;

    if (regexec(&regex_ns, line, 4, match, 0) == 0) {
      domain = line + match[1].rm_so;
      line[match[1].rm_eo] = 0;
      if (uid != 0) {
        username = line + match[2].rm_so;
        line[match[2].rm_eo] = 0;
      }
    } else if (uid != 0 && regexec(&regex_txt, line, 4, match, 0) == 0) {
      domain = line + match[1].rm_so;
      username = line + match[2].rm_so;
      line[match[1].rm_eo] = 0;
      line[match[2].rm_eo] = 0;
    }

    if (username) {
      struct passwd *pw = getpwnam(username);
      if (!pw || pw->pw_uid != uid)
        continue;
    }

    if (domain) {
      if (capacity <= count) {
        capacity = capacity ? capacity << 1 : 256;
        if (!(domains = realloc(domains, capacity * sizeof *domains)))
          err(1, "realloc");
      }
      if (!(domains[count++] = strdup(domain)))
        err(1, "strdup");
    }
  }

  qsort(domains, count, sizeof *domains, compare);
  for (size_t i = 0; i < count; i++)
    if (i == 0 || strcmp(domains[i - 1], domains[i]))
      puts(domains[i]);
  fclose(data);
  return 0;
}
