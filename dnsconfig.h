#ifndef DNSCONFIG_H
#define DNSCONFIG_H

int auth_name(const char *name, uid_t uid);
int check_name(const char *name, int wild);
size_t filter(char *domain, uid_t uid, FILE *input, FILE *include,
  FILE *exclude, int errors);

#endif
