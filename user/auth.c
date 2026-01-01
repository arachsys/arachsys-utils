#include <err.h>
#include <pwd.h>
#include <regex.h>
#include <resolv.h>
#include <string.h>

static int initialised;
static regex_t regex_ns, regex_txt;

static int ns_query(ns_msg *handle, const char *name, int type) {
  static uint8_t answer[65536];
  ssize_t length;

  length = res_query(name, ns_c_in, type, answer, sizeof answer);
  return length > 0 && ns_initparse(answer, length, handle) >= 0;
}

static int match_ns(char *name, uid_t uid) {
  struct passwd *pw;
  char buffer[254];
  regmatch_t match;
  ns_msg handle;
  ns_rr rr;

  if (!ns_query(&handle, name, ns_t_ns))
    return 0;

  for (size_t i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
    if (ns_parserr(&handle, ns_s_an, i, &rr) < 0)
      continue;
    if (ns_rr_type(rr) != ns_t_ns || strcmp(ns_rr_name(rr), name))
      continue;
    if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
          ns_rr_rdata(rr), buffer, sizeof buffer) < 0)
      continue;

    if (regexec(&regex_ns, buffer, 1, &match, 0) || match.rm_so <= 0)
      continue;
    buffer[match.rm_so] = 0;

    if ((pw = getpwnam(buffer)) && pw->pw_uid == uid)
      return 1;
  }
  return 2;
}

static int match_txt(char *name, uid_t uid) {
  struct passwd *pw;
  char buffer[128];
  regmatch_t match;
  ns_msg handle;
  ns_rr rr;

  if (!ns_query(&handle, name, ns_t_txt))
    return 0;

  for (size_t i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
    if (ns_parserr(&handle, ns_s_an, i, &rr) < 0)
      continue;
    if (ns_rr_type(rr) != ns_t_txt)
      continue;

    if (ns_rr_rdlen(rr) < 15 || ns_rr_rdlen(rr) > 127)
      continue;
    if (ns_rr_rdlen(rr) != 1 + *ns_rr_rdata(rr))
      continue;
    memcpy(buffer, ns_rr_rdata(rr) + 1, *ns_rr_rdata(rr));
    buffer[*ns_rr_rdata(rr)] = 0;

    if (regexec(&regex_txt, buffer, 1, &match, 0) || match.rm_so < 0)
      continue;

    if ((pw = getpwnam(buffer + match.rm_eo)) && pw->pw_uid == uid)
      return 1;
  }
  return 0;
}

int auth_name(char *name, uid_t uid) {
  if (!initialised) {
    if (res_init() < 0)
      err(1, "res_init");
    if (regcomp(&regex_ns, "\\.[a-z]\\.ns\\.arachsys\\.net$",
          REG_EXTENDED | REG_ICASE) < 0)
      errx(1, "regcomp: Failed to compile NS pattern");
    if (regcomp(&regex_txt, "^ARACHSYS[\t ]+USER[\t ]+",
          REG_EXTENDED | REG_ICASE) < 0)
      errx(1, "regcomp: Failed to compile TXT pattern");
    initialised = 1;
  }

  while (1) {
    int ns = match_ns(name, uid);
    int txt = match_txt(name, uid);

    if (ns == 1 || txt == 1)
      return 1;
    if (ns == 2 || *name == 0)
      return 0;
    while (*name && *name++ != '.')
      continue;
  }
}
