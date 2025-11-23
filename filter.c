#include <err.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "dnsconfig.h"
#include "scan.h"
#include "stralloc.h"

static stralloc f[15];
static int verbose;

static char *line;
static size_t size;
static size_t failc;
static size_t linec;

static int fail(const char *fmt, ...) {
  va_list args;

  if (verbose) {
    fprintf(stderr, "%zu: ", linec);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
  }
  return 0;
}

static int check_count(size_t max) {
  for (size_t i = max; i < sizeof f / sizeof *f; i++)
    if (f[i].len > 0)
      return fail("Too many fields");
  return 1;
}

int check_name(const char *name, int wild) {
  const char *permitted = "-0123456789_abcdefghijklmnopqrstuvwxyz";
  size_t i = 0, j = 0;

  if (strlen(name) > 253)
    return fail("Domain name too long: %s", name);
  if (wild && name[0] == '*' && name[1] == 0)
    return 1;
  if (wild && name[0] == '*' && name[1] == '.')
    i += 2;

  while (name[i])
    if (strchr(permitted, name[i])) {
      if (j >= 63)
        return fail("Invalid domain name: %s", name);
      i++, j++;
    } else {
      if (name[i] != '.')
        return fail("Illegal character in domain name: %s", name);
      if (!name[i + 1] || j == 0)
        return fail("Invalid domain name: %s", name);
      i++, j = 0;
    }
  return 1;
}

static int check_mail(const stralloc *in) {
  const char *permitted = "-0123456789_abcdefghijklmnopqrstuvwxyz";
  const char *at = memchr(in->s, '@', in->len);
  size_t i = 0, j = 0;

  if (!at)
    return check_name(in->s, 0);
  if (at > in->s + 63 || in->len > 253)
    return fail("Email address too long: %s", in->s);

  while (i < in->len)
    if (strchr(permitted, in->s[i])) {
      if (j >= 63)
        return fail("Invalid domain name: %s", in->s);
      i++, j++;
    } else {
      if (in->s[i] != '.')
        return fail("Illegal character in domain name: %s", in->s);
      if (i == in->len - 1 || j == 0)
        return fail("Invalid domain name: %s", in->s);
      i++, j = 0;
    }
  return 1;
}

static int check_ip(const stralloc *in, uid_t uid) {
  static stralloc name;
  char ip[16];

  if (in->len == 0)
    return fail("Missing IP address");
  if (!stralloc_ready(&name, 73))
    err(1, "stralloc");
  stralloc_zero(&name);

  if (scan_ip4(in->s, ip) == in->len) {
    if (uid == 0)
      return 1;
    for (int i = 0; i < 4; i++) {
      size_t digits = 1;
      for (uint8_t x = ip[3 - i]; x > 9; x /= 10)
        digits++;
      for (uint8_t j = 1, x = ip[3 - i]; j <= digits; j++)
        name.s[name.len + digits - j] = '0' + x % 10, x /= 10;
      name.s[name.len + digits] = '.';
      name.len += digits + 1;
    }
    memcpy(name.s + name.len, "in-addr.arpa\0", 13);
    name.len += 12; /* not including \0 */
    return auth_name(name.s, uid);
  }

  if (scan_ip6(in->s, ip) == in->len) {
    if (uid == 0)
      return 1;
    for (int i = 0; i < 16; i++) {
      const char xdigit[16] = "0123456789abcdef";
      name.s[name.len++] = xdigit[(uint8_t) ip[15 - i] & 15];
      name.s[name.len++] = '.';
      name.s[name.len++] = xdigit[(uint8_t) ip[15 - i] >> 4];
      name.s[name.len++] = '.';
    }
    memcpy(name.s + name.len, "ip6.arpa\0", 9);
    name.len += 8; /* not including \0 */
    return auth_name(name.s, uid);
  }

  return fail("Invalid IP address: %s", in->s);
}

static int check_suffix(const stralloc *in, const char *suffix) {
  size_t n = strlen(suffix);

  if (in->len < n || strcmp(in->s + in->len - n, suffix))
    return fail("Record outside %s", suffix);
  if (in->len > n && n > 0 && in->s[in->len - n - 1] != '.')
    return fail("Record outside %s", suffix);
  return 1;
}

static int parse_loc(char loc[2], const stralloc *in) {
  if (in->len > 2)
    return fail("Invalid location code: %s", in->s);
  loc[0] = in->len > 0 ? in->s[0] : 0;
  loc[1] = in->len > 1 ? in->s[1] : 0;
  return 1;
}

static void parse_text(stralloc *sa) {
  size_t i = 0, j = 0;
  uint8_t byte;

  while (i < sa->len) {
    byte = sa->s[i++];
    if (byte == '\\') {
      if (i >= sa->len)
        break;
      byte = sa->s[i++];

      if (byte >= '0' && byte <= '7') {
        byte = byte - '0';
        if (i < sa->len && sa->s[i] >= '0' && sa->s[i] <= '7') {
          byte = (byte << 3) + sa->s[i++] - '0';
          if (i < sa->len && sa->s[i] >= '0' && sa->s[i] <= '7' && byte < 32)
            byte = (byte << 3) + sa->s[i++] - '0';
        }
      }
    }
    sa->s[j++] = byte;
  }
  sa->len = j;
}

static int parse_ttl(uint32_t *ttl, const stralloc *in) {
  if (in->len == 0)
    *ttl = 0;
  if (in->len && scan_uint32(in->s, ttl) != in->len)
    return fail("Invalid TTL: %s", in->s);
  return 1;
}

static int parse_ttd(uint64_t *ttd, const stralloc *in) {
  if (scan_uint64(in->s, ttd) == in->len)
    return 1;
  if (in->len > 1 && scan_uint64(in->s + 1, ttd) == in->len - 1) {
    if (*in->s == '-')
      *ttd += 0x8000000000000000;
    if (*in->s == '+' || *in->s == '-')
      return 1;
  }
  return fail("Invalid TTD: %s", in->s);
}

static int parse_uint16(uint16_t *out, const stralloc *in) {
  if (in->len == 0)
    *out = 0;
  if (in->len && scan_uint16(in->s, out) != in->len)
    return fail("Invalid 16-bit value: %s", in->s);
  return 1;
}

static int parse_uint32(uint32_t *out, const stralloc *in) {
  if (in->len == 0)
    *out = 0;
  if (in->len && scan_uint32(in->s, out) != in->len)
    return fail("Invalid 32-bit value: %s", in->s);
  return 1;
}

static int check(const char *domain, uid_t uid) {
  uint16_t u16;
  uint32_t u32;
  uint64_t u64;
  char loc[2];

  if (!check_name(f[0].s, 1) || !check_suffix(&f[0], domain))
    return 0;

  switch(*line) {
    case 'Z':
      if (!check_count(8))
        return 0;
      if (!check_name(f[1].s, 0))
        return 0;
      if (!check_mail(&f[2]))
        return 0;
      if (!parse_ttl(&u32, &f[8]))
        return 0;
      if (!parse_ttd(&u64, &f[9]))
        return 0;
      if (!parse_loc(loc, &f[10]))
        return 0;
      if (!parse_uint32(&u32, &f[3]))
        return 0;
      if (!parse_uint32(&u32, &f[4]))
        return 0;
      if (!parse_uint32(&u32, &f[5]))
        return 0;
      if (!parse_uint32(&u32, &f[6]))
        return 0;
      if (!parse_uint32(&u32, &f[7]))
        return 0;
      return 1;

    case '.':
    case '&':
      if (!check_count(5))
        return 0;
      if (!check_name(f[1].s, 0))
        return 0;
      if (!parse_ttl(&u32, &f[2]))
        return 0;
      if (!parse_ttd(&u64, &f[3]))
        return 0;
      if (!parse_loc(loc, &f[4]))
        return 0;
      return 1;

    case '+':
    case '=':
      if (!check_count(5))
        return 0;
      if (!check_ip(&f[1], *line == '=' ? uid : 0))
        return 0;
      if (!parse_ttl(&u32, &f[2]))
        return 0;
      if (!parse_ttd(&u64, &f[3]))
        return 0;
      if (!parse_loc(loc, &f[4]))
        return 0;
      return 1;


    case '@':
      if (!check_count(6))
        return 0;
      if (!check_name(f[1].s, 0))
        return 0;
      if (!parse_uint16(&u16, &f[2]))
        return 0;
      if (!parse_ttl(&u32, &f[3]))
        return 0;
      if (!parse_ttd(&u64, &f[4]))
        return 0;
      if (!parse_loc(loc, &f[5]))
        return 0;
      return 1;

    case 'S':
      if (!check_count(8))
        return 0;
      if (!check_name(f[1].s, 0))
        return 0;
      if (!parse_uint16(&u16, &f[2]))
        return 0;
      if (!parse_uint16(&u16, &f[3]))
        return 0;
      if (!parse_uint16(&u16, &f[4]))
        return 0;
      if (!parse_ttl(&u32, &f[5]))
        return 0;
      if (!parse_ttd(&u64, &f[6]))
        return 0;
      if (!parse_loc(loc, &f[7]))
        return 0;
      return 1;

    case 'C':
    case '^':
      if (!check_count(5))
        return 0;
      if (!check_name(f[1].s, *line == 'C'))
        return 0;
      if (!parse_ttl(&u32, &f[2]))
        return 0;
      if (!parse_ttd(&u64, &f[3]))
        return 0;
      if (!parse_loc(loc, &f[4]))
        return 0;
      return 1;

    case '\'':
      if (!check_count(5))
        return 0;
      if (parse_text(&f[1]), f[1].len > 65279)
        return fail("Record too long");
      if (!parse_ttl(&u32, &f[2]))
        return 0;
      if (!parse_ttd(&u64, &f[3]))
        return 0;
      if (!parse_loc(loc, &f[4]))
        return 0;
      return 1;

    case ':':
      if (!check_count(6))
        return 0;

      if (!parse_uint16(&u16, &f[1]))
        return 0;
      if (u16 == 0)
        return fail("Type 0 is prohibited");
      if (u16 == 2)
        return fail("Type NS is prohibited");
      if (u16 == 5)
        return fail("Type CNAME is prohibited");
      if (u16 == 6)
        return fail("Type SOA is prohibited");
      if (u16 == 12)
        return fail("Type PTR is prohibited");
      if (u16 == 15)
        return fail("Type MX is prohibited");
      if (u16 == 39)
        return fail("Type DNAME is prohibited");
      if (u16 == 251)
        return fail("Type IXFR is prohibited");
      if (u16 == 252)
        return fail("Type AXFR is prohibited");

      if (parse_text(&f[1]), f[1].len > 65535)
        return fail("Record too long");
      if (!parse_ttl(&u32, &f[3]))
        return 0;
      if (!parse_ttd(&u64, &f[4]))
        return 0;
      if (!parse_loc(loc, &f[5]))
        return 0;
      return 1;

    case '-':
      if (!check_count(3))
        return 0;
      if (!parse_ttd(&u64, &f[1]))
        return 0;
      if (!parse_loc(loc, &f[2]))
        return 0;
      return 1;
  }
  return fail("Unrecognized record type: %c", *line);
}

static int putline(const char *line, size_t length, FILE *stream) {
  if (fwrite(line, length, 1, stream) != 1)
    return -1;
  if (putc('\n', stream) != '\n')
    return -1;
  return 0;
}

size_t filter(char *domain, uid_t uid, FILE *input, FILE *include,
    FILE *exclude, int errors) {
  const char fs = ':';
  failc = linec = 0;
  verbose = errors;

  while (linec++, getline(&line, &size, input) >= 0) {
    for (size_t i = strlen(line); i-- > 0; line[i] = 0)
      if (line[i] != '\t' && line[i] != '\n' && line[i] != ' ')
        break;
    if (line[0] == 0 || line[0] == '#') {
      if (exclude && putline(line, strlen(line), exclude) < 0)
        err(1, "fwrite");
      continue;
    }

    for (size_t i = 0; line[i]; i++)
      if (line[i] >= 0 && line[i] < 32 && line[i] != '\t')
        errx(1, "Illegal control characters");

    for (size_t j = 0; j < sizeof f / sizeof *f; j++)
      stralloc_zero(&f[j]);

    for (size_t i = 1, j = 0; line[i] && j < sizeof f / sizeof *f; i++) {
      if (line[i] == '\\' && line[i + 1] && line[i + 1] != '\n') {
        if (line[i + 1] == fs && !stralloc_catb(&f[j], &fs, 1))
          err(1, "stralloc");
        if (line[i + 1] != fs && !stralloc_catb(&f[j], line + i, 2))
          err(1, "stralloc");
        i += 1;
      } else {
        if (line[i] != fs && !stralloc_catb(&f[j], line + i, 1))
          err(1, "stralloc");
        j += line[i] == fs;
      }
    }

    for (size_t j = 0; j < sizeof f / sizeof *f; j++)
      if (!stralloc_guard(&f[j]))
        err(1, "stralloc");

    if (check(domain, uid)) {
      if (include && putline(line, strlen(line), include) < 0)
        err(1, "fwrite");
    } else {
      if (exclude && putline(line, strlen(line), exclude) < 0)
        err(1, "fwrite");
      if (failc++, errors >= 2)
        break;
    }
  }
  return failc;
}
