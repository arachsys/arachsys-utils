#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void atoip(const char *s, struct in_addr *i) {
  struct hostent *h;
  i->s_addr = inet_addr(s);
  if (i->s_addr == -1) {
    if ((h = gethostbyname(s)))
      memcpy(i, h->h_addr, sizeof(i));
    else
      error(1, 0, "unknown host '%s'", s);
  }
}

void atohw(const char *s, u_int8_t *h) {
  char a, b, i;

  for (a = b = i = 0; i < ETH_ALEN; i++, h++) {
    if (!(a = tolower(*s++)) || !(b = tolower(*s++)))
      error(1, 0, "invalid hardware address length");

    if (isdigit(a))
      *h = (a - '0') << 4;
    else if (a >= 'a' && a <= 'f')
      *h = (a - 'a' + 10) << 4;
    else
      error(1, 0, "invalid digit in hardware address");

    if (isdigit(b))
      *h |= b - '0';
    else if (b >= 'a' && b <= 'f')
      *h |= b - 'a' + 10;
    else
      error(1, 0, "invalid digit in hardware address");

    if (*s == ':')
      s++;
  }
}

int main(int argc, char **argv) {
  int s;
  struct sockaddr sa;
  struct {
    struct ether_header eh;
    struct arphdr ah;
    u_int8_t ar_sha[ETH_ALEN];
    struct in_addr ar_sip;
    u_int8_t ar_tha[ETH_ALEN];
    struct in_addr ar_tip;
    u_int8_t padding[18];
  } p;

  if (argc != 4 && argc != 6) {
    fprintf(stderr, "\
Usage: %s INTERFACE SENDER-IP SENDER-HW [TARGET-IP TARGET-HW]\n\
TARGET-IP and TARGET HW default to SENDER-IP and ff:ff:ff:ff:ff:ff for\n\
gratuitous arp broadcast.\n\
", argv[0]);
    exit(1);
  }

  atoip(argv[2], &p.ar_sip);
  atohw(argv[3], p.eh.ether_shost);
  atohw(argv[3], p.ar_sha);
  if (argc > 5) {
    atoip(argv[4], &p.ar_tip);
    atohw(argv[5], p.eh.ether_dhost);
    atohw(argv[5], p.ar_tha);
  } else {
    atoip(argv[2], &p.ar_tip);
    atohw("ff:ff:ff:ff:ff:ff", p.eh.ether_dhost);
    atohw("ff:ff:ff:ff:ff:ff", p.ar_tha);
  }

  p.eh.ether_type = htons(ETHERTYPE_ARP);
  p.ah.ar_hrd = htons(ARPHRD_ETHER);
  p.ah.ar_pro = htons(ETHERTYPE_IP);
  p.ah.ar_hln = ETH_ALEN;
  p.ah.ar_pln = sizeof(struct in_addr);
  p.ah.ar_op = htons(ARPOP_REPLY);
  memset(&p.padding, 0, sizeof(p.padding));

  s = socket(PF_INET, SOCK_PACKET, htons(ETH_P_RARP));
  if (s < 0)
    error(1, errno, "socket");
  strncpy(sa.sa_data, argv[1], sizeof(sa.sa_data));
  if (sendto(s, &p, sizeof(p), 0, &sa, sizeof(sa)) < 0)
    error(1, errno, "sendto");
  exit(0);
}
