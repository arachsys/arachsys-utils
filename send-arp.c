#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void atoip(const char *s, struct in_addr *i) {
  struct hostent *h;
  i->s_addr = inet_addr(s);
  if (i->s_addr == -1) {
    if ((h = gethostbyname(s)))
      memcpy(i, h->h_addr, sizeof(i));
    else
      error(1, 0, "Unknown host '%s'", s);
  }
}

void atohw(const char *s, u_int8_t *h) {
  char a, b, i;

  for (a = b = i = 0; i < ETH_ALEN; i++, h++) {
    if (!(a = tolower(*s++)) || !(b = tolower(*s++)))
      error(1, 0, "Invalid hardware address length");

    if (isdigit(a))
      *h = (a - '0') << 4;
    else if (a >= 'a' && a <= 'f')
      *h = (a - 'a' + 10) << 4;
    else
      error(1, 0, "Invalid digit in hardware address");

    if (isdigit(b))
      *h |= b - '0';
    else if (b >= 'a' && b <= 'f')
      *h |= b - 'a' + 10;
    else
      error(1, 0, "Invalid digit in hardware address");

    if (*s == ':')
      s++;
  }
}

void usage(char *progname) {
  fprintf(stderr, "\
Usage: %s [OPTIONS] INTERFACE SENDER-IP SENDER-HW [TARGET-IP TARGET-HW]\n\
Options:\n\
  -i N  send arp broadcast every N milliseconds\n\
\n\
TARGET-IP and TARGET HW default to SENDER-IP and ff:ff:ff:ff:ff:ff for\n\
gratuitous arp broadcast.\n\
", progname);
  exit(1);
}

int main(int argc, char **argv) {
  int i = 0, opt, s;
  char *progname = argv[0];
  struct ifreq ifr;
  struct sockaddr_ll sa;
  struct {
    struct ether_header eh;
    struct arphdr ah;
    u_int8_t ar_sha[ETH_ALEN];
    struct in_addr ar_sip;
    u_int8_t ar_tha[ETH_ALEN];
    struct in_addr ar_tip;
    u_int8_t padding[18];
  } p;

  while ((opt = getopt(argc, argv, "i:")) > 0)
    switch (opt) {
      case 'i':
        i = atoi(optarg);
        if (i == 0)
          error(1, 0, "-i takes a positive integer argument");
        i *= 1000;
        break;
      default:
        usage(progname);
    }
  argc -= optind;
  argv += optind;

  if (argc != 3 && argc != 5)
    usage(progname);

  atoip(argv[1], &p.ar_sip);
  atohw(argv[2], p.eh.ether_shost);
  atohw(argv[2], p.ar_sha);
  if (argc > 4) {
    atoip(argv[3], &p.ar_tip);
    atohw(argv[3], p.eh.ether_dhost);
    atohw(argv[4], p.ar_tha);
  } else {
    atoip(argv[1], &p.ar_tip);
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

  s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_RARP));
  if (s < 0)
    error(1, errno, "socket");

  strncpy (ifr.ifr_name, argv[0], IFNAMSIZ);
  if (ioctl(s, SIOCGIFINDEX, &ifr) < 0)
    error(1, errno, "ioctl SIOCGIFINDEX");

  sa.sll_family = AF_PACKET;
  sa.sll_ifindex = ifr.ifr_ifindex;
  sa.sll_halen = ETH_ALEN;

  while (1) {
    if (sendto(s, &p, sizeof(p), 0, (struct sockaddr *) &sa, sizeof(sa)) < 0)
      error(1, errno, "sendto");
    if (i == 0)
      exit(0);
    usleep(i);
  }
}
