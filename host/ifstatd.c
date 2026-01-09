#include <err.h>
#include <errno.h>
#include <fnmatch.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <sys/socket.h>

static void summarise(int stream, int netlink, char **patterns) {
  const struct {
    struct nlmsghdr nlh;
    struct ifinfomsg ifi;
  } request = {
    .nlh = {
      .nlmsg_len = NLMSG_LENGTH(sizeof request.ifi),
      .nlmsg_type = RTM_GETLINK,
      .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP
    },
    .ifi = {
      .ifi_family = AF_UNSPEC
    }
  };

  union {
    struct nlmsghdr nlh;
    char buffer[16384];
  } response;

  while (send(netlink, &request, request.nlh.nlmsg_len, 0) < 0)
    if (errno != EAGAIN && errno != EINTR)
      err(1, "send");

  while (1) {
    ssize_t size = recv(netlink, &response, sizeof response, 0);
    struct nlmsghdr *nlh = &response.nlh;

    if (size < 0) {
      if (errno != EAGAIN && errno != EINTR)
        err(1, "recv");
      continue;
    }

    while (NLMSG_OK(nlh, size)) {
      if (nlh->nlmsg_type == NLMSG_DONE)
        return;

      if (nlh->nlmsg_type == RTM_NEWLINK) {
        size_t length = nlh->nlmsg_len - request.nlh.nlmsg_len;
        struct rtattr *attr = IFLA_RTA(NLMSG_DATA(nlh));
        struct rtnl_link_stats64 *stats = NULL;
        const char *name = NULL;

        while (RTA_OK(attr, length)) {
          if (attr->rta_type == IFLA_IFNAME)
            name = RTA_DATA(attr);
          if (attr->rta_type == IFLA_STATS64)
            stats = RTA_DATA(attr);
          attr = RTA_NEXT(attr, length);
        }

        for (int i = 0; name && stats && patterns[i]; i++)
          if (!fnmatch(patterns[i], name, 0)) {
            dprintf(stream, "%s %llu %llu %llu %llu\n", name,
              stats->rx_bytes, stats->rx_packets,
              stats->tx_bytes, stats->tx_packets);
            break;
          }
      }

      nlh = NLMSG_NEXT(nlh, size);
    }
  }
}

int main(int argc, char **argv) {
  int listener, netlink, stream;
  unsigned int end = 0, port;

  if (argc < 3) {
    fprintf(stderr, "Usage: %s PORT PATTERN...\n", argv[0]);
    return 64;
  }

  if (sscanf(argv[1], "%u%n", &port, &end) < 1 \
        || end != strlen(argv[1]) || port < 0 || port > 65535)
    errx(1, "Invalid port number: %s", argv[1]);

  if ((netlink = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0)
    err(1, "socket AF_NETLINK");

  if ((listener = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
    err(1, "socket AF_INET6");

  if (setsockopt(listener, IPPROTO_IPV6 , IPV6_V6ONLY,
        &(int) { 0 }, sizeof(int)) < 0)
    err(1, "setsockopt IPV6_V6ONLY");

  if (setsockopt(listener, SOL_SOCKET , SO_REUSEADDR,
        &(int) { 1 }, sizeof(int)) < 0)
    err(1, "setsockopt SO_REUSEADDR");

  if (bind(listener,
        (struct sockaddr *) &(struct sockaddr_in6) {
          .sin6_family = AF_INET6,
          .sin6_addr = IN6ADDR_ANY_INIT,
          .sin6_port = htons(port)
        }, sizeof(struct sockaddr_in6)) < 0)
    err(1, "bind %u/tcp", port);

  if (listen(listener, SOMAXCONN) < 0)
    err(1, "listen");

  signal(SIGPIPE, SIG_IGN);

  while (1) {
    while ((stream = accept(listener, NULL, NULL)) < 0)
      if (errno != EAGAIN && errno != EINTR)
        err(1, "accept");
    summarise(stream, netlink, argv + 2);
    close(stream);
  }
}
