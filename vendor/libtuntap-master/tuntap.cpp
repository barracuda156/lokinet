/*
 * Copyright (c) 2012 Tristan Le Guern <tleguern@bouledef.eu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * Copyright (c) 2016 Mahdi Mokhtari <mokhi64@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#if defined Windows
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wspiapi.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdarg.h>

#include <llarp/logger.hpp>

#include "tuntap.h"

extern "C"
{
  struct device *
  tuntap_init(void)
  {
    struct device *dev = NULL;

    if((dev = (struct device *)malloc(sizeof(*dev))) == NULL)
      return NULL;

    (void)memset(dev->if_name, '\0', sizeof(dev->if_name));
    (void)memset(dev->hwaddr, '\0', sizeof(dev->hwaddr));
    dev->tun_fd    = TUNFD_INVALID_VALUE;
    dev->ctrl_sock = -1;
    dev->flags     = 0;

    __tuntap_log = &tuntap_log_default;
    return dev;
  }

  void
  tuntap_destroy(struct device *dev)
  {
    tuntap_sys_destroy(dev);
    tuntap_release(dev);
  }

  char *
  tuntap_get_ifname(struct device *dev)
  {
    return dev->if_name;
  }

  int
  tuntap_version(void)
  {
    return TUNTAP_VERSION;
  }

#if !defined(FreeBSD)
  int
  tuntap_set_ip_old(struct device *dev, const char *addr, int netmask)
  {
    t_tun_in_addr baddr4;
    t_tun_in6_addr baddr6;
    uint32_t mask;
    int errval;

    /* Only accept started device */
    if(dev->tun_fd == TUNFD_INVALID_VALUE)
    {
      llarp::LogInfo("device not started");
      return 0;
    }

    if(addr == NULL)
    {
      llarp::LogError("Invalid address");
      return -1;
    }

    if(netmask < 0 || netmask > 128)
    {
      llarp::LogError("Invalid netmask");
      return -1;
    }

    /* Netmask */
    mask = ~0;
    mask = ~(mask >> netmask);
    mask = htonl(mask);

    /*
     * Destination address parsing: we try IPv4 first and fall back to
     * IPv6 if inet_pton return 0
     */
    (void)memset(&baddr4, '\0', sizeof(baddr4));
    (void)memset(&baddr6, '\0', sizeof(baddr6));

    errval = inet_pton(AF_INET, addr, &(baddr4));
    if(errval == 1)
    {
      return tuntap_sys_set_ipv4(dev, &baddr4, mask);
    }
    else if(errval == 0)
    {
      if(inet_pton(AF_INET6, addr, &(baddr6)) == -1)
      {
        llarp::LogError("invalid ipv6 address: ", addr);
        return -1;
      }
      return tuntap_sys_set_ipv6(dev, &baddr6, mask);
    }
    else if(errval == -1)
    {
      llarp::LogError("invalid address: ", addr);
      return -1;
    }

    /* NOTREACHED */
    return -1;
  }
#endif

  int
  tuntap_set_ip(struct device *dev, ...)
  {
    va_list vl;
    char *saddr;
    char *daddr;
    int netmask;
    t_tun_in_addr sbaddr4;
    t_tun_in6_addr sbaddr6;
#if defined(FreeBSD)
    t_tun_in_addr dbaddr4;
    t_tun_in6_addr dbaddr6;
#endif
    uint32_t mask;
    int errval;

    saddr = daddr = NULL;
    netmask       = -1;

    va_start(vl, dev);
    saddr   = va_arg(vl, char *);
    netmask = va_arg(vl, int);
#if defined(FreeBSD)
    if(dev->mode == TUNTAP_MODE_TUNNEL)
      daddr = va_arg(vl, char *);
#endif
    va_end(vl);

    /* Only accept started device */
    if(dev->tun_fd == TUNFD_INVALID_VALUE)
    {
      llarp::LogWarn("device not started");
      return 0;
    }

    if(saddr == NULL)
    {
      llarp::LogWarn("invalid source addr");
      return -1;
    }

    if(netmask < 0 || netmask > 128)
    {
      llarp::LogWarn("invalid netmask");
      return -1;
    }

    /* Netmask */
    mask = ~0;
    mask = ~(mask >> netmask);
    mask = htonl(mask);

    /*
     * Destination address parsing: we try IPv4 first and fall back to
     * IPv6 if inet_pton return 0
     */
    (void)memset(&sbaddr4, 0, sizeof(sbaddr4));
    (void)memset(&sbaddr6, 0, sizeof(sbaddr6));

    errval = inet_pton(AF_INET, saddr, &(sbaddr4));
    if(errval == 1)
    {
#if defined(FreeBSD)
#define tuntap_sys_set_ipv4 tuntap_sys_set_ipv4_tap
      if(dev->mode == TUNTAP_MODE_TUNNEL)
      {
        if(daddr == NULL)
        {
          llarp::LogWarn("invalid destination address");
          return -1;
        }
        (void)memset(&dbaddr4, 0, sizeof(dbaddr4));
        (void)inet_pton(AF_INET, daddr, &(dbaddr4));
        return tuntap_sys_set_ipv4_tun(dev, &sbaddr4, &dbaddr4, mask);
      }
      else
#endif
      {
        return tuntap_sys_set_ipv4(dev, &sbaddr4, mask);
      }
    }
    else if(errval == 0)
    {
#if !defined(FreeBSD) /* No IPV6 tests YET */
      if(inet_pton(AF_INET6, saddr, &(sbaddr6)) == -1)
      {
        llarp::LogWarn("invalid ip6 source address: ", saddr);
        return -1;
      }
      return tuntap_sys_set_ipv6(dev, &sbaddr6, mask);
    }
    else if(errval == -1)
    {
      llarp::LogWarn("invalid ip6 source address: ", saddr);
      return -1;
#endif
    }

    /* NOTREACHED */
    return -1;
  }
}