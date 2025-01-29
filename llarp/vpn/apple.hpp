#pragma once

#include "platform.hpp"
#include "common.hpp"

#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/kern_event.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/uio.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#include <fcntl.h>
#include <ifaddrs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

namespace llarp::vpn
{
  class AppleInterface : public NetworkInterface
  {
    const int m_fd;
    std::string m_IfName;

    static void
    Exec(std::string cmd)
    {
      system(cmd.c_str());
    }

   public:
    AppleInterface(InterfaceInfo info)
        : NetworkInterface{std::move(info)}, m_fd{::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)}
    {
      if (m_fd == -1)
        throw std::invalid_argument{"cannot open control socket: " + std::string{strerror(errno)}};

      ctl_info cinfo{};
      const std::string apple_utun = "com.apple.net.utun_control";
      std::copy_n(apple_utun.c_str(), apple_utun.size(), cinfo.ctl_name);
      if (::ioctl(m_fd, CTLIOCGINFO, &cinfo) < 0)
      {
        ::close(m_fd);
        throw std::runtime_error{"ioctl CTLIOCGINFO call failed: " + std::string{strerror(errno)}};
      }
      sockaddr_ctl addr{};
      addr.sc_id = cinfo.ctl_id;

      addr.sc_len = sizeof(addr);
      addr.sc_family = AF_SYSTEM;
      addr.ss_sysaddr = AF_SYS_CONTROL;
      addr.sc_unit = 0;

      if (connect(m_fd, (sockaddr*)&addr, sizeof(addr)) < 0)
      {
        ::close(m_fd);
        throw std::runtime_error{
            "cannot connect to control socket address: " + std::string{strerror(errno)}};
      }
      uint32_t namesz = IFNAMSIZ;
      char name[IFNAMSIZ + 1]{};
      if (getsockopt(m_fd, SYSPROTO_CONTROL, 2, name, &namesz) < 0)
      {
        ::close(m_fd);
        throw std::runtime_error{
            "cannot query for interface name: " + std::string{strerror(errno)}};
      }
      m_IfName = name;
      for (const auto& ifaddr : m_Info.addrs)
      {
        if (ifaddr.fam == AF_INET)
        {
          const huint32_t addr = net::TruncateV6(ifaddr.range.addr);
          const huint32_t netmask = net::TruncateV6(ifaddr.range.netmask_bits);
          const huint32_t daddr = addr & netmask;
          Exec(
              "/sbin/ifconfig " + m_IfName + " " + addr.ToString() + " " + daddr.ToString()
              + " mtu 1500 netmask 255.255.255.255 up");
          Exec(
              "/sbin/route add " + daddr.ToString() + " -netmask " + netmask.ToString()
              + " -interface " + m_IfName);
          Exec("/sbin/route add " + addr.ToString() + " -interface lo0");
        }
        else if (ifaddr.fam == AF_INET6)
        {
          Exec("/sbin/ifconfig " + m_IfName + " inet6 " + ifaddr.range.ToString());
        }
      }
    }

    ~AppleInterface()
    {
      ::close(m_fd);
    }

    int
    PollFD() const override
    {
      return m_fd;
    }

    net::IPPacket
    ReadNextPacket() override
    {
      constexpr int uintsize = sizeof(unsigned int);
      net::IPPacket pkt{};
      unsigned int pktinfo = 0;
      const struct iovec vecs[2] = {
          {.iov_base = &pktinfo, .iov_len = uintsize},
          {.iov_base = pkt.data(), .iov_len = sizeof(pkt.data())}
        };
      int sz = readv(m_fd, vecs, 2);
      if (sz >= uintsize)
        sz -= sizeof(unsigned int);
      else if (sz >= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
        sz = 0;
      else
        throw std::error_code{errno, std::system_category()};
      return pkt;
    }

    bool
    WritePacket(net::IPPacket pkt) override
    {
      static unsigned int af4 = htonl(AF_INET);
      static unsigned int af6 = htonl(AF_INET6);

      const struct iovec vecs[2] = {
          {.iov_base = pkt.IsV6() ? &af6 : &af4, .iov_len = sizeof(unsigned int)},
          {.iov_base = pkt.data(), .iov_len = pkt.size()}
        };

      ssize_t sz = writev(m_fd, vecs, 2);
      if (sz >= (int)sizeof(unsigned int))
      {
        sz -= sizeof(unsigned int);
        return static_cast<size_t>(sz) == pkt.size();
      }
      return false;
    }
  };

  class AppleRouteManager : public IRouteManager
  {
    void AddRoute(net::ipaddr_t, net::ipaddr_t) override{};

    void DelRoute(net::ipaddr_t, net::ipaddr_t) override{};

    void
    AddDefaultRouteViaInterface(NetworkInterface&) override{};

    void
    DelDefaultRouteViaInterface(NetworkInterface&) override{};

    void
    AddRouteViaInterface(NetworkInterface&, IPRange) override{};

    void
    DelRouteViaInterface(NetworkInterface&, IPRange) override{};

    std::vector<net::ipaddr_t>
    GetGatewaysNotOnInterface(NetworkInterface&) override
    {
      return std::vector<net::ipaddr_t>{};
    };
  };

  class ApplePlatform : public Platform
  {
    AppleRouteManager _routeManager{};

   public:
    std::shared_ptr<NetworkInterface>
    ObtainInterface(InterfaceInfo info, AbstractRouter*) override
    {
      return std::make_shared<AppleInterface>(std::move(info));
    };

    IRouteManager&
    RouteManager() override
    {
      return _routeManager;
    }
  };
}  // namespace llarp::vpn
