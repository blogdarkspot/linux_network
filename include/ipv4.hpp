#ifndef __IPV4_PROTOCOL__
#define __IPV4_PROTOCOL__

#include <cinttypes>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <string>
#include <sys/types.h>

namespace io::network::ipv4
{

struct header
{
#if defined(__LITTLE_ENDIAN_BITFIELD)
  std::uint8_t ihl : 4, version : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
  std::uint8_t version : 4, ihl : 4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
  std::uint8_t tos;
  std::uint16_t tot_len;
  std::uint16_t id;
  std::uint16_t frag_off;
  std::uint8_t ttl;
  std::uint8_t protocol;
  std::uint16_t check;
  std::uint32_t saddr;
  std::uint32_t daddr;
};

struct icmp
{
  std::uint8_t type;
  std::uint8_t code;
  std::uint16_t checksum;
  std::uint16_t identifier;
  std::uint16_t sequence;
};

/**
 * @brief This enum class represents the network protocols over ipv4
 * @ref icmp https://datatracker.ietf.org/doc/html/rfc792
 * @ref tcp https://datatracker.ietf.org/doc/html/rfc9293
 * @ref udp https://datatracker.ietf.org/doc/html/rfc768
 */
enum class protocols : std::uint8_t
{
  icmp = 1,
  tcp = 6,
  udp = 17
};

enum class precedence : std::uint8_t
{
  routine = 0,
  priority = 1,
  immediate = 2,
  flash = 3,
  flash_override = 4,
  critical = 5,
  internetwork_control = 6,
  network_control = 7
};

enum class copiedFlag : std::uint8_t
{
  not_copied = 0,
  copied = 1
};

enum class optionClasses : std::uint8_t
{
  control = 0,
  reserved = 1,
  debug = 2,
  reserved2 = 3
};

constexpr std::uint8_t copied_flag_mask = 0x80;
constexpr std::uint8_t option_class_mask = 0x60;
constexpr std::uint8_t option_number_mask = 0x1F;
constexpr std::uint8_t precedence_mask = 0xE0;

inline bool
is_low_delay (std::uint8_t tos)
{
  return tos & 0x10;
}

inline bool
is_high_throughput (std::uint8_t tos)
{
  return tos & 0x08;
}

inline bool
is_high_reliability (std::uint8_t tos)
{
  return tos & 0x04;
}

enum class fragment_flags : std::uint16_t
{
  reserved = 0x8000,
  dont_fragment = 0x4000,
  more_fragments = 0x2000
};

inline bool
is_last_fragment (std::uint16_t frag_off)
{
  return frag_off & 0x02;
}

inline bool
is_dont_fragment (std::uint16_t frag_off)
{
  return frag_off & 0x01;
}

constexpr std::uint32_t ipv4_class_a_network_mask = 0x7F000000;
constexpr std::uint32_t ipv4_class_a_address_mask = 0x00FFFFFF;
constexpr std::uint32_t ipv4_class_b_network_mask = 0x3FFF0000;
constexpr std::uint32_t ipv4_class_b_address_mask = 0x0000FFFF;
constexpr std::uint32_t ipv4_class_c_network_mask = 0xDFFFFF00;
constexpr std::uint32_t ipv4_class_c_address_mask = 0x000000FF;

static const std::string
ip_to_string (std::uint32_t ip)
{
  std::string ip_str;
  ip_str += std::to_string ((ip >> 24) & 0xFF);
  ip_str += ".";
  ip_str += std::to_string ((ip >> 16) & 0xFF);
  ip_str += ".";
  ip_str += std::to_string ((ip >> 8) & 0xFF);
  ip_str += ".";
  ip_str += std::to_string (ip & 0xFF);
  return ip_str;
}

static protocols
get_protocol (std::uint8_t protocol)
{
  return static_cast<protocols> (protocol);
}

static const std::uint32_t
string_to_ip (const std::string &ip_str)
{
  std::uint32_t ip = 0;
  std::size_t pos = 0;
  std::size_t prev = 0;
  for (std::size_t i = 0; i < 4; i++)
    {
      pos = ip_str.find (".", prev);
      if (pos == std::string::npos)
        {
          pos = ip_str.length ();
        }
      std::uint32_t octet = std::stoi (ip_str.substr (prev, pos - prev));
      ip |= octet << (24 - (i * 8));
      prev = pos + 1;
    }
  return ip;
}

static const std::uint32_t
network_to_host (std::uint32_t ip, std::uint32_t mask)
{
  return ip & mask;
}

static const std::uint32_t
get_localhost_ip (std::string __interface)
{
  struct ifaddrs *ifaddr;
  auto ret = getifaddrs (&ifaddr);
  if (ret == -1)
    {
      return 0;
    }
  for (auto ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
    {
      if (ifa->ifa_addr->sa_family == AF_INET)
        {
          auto addr = reinterpret_cast<struct sockaddr_in *> (ifa->ifa_addr);
          if (ifa->ifa_name == __interface)
            {
              freeifaddrs (ifaddr);
              return addr->sin_addr.s_addr;
            }
        }
    }
  return 0x00;
}
}
#endif