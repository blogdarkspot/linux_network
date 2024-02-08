#ifndef __PROTOCOLS__
#define __PROTOCOLS__

#include <cinttypes>
#include <cstring>
#include <system_error>
#include <linux/types.h>
#include <linux/if_packet.h>

namespace io::network
{
struct ip_hdr
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

struct eth_hdr
{
  static constexpr std::uint16_t eth_len
      = 6;                         /* Octets in one ethernet addr	 */
  unsigned char h_dest[eth_len];   /* destination eth addr	*/
  unsigned char h_source[eth_len]; /* source ether addr	*/
  __be16 h_proto;                  /* packet type ID field	*/
};

struct tcp_hdr
{
    std::uint16_t source_port;
    std::uint16_t destination_port;
    std::uint32_t seq_number;
    std::uint32_t ack_number;
 #if defined(__LITTLE_ENDIAN_BITFIELD)
  std::uint8_t data_offset : 4, reserved : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
  std::uint8_t reserved : 4, data_offset : 4;
#else
#error "Please fix <asm/byteorder.h>"
#endif   
    std::uint8_t flags;
    std::uint16_t window_size;
    std::uint16_t checksum;
    std::uint16_t urgent_pointer;
};

enum class TcpFlag : std::uint8_t {
  FIN = 0x01,
  SYN = 0x02,
  RST = 0x04,
  PSH = 0x08,
  ACK = 0x10,
  URG = 0x20,
};

struct ipv4_address
{
  ipv4_address () = default;
  ipv4_address (int __addr) : address (__addr) {}
  ipv4_address (const std::string &__addr) {}
  int address = 0x0F0001; // default address;
};
};
#endif