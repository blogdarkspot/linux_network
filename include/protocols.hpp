#ifndef __PROTOCOLS__
#define __PROTOCOLS__

#include <cinttypes>
#include <cstring>
#include <system_error>
#include <linux/types.h>
#include <linux/if_packet.h>

/**
  * @brief This namespace contains the network protocols
  * 
  the internet protocol is referenced in rfc791 see https://datatracker.ietf.org/doc/html/rfc791
  the tcp protocol is referenced in rfc9293 see https://datatracker.ietf.org/doc/html/rfc9293
*/
namespace io::network
{



constexpr std::uint32_t ipv4_class_a_network_mask = 0x7F000000;
constexpr std::uint32_t ipv4_class_a_address_mask = 0x00FFFFFF;
constexpr std::uint32_t ipv4_class_b_network_mask = 0x3FFF0000;
constexpr std::uint32_t ipv4_class_b_address_mask = 0x0000FFFF;
constexpr std::uint32_t ipv4_class_c_network_mask = 0xDFFFFF00;
constexpr std::uint32_t ipv4_class_c_address_mask = 0x000000FF;

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