#pragma once
#include <cstdint>
#include <sys/uio.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string>               // added for network_config
#include <sys/types.h>

namespace io::network {

struct udp_hdr {
    std::uint16_t source;
    std::uint16_t dest;
    std::uint16_t len;
    std::uint16_t check;
};

struct ip_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    std::uint8_t    ihl:4,
                    version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    std::uint8_t    version:4,
                    ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
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

struct eth_hdr {
    static constexpr std::uint16_t eth_len = 6;
    unsigned char h_dest[eth_len];
    unsigned char h_source[eth_len];
    std::uint16_t h_proto;
};

struct block_desc {
    uint32_t version;
    uint32_t offset_to_priv;
    tpacket_hdr_v1 h1;
};

struct ring {
    iovec *rd;
    uint8_t *map;
    tpacket_req3 req;
};

struct _socket {
    int packet_version = TPACKET_V3;
    int fd;
    struct sockaddr_ll addr;
};

struct udp_packet {
    sockaddr_ll *sock_address;
    eth_hdr* eth;
    ip_hdr* ip;
    udp_hdr* udp;
    char *data;
    std::size_t data_len;     // novo: comprimento do payload UDP
    uint64_t timestamp_ns;
};

struct network_config {
    std::string interface;
    std::string address;
    std::uint16_t port = 0;   // host order
    std::uint32_t group = 0;  // network order (as returned by inet_pton)
    bool loopback = false;
};

} // namespace io::network