#ifndef PACKAGE_MULTICAST_UDP_SOCKET_LIBRARY_H
#define PACKAGE_MULTICAST_UDP_SOCKET_LIBRARY_H
//=========== Linux ==============//
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h> //struct ifreq
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <linux/net_tstamp.h> //timestamp interface
#include <linux/sockios.h>    //SIOCSHWTSTAMP
#include <netdb.h>
//============ C++ ================//
#include <system_error>
#include <string>
#include <cstring>
#include <iostream>
#include <functional>
#include <optional>
#include <memory>               // added for factory unique_ptr

#include "packet_types.h" // tipos
#include "tpacket_ring.h" // encapsula ring + mmap

namespace io::network {

// erros locais usados pelo construtor
enum class ErrorCode {
    bind_interface_error = 0x01,
};

static const char* BIND_ERROR_DESC = "Error to bind to interface: %s\n";

class multicast_udp_receiver {
public:
    // Factory template: allows injecting Ring/Socket test doubles or using defaults.
    // Usage:
    //   auto cfg = network_config{"enp4s0", "239.0.0.1", 12345, /*group*/0, /*loopback*/false};
    //   auto r = multicast_udp_receiver::make(cfg);
    template <typename Ring = tpacket_ring, typename Socket = _socket>
    static std::unique_ptr<multicast_udp_receiver> make(network_config cfg) {
        auto ptr = std::unique_ptr<multicast_udp_receiver>(new multicast_udp_receiver());

        // fill config early: init_socket needs interface for HW timestamp setup
        ptr->_M_config = cfg;
        if (!ptr->_M_config.address.empty() && ptr->_M_config.group == 0) {
            auto bip = ptr->get_binary_ip(ptr->_M_config.address);
            if (!bip.has_value()) {
                throw std::system_error(std::make_error_code(std::errc::invalid_argument));
            }
            ptr->_M_config.group = bip.value();
        }

        // create/initialize socket (Socket type must provide default constructible compatible _socket)
        ptr->_M_sock = Socket();
        auto ec = ptr->init_socket();
        if (ec) throw std::system_error(ec);

        // configure and create ring
        ptr->_M_ring = Ring();
        ptr->_M_ring.configure_defaults();
        if (!ptr->_M_ring.create(ptr->_M_sock.fd)) {
            throw std::system_error(std::make_error_code(std::errc::io_error));
        }

        // prepare polling
        ptr->config_poll();

        // bind to interface
        if (!ptr->bind_to_interface(ptr->_M_config.interface)) {
            ptr->_M_ring.destroy(ptr->_M_sock.fd);
            char msg[500];
            sprintf(msg, BIND_ERROR_DESC, ptr->_M_config.interface.c_str());
            throw std::system_error(static_cast<int>(ErrorCode::bind_interface_error),
                                    std::generic_category(), msg);
        }

        return ptr;
    }

    // Synchronous read that dispatches parsed packets through the provided callback.
    // timeout_ms: -1 = wait indefinitely, 0 = non-blocking poll, >0 = milliseconds
    // Returns number of packets delivered to the callback (0 = timeout / no packet).
    int read_packtes(int timeout_ms, const std::function<void(const udp_packet &)> &callback) {
        int rc = poll(&_M_pfd, 1, timeout_ms);
        if (rc < 0) return -1;
        if (rc == 0) return 0;

        while (true) {
            block_desc *pbd = _M_ring.current_block();
            if (!pbd) return 0;
            if ((pbd->h1.block_status & TP_STATUS_USER) == 0) {
                int rc2 = poll(&_M_pfd, 1, timeout_ms);
                if (rc2 <= 0) return 0;
                continue;
            }

            int delivered = 0;
            auto num_pkts = pbd->h1.num_pkts;
            auto ppd = (tpacket3_hdr *) ((uint8_t *) pbd + pbd->h1.offset_to_first_pkt);

            for (unsigned int i = 0; i < num_pkts; ++i) {
                udp_packet pkt;
                if (parse_udp_packet(ppd, pkt)) {
                    callback(pkt);
                    ++delivered;
                }
                ppd = (tpacket3_hdr *) ((uint8_t *) ppd + ppd->tp_next_offset);
            }

            _M_ring.mark_block_kernel(pbd);
            _M_ring.advance();

            if (delivered > 0) return delivered;
            // otherwise loop and wait for next block
        }
    }

    ~multicast_udp_receiver() {
        teardown_socket();
    }

private:
    // make ctor private to force factory usage
    multicast_udp_receiver() = default;

    // get binary IPv4 in network byte order; std::nullopt on error
    std::optional<std::uint32_t> get_binary_ip(const std::string& __ipv4) {
        in_addr addr;
        if (inet_pton(AF_INET, __ipv4.c_str(), &addr) != 1) {
            return std::nullopt;
        }
        return static_cast<std::uint32_t>(addr.s_addr); // network byte order
    }

    int get_inteface_index(const std::string& __interface) {
        struct ifreq s_ifr;
        memset(&s_ifr, 0, sizeof(s_ifr));
        strncpy(s_ifr.ifr_name, __interface.c_str(), IFNAMSIZ - 1);
        if (ioctl(_M_sock.fd, SIOCGIFINDEX, &s_ifr) < 0) {
            return -1;
        }
        return s_ifr.ifr_ifindex;
    }

    bool bind_to_interface(const std::string &__interface) {
        struct ifreq s_ifr;
        memset(&s_ifr, 0, sizeof(s_ifr));
        strncpy(s_ifr.ifr_name, __interface.c_str(), IFNAMSIZ - 1);
        if (ioctl(_M_sock.fd, SIOCGIFINDEX, &s_ifr) < 0) {
            return false;
        }

        _M_sock.addr.sll_family = AF_PACKET;
        _M_sock.addr.sll_protocol = htons(ETH_P_IP);
        _M_sock.addr.sll_ifindex = s_ifr.ifr_ifindex; // index of interface
        _M_sock.addr.sll_pkttype = PACKET_MULTICAST;

        if (bind(_M_sock.fd, (struct sockaddr *) &(_M_sock.addr), sizeof(struct sockaddr_ll))) {
            return false;
        }
        return true;
    }

    bool join_to_group(const std::string __interface, const std::string __ipv4, std::uint16_t __port) {
        _M_config.interface = __interface;
        _M_config.port = __port;
        auto index = get_inteface_index(__interface);
        auto bip_opt = get_binary_ip(__ipv4);
        if (!bip_opt.has_value() || index == -1) return false;
        _M_config.group = bip_opt.value();
        _M_config.address = __ipv4;
        return join_to_group(static_cast<uint32_t>(index), ntohl(_M_config.group));
    }

    bool leave_group(const std::string __interface, const std::string __ipv4) {
        auto index = get_inteface_index(__interface);
        auto bip_opt = get_binary_ip(__ipv4);
        if (!bip_opt.has_value() || index == -1) return false;
        return leave_group(static_cast<uint32_t>(index), ntohl(bip_opt.value()));
    }

    void ipv4MulticastToMac(uint32_t ipv4Multicast, unsigned char macAddress[6]) {
        macAddress[0] = 0x01;
        macAddress[1] = 0x00;
        macAddress[2] = 0x5E;
        uint32_t macSuffix = (ipv4Multicast & 0x007FFFFF) | 0x00800000;
        macAddress[3] = (macSuffix >> 16) & 0xFF;
        macAddress[4] = (macSuffix >> 8) & 0xFF;
        macAddress[5] = macSuffix & 0xFF;
    }

    bool join_to_group(uint32_t __interface_index, uint32_t __ipv4) {
        packet_mreq req;
        memset(&req, 0, sizeof(req));
        req.mr_ifindex = __interface_index;
        req.mr_type = PACKET_MR_MULTICAST;
        req.mr_alen = 0x06;
        ipv4MulticastToMac((__ipv4), req.mr_address);
        if (setsockopt(_M_sock.fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &req, sizeof(packet_mreq))) {
            return false;
        }
        return true;
    }

    bool leave_group(uint32_t __interface_index, short __ipv4) {
        packet_mreq req;
        memset(&req, 0, sizeof(req));
        req.mr_ifindex = __interface_index;
        req.mr_type = PACKET_MR_MULTICAST;
        req.mr_alen = 0x06;
        ipv4MulticastToMac(__ipv4, req.mr_address);
        if (setsockopt(_M_sock.fd, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &req, sizeof(packet_mreq))) {
            return false;
        }
        return true;
    }

    std::error_code init_socket() {
        _M_sock.fd = ::socket(PF_PACKET, SOCK_RAW, htons(0x00));
        if (_M_sock.fd == -1) {
            return std::make_error_code(std::errc::bad_file_descriptor);
        }
        if (setsockopt(_M_sock.fd, SOL_PACKET, PACKET_VERSION, &(_M_sock.packet_version),
                       sizeof(_M_sock.packet_version))) {
            return std::make_error_code(std::errc::invalid_argument);
        }
        auto ec = configure_hardware_timestamp();
        if (ec) {
            return ec;
        }
        return std::error_code();
    }

    std::error_code configure_hardware_timestamp() {
        if (_M_config.interface.empty()) {
            return std::make_error_code(std::errc::invalid_argument);
        }

        ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, _M_config.interface.c_str(), IFNAMSIZ - 1);

        hwtstamp_config hw_cfg;
        memset(&hw_cfg, 0, sizeof(hw_cfg));
        hw_cfg.flags = 0;
        hw_cfg.tx_type = HWTSTAMP_TX_OFF;
        hw_cfg.rx_filter = HWTSTAMP_FILTER_ALL;
        ifr.ifr_data = reinterpret_cast<char *>(&hw_cfg);

        if (ioctl(_M_sock.fd, SIOCSHWTSTAMP, &ifr) < 0) {
            return std::error_code(errno, std::system_category());
        }

        int packet_timestamp_type = SOF_TIMESTAMPING_RAW_HARDWARE;
        if (setsockopt(_M_sock.fd, SOL_PACKET, PACKET_TIMESTAMP, &packet_timestamp_type,
                       sizeof(packet_timestamp_type)) < 0) {
            return std::error_code(errno, std::system_category());
        }

        return std::error_code();
    }

    static uint64_t get_packet_timestamp_ns(const tpacket3_hdr *ppd) {
        constexpr uint64_t NSEC_PER_SEC = 1000000000ULL;
        return static_cast<uint64_t>(ppd->tp_sec) * NSEC_PER_SEC +
               static_cast<uint64_t>(ppd->tp_nsec);
    }

    void config_poll() {
        memset(&_M_pfd, 0, sizeof(_M_pfd));
        _M_pfd.fd = _M_sock.fd;
        _M_pfd.events = POLLIN | POLLERR;
        _M_pfd.revents = 0;
    }

    void update_statistics() {
        tpacket_stats_v3 stats;
        socklen_t len = sizeof(stats);
        getsockopt(_M_sock.fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
        printf("\nReceived %u packets,  %u dropped, freeze_q_cnt: %u\n",
               stats.tp_packets, stats.tp_drops, stats.tp_freeze_q_cnt);
    }

    // parse packet and fill udp_packet; return true if packet passes filters and was parsed
    bool parse_udp_packet(tpacket3_hdr *ppd, udp_packet &packet_out) {
        constexpr int UDP_PROTOCOL = 17;

        sockaddr_ll *src_addr = (sockaddr_ll *) ((uint8_t *) ppd + sizeof(tpacket3_hdr));
        auto eth = (eth_hdr *) ((uint8_t *) ppd + ppd->tp_mac);

        // IP header start
        auto ip = (ip_hdr *) ((uint8_t *) eth + ETH_HLEN);
        std::size_t ip_header_len = (ip->ihl & 0x0F) * 4;
        if (ip_header_len < 20) return false;

        std::size_t ip_total_len = ntohs(ip->tot_len);
        if (ip_total_len < ip_header_len) return false;

        auto udp = (udp_hdr *) ((uint8_t *) ip + ip_header_len);
        std::size_t udp_len = ntohs(udp->len);
        if (udp_len < sizeof(udp_hdr)) return false;

        std::size_t ip_payload_len = ip_total_len - ip_header_len;
        if (udp_len > ip_payload_len) return false;

        char *payload = (char *) ((uint8_t *) udp + sizeof(udp_hdr));
        std::size_t payload_len = udp_len - sizeof(udp_hdr);

        /*
        std::cout << "Packet received: src=" << inet_ntoa(*(in_addr *) &ip->saddr)
                  << ":" << ntohs(udp->source) << " -> dst=" << inet_ntoa(*(in_addr *) &ip->daddr)
                  << ":" << ntohs(udp->dest) << " len=" << payload_len
                  << " type=" << (src_addr->sll_pkttype == PACKET_OUTGOING ? "OUTGOING" : "MULTICAST")
                  << std::endl;

        if (((src_addr->sll_pkttype == PACKET_OUTGOING && !_M_config.loopback) &&
             src_addr->sll_pkttype != PACKET_MULTICAST) ||
            !(ntohs(eth->h_proto) == ETH_P_IP &&
              ip->protocol == UDP_PROTOCOL &&
              ip->daddr == _M_config.group &&
              ntohs(udp->dest) == _M_config.port)) {
            return false;
        }
       */ 
        packet_out.sock_address = src_addr;
        packet_out.eth = eth;
        packet_out.ip = ip;
        packet_out.udp = udp;
        packet_out.data = payload;
        packet_out.data_len = payload_len;
        packet_out.timestamp_ns = get_packet_timestamp_ns(ppd);
        return true;
    }

    void flush_block(block_desc *pbd) {
        _M_ring.mark_block_kernel(pbd);
    }

    void teardown_socket() {
        _M_ring.destroy(_M_sock.fd);
        if (_M_sock.fd != -1) close(_M_sock.fd);
        _M_sock.fd = -1;
    }

    tpacket_ring _M_ring;
    _socket _M_sock;
    pollfd _M_pfd;

    // replaced loose members with a single config struct
    network_config _M_config;

};

} // namespace io::network

#endif //PACKAGE_MULTICAST_UDP_SOCKET_LIBRARY_H
