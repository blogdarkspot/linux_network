#ifndef  __SOCKET_RAW__
#define  __SOCKET_RAW__

#include<linux/if_packet.h>
#include <poll.h>
#include <linux/uio.h>

//============ C++ ================//
#include <system_error>
#include <string>
#include <cstdint>
#include <thread>
#include <memory>



#ifndef SO_TIMESTAMPING
# define SO_TIMESTAMPING         37
# define SCM_TIMESTAMPING        SO_TIMESTAMPING
#endif

#ifndef SO_TIMESTAMPNS
# define SO_TIMESTAMPNS 35
#endif

#ifndef SIOCGSTAMPNS
# define SIOCGSTAMPNS 0x8907
#endif

#ifndef SIOCSHWTSTAMP
# define SIOCSHWTSTAMP 0x89b0
#endif

namespace io::network {

    struct ip_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        std::uint8_t    ihl:4,
                version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
        std::uint8_t    version:4,
  		                ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
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
        static constexpr std::uint16_t eth_len = 6;	/* Octets in one ethernet addr	 */
        unsigned char	h_dest[eth_len];	/* destination eth addr	*/
        unsigned char	h_source[eth_len];	/* source ether addr	*/
        __be16		h_proto;		/* packet type ID field	*/
    };
    struct block_desc {
        std::uint32_t version;
        std::uint32_t offset_to_priv;
        tpacket_hdr_v1 h1;
    };
    struct ring {
        iovec *rd; //readerss descriptos
        std::uint8_t *map;
        tpacket_req3 req;
    };
    struct _socket {
        std::int32_t packet_version = TPACKET_V3; //packet version
        std::int32_t fd; //socket file descriptor
        struct sockaddr_ll addr; //struct com para o bind na interface e  protocolo
        pollfd pfd;
	ring buffer;
    };
    
    enum class ErrorCode
    {
        bind_interface_error = 0x01,
    };

    static const char* BIND_ERROR_DESC = "Error to bind to interface: %s\n";

    struct tcp_stmachine
    {
    };

    class tcp_client {
    public:
        tcp_client (std::string __interface, std::string __address, short __port);
        void connect();
        void disconnect();
	char* aquire_buffer(std::size_t&);
	std::error_code send();
        ~tcp_client() {
        }

    private:
	std::error_code init_write_socket();
	std::error_code init_read_socket();
	std::error_code init_socket(_socket&);
	std::error_code enable_timestamp(const _socket&) const;
        bool bind_to_interface(const std::string &__interface);
        int get_binary_ip(const std::string& __ipv4);
        int get_inteface_index(const std::string& __interface);
	bool setup_ring_buffer(_socket&, int);
	void v3_fill(_socket&);
	void create_mmap(_socket&);
	void config_poll(_socket&);
	void update_statistics(_socket&);
	void read_async();
	void walk_block(block_desc *pbd);
	void filter_and_dispatch_packet(tpacket3_hdr *ppd);
        void flush_block(block_desc *pbd);
        void teardown_socket();

        bool _M_init = false;
        bool _M_loopback = false;
        bool _M_is_running = false;

        std::unique_ptr<std::thread> _M_thread;
        std::uint32_t _M_group;
        std::uint16_t _M_port;
        std::string _M_interface;
        std::string _M_address;
        struct timespec _timer;
	tcp_stmachine _M_tcp_stmachine;
	//read
	_socket _M_read;
	_socket _M_write;
    };
}
#endif //PACKAGE_MULTICAST_UDP_SOCKET_LIBRARY_H
