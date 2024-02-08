#ifndef __TCP_CLIENT__
#define __TCP_CLIENT__

#include "protocols.hpp"
#include "socket_raw.hpp"
#include <set>
#include <string>
#include <functional>
#include <memory>
#include <exception>

#include <cstdlib>

namespace io::network
{
    enum class tcp_stage
    {
        Closed = 1,
        SyncSent = 1 << 2,
        Established = 1 << 3,
        Closing = 1 << 4,
        Finish = 1 << 5 
    };

    struct network_exception : std::exception 
    {
        network_exception(const std::string& __msg) : msg(__msg) {}

    virtual const char*
    what() const _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_NOTHROW override {
        return msg.c_str();
    }
        private:
        std::string msg;
    };

    struct tbc_t
    {
        std::uint32_t seq_number = rand();
        std::uint32_t ack = 0x00;
    };

    struct tcp_info
    {
        tcp_stage current_stage;
        std::uint32_t src;
        std::uint32_t dst;
        short dst_port;
        short src_port;
        tbc_t tbc;
    };

    class tcp_client
    {
        public:
        tcp_client(const std::string __interface, 
                     std::function<void(const char*, size_t)> __output) : _M_interface(__interface),
                     _M_output(__output)
        {
            _M_socket = std::make_unique<socket_raw>([&](auto buffer, auto size) { received_buffer(buffer, size);});
            int fd = 0x00;
            struct ifreq ifr;
            fd = socket(AF_INET, SOCK_DGRAM, 0x00); 

            ifr.ifr_addr.sa_family = AF_INET;
            strncpy(ifr.ifr_name, __interface.c_str(), __interface.size());
            ioctl(fd, SIOCGIFADDR, &ifr);
            close(fd);
            //a ideia aqui é pegar o endereçco local da interface que vamos usar como porta de saída.
            _M_info.src = (std::uint32_t)((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
        }

        bool connect(const std::uint32_t __address, 
                    short __port)
        {
            auto ret = _M_socket->init_write_socket(_M_interface);
            if(ret)
            {
                throw network_exception(ret.message());
            }
            ret = _M_socket->init_read_socket_async(_M_interface);
            if(ret)
            {
                throw  network_exception(ret.message());
            }
            _M_info.src = __address;

            return start_connection();
        }

        short get_random_port()
        {
            return 450003;
        }

        bool disconnect()
        {
            return false;
        }

        char* aquire_buffer(size_t& __len)
        {
            char* buffer = _M_socket->aquire_buffer(__len);
            size_t offset = sizeof(ip_hdr) + sizeof(tcp_hdr);
            char* payload = buffer + offset;
            __len -= offset;
            return  payload;
        }

        bool send(size_t __len)
        {
            char* buffer = _M_socket->aquire_buffer(__len);
            set_ipv4header(buffer, __len);
            set_tcpheader(buffer, __len);
            _M_socket->send(__len);
            return true;
        }

        private:

        inline void set_ipv4header(char* __buffer, size_t __len) const
        {
            size_t offset = sizeof(ip_hdr) + sizeof(tcp_hdr);
            ip_hdr* ip = (ip_hdr *)__buffer - offset;
            ip->ihl = 0x05; // ip header size 
            ip->version = 0x04; // ipv4 version
            ip->frag_off = 0x02; //no frag
            ip->ttl = 64; //time to live
            ip->protocol = 0x06; // TCP Code
            ip->tot_len = __len + offset; // will be set later
        }

        inline void set_tcpheader(char* __buffer, size_t __len, std::uint8_t __flag) 
        {
            //CTL=ACK
            if(!(std::uint8_t(TcpFlag::ACK) ^ __flag))
            {
                _M_info.tbc.ack += 1;
            }
            //CTL=SYN,ACK 
            if(std::uint8_t(TcpFlag::SYN) ^ __flag))
            {
                _M_info.tbc.f
            }

            _M_info.tbc.seq_number += 1;
            size_t offset = sizeof(tcp_hdr);
            tcp_hdr* tcp = (tcp_hdr*)__buffer - offset;
            tcp->source_port = _M_info.src_port;
            tcp->destination_port = _M_info.dst_port;
            tcp->ack_number = _M_info.tbc.ack;
            tcp->seq_number = _M_info.tbc.seq_number;
            tcp->flags = __flag;

        }

        bool start_connection()
        {
            return false;
        }

        void received_buffer(const char* __buffer, size_t __len)
        {
            eth_hdr* eth = (eth_hdr *) __buffer;
            ip_hdr* ip = (ip_hdr *) eth + sizeof(eth_hdr);
            process_tcp_packet(get_tcp_packet(ip));
        }

        tcp_hdr* get_tcp_packet(ip_hdr* __header)
        {
            if(__header == nullptr)
            {
                return nullptr;
            }
            return (tcp_hdr*)__header + __header->ihl;
        }

        void process_tcp_packet(tcp_hdr* __packet_tcp)
        {
                if(__packet_tcp == nullptr)
                {
                    return;
                }
        }

        std::string _M_interface;
        std::unique_ptr<socket_raw> _M_socket;
        tcp_info _M_info;
        std::function<void(const char*, size_t)> _M_output;
        std::set<short> _M_busy_ports;
    };
};
#endif