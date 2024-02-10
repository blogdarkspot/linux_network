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

    enum class TcpStatus {
        LISTEN = 0x00,
        SYN_SENT = 0x01,
        SYN_RECEIVED = 0x02,
        ESTABLISHED = 0x03,
        FIN_WAIT_1 = 0x04,
        FIN_WAIT_2 = 0x05,
        CLOSE_WAIT = 0x06,
        CLOSING = 0x07,
        LAST_ACK = 0x08,
        TIME_WAIT = 0x09,
        CLOSED = 0x0A
    }; 

    enum class TcpFlag : std::uint8_t
    {
        FIN = 0x01,
        SYN = 0x02,
        RST = 0x04,
        PSH = 0x08,
        ACK = 0x10,
        URG = 0x20,
        ECE = 0x40,
        CWR = 0x80
    };

    enum class TcpOption : std::uint8_t
    {
        NOP = 0x01,
        MSS = 0x02,
        WSCALE = 0x03,
        SACK_PERM = 0x04,
        SACK = 0x05,
        TIMESTAMP = 0x08
    };

    enum class TcpOptionLength : std::uint8_t
    {
        MSS = 0x04,
        WSCALE = 0x03,
        SACK_PERM = 0x02,
        SACK = 0x02,
        TIMESTAMP = 0x10
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

        using checksum_t = std::uint16_t;

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
            _M_status = TcpStatus::CLOSED;
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

        //__timeout in seconds
        bool start_connection(std::uint32_t __timeout)
        {
            bool timeout = false;
            auto start = std::chrono::high_resolution_clock::now();

            do {

                send_sync();
                std::this_thread::yield();
                auto end = std::chrono::high_resolution_clock::now();
                if(std::chrono::duration_cast<std::chrono::seconds>(end - start) > __timeout)
                {
                    timeout = true;
                }
            }while(_M_status != TcpStatus::ESTABLISHED  || !timeout);
            return !timeout && _M_status == TcpStatus::ESTABLISHED;
        }

        short get_random_port()
        {
            return 4503;
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

        bool wating_for_ack(std::chrono::milliseconds __timeout)
        {
            auto start = std::chrono::high_resolution_clock::now();
            while(_M_waiting_ack)
            {
                std::this_thread::yield();
                auto end = std::chrono::high_resolution_clock::now();
                if(std::chrono::duration_cast<std::chrono::milliseconds>(end - start) > __timeout)
                {
                    return false;
                }
            }
            return true;
        }

        

        inline void set_tcpheader(char* __buffer, size_t __len, std::uint8_t __flag) 
        {
            //CTL=ACK
            else if (!(std::uint8_t(TcpFlag::FIN | TcpFlag::ACK) ^ __flag))
            {
                _M_info.tbc.seq_number += 1;
                _M_info.tbc.ack += 1;
            }
            else if (!(std::uint8_t(TcpFlag::RST | TcpFlag::ACK) ^ __flag))
            {
                _M_info.tbc.seq_number += 1;
                _M_info.tbc.ack += 1;
            } else if (!(std::uint8_t(TcpFlag::SYN | TcpFlag::ACK) ^ __flag))
            {
                _M_info.tbc.ack += 1;
            } 
            else if(!(std::uint8_t(TcpFlag::ACK) ^ __flag))
            {
                _M_info.tbc.ack += 1;
            }
            else if(!(std::uint8_t(TcpFlag::SYN) ^ __flag))
            {
                _M_info.tbc.seq_number = rand();
            } else if (!(std::uint8_t(TcpFlag::FIN) ^ __flag))
            {
                _M_info.tbc.seq_number += 1;
            }  else if (!(std::uint8_t(TcpFlag::RST) ^ __flag))
            {
                _M_info.tbc.seq_number += 1;
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

        void send_sync()
        {
            size_t len = 0x00;
            char* buffer = aquire_buffer(len);
            set_ipv4header(buffer, len);
            set_tcpheader(buffer, len, std::uint8_t(TcpFlag::SYN));
            send(len);
        }

        void send_data(std::size_t __len)
        {
            size_t len = 0x00;
            char* buffer = aquire_buffer(len);
            set_ipv4header(buffer, __len);
            set_tcpheader(buffer, __len, std::uint8_t(TcpFlag::ACK));
            send(len);
        }

        void set_checksum(char* __buffer, size_t __len)
        {
            ip_hdr* ip = (ip_hdr*)__buffer;
            tcp_hdr* tcp = (tcp_hdr*)__buffer + sizeof(ip_hdr);
            ip->check = 0x00;
            ip->check = checksum((unsigned short*)__buffer, sizeof(ip_hdr));
            tcp->check = 0x00;
            tcp->check = checksum((unsigned short*)tcp, __len);
        }
        checksum_t checksum(unsigned short* __buffer, size_t __len)
        {
            unsigned long sum = 0;
            while(__len > 1)
            {
                sum += *__buffer++;
                __len -= 2;
            }
            if(__len > 0)
            {
                sum += *(__buffer++);
            }
            while(sum >> 16)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            sum = ~sum;
            return (checksum_t)sum;
        }

        void send_ack()
        {
            size_t len = 0x00;
            char* buffer = aquire_buffer(len);
            set_ipv4header(buffer, len);
            set_tcpheader(buffer, len, std::uint8_t(TcpFlag::ACK));
            send(len);
        }

        void send_close()
        {
            size_t len = 0x00;
            char* buffer = aquire_buffer(len);
            set_tcpheader(buffer, len, std::uint8_t(TcpFlag::FIN));
            send(len);
        }

        void send_close_ack()
        {
            size_t len = 0x00;
            char* buffer = aquire_buffer(len);
            set_tcpheader(buffer, len, std::uint8_t(TcpFlag::FIN | TcpFlag::ACK));
            do {
                send(len);
            }while(wating_for_ack(std::chrono::milliseconds(1000)));
        }

        void decode_tcp_flags(std::uint8_t __flags)
        {
            if(__flags & std::uint8_t(TcpFlag::SYN))
            {
                _M_info.current_stage = tcp_stage::SyncSent;
            }
            if(__flags & std::uint8_t(TcpFlag::ACK))
            {
                _M_info.current_stage = tcp_stage::Established;
            }
            if(__flags & std::uint8_t(TcpFlag::FIN))
            {
                _M_info.current_stage = tcp_stage::Finish;
            }
        }

        void disconnect_tcp()
        {
            send_close();
            send_close_ack();
        };

        void decode_tcp_header(tcp_hdr* __header)
        {
            _M_info.dst_port = __header->destination_port;
            _M_info.src_port = __header->source_port;
            decode_tcp_flags(__header->flags);
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
            if(__header->protocol == 0x06 && __header->saddr == _M_info.src && __header->daddr == _M_info.dst)
            {
                return (tcp_hdr*)__header + __header->ihl;
            }
            else
            {
                return nullptr;
            }
        }

        bool get_ip_data(ip_hdr* __header, char** __data, size_t* __len)
        {
            if(__header == nullptr)
            {
                return false;
            }
            if(__header->protocol == 0x06 && __header->src == _M_info.src && __header->dst == _M_info.dst)
            {
                *__data = (char*)__header + __header->ihl;
                *__len = __header->tot_len - __header->ihl;
                return true;
            }
            return false;
        }

        void decode_tcp_packet_header(tcp_hdr* __packet_tcp)
        {
            if(__packet_tcp == nullptr)
            {
                return;
            }
            decode_tcp_header(__packet_tcp);
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
        bool _M_waiting_ack;
        std::uint32_t _M_max_retries;
        TcpStatus _M_status;
    };
};
#endif
