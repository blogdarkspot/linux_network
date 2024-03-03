#ifndef __SOCKET_RAW__
#define __SOCKET_RAW__

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/net_tstamp.h> //timestamp interface
#include <net/if.h>           //struct ifreq
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <system_error>
#include <unistd.h>
#include <cstring>
#include <linux/if_packet.h>
#include <poll.h>
#include <sys/uio.h>
#include <sys/capability.h>
//============ C++ ================//
#include <cstdint>
#include <memory>
#include <string>
#include <system_error>
#include <thread>
#include <functional>

#ifndef SO_TIMESTAMPING
#define SO_TIMESTAMPING 37
#define SCM_TIMESTAMPING SO_TIMESTAMPING
#endif

#ifndef SO_TIMESTAMPNS
#define SO_TIMESTAMPNS 35
#endif

#ifndef SIOCGSTAMPNS
#define SIOCGSTAMPNS 0x8907
#endif

#ifndef SIOCSHWTSTAMP
#define SIOCSHWTSTAMP 0x89b0
#endif

namespace io::network
{

struct block_desc
{
  std::uint32_t version;
  std::uint32_t offset_to_priv;
  tpacket_hdr_v1 h1;
};

struct ring
{
  iovec *rd; // readerss descriptos
  std::uint8_t *map;
  tpacket_req3 req;
  size_t current_pk = 0x00;
};

struct _socket
{
  std::int32_t packet_version = TPACKET_V3; // packet version
  std::int32_t fd;                          // socket file descriptor
  struct sockaddr_ll addr; // struct com para o bind na interface e  protocolo
  pollfd pfd;
  ring buffer;
};

enum class ErrorCode
{
  bind_interface_error = 0x01,
};

static const char *BIND_ERROR_DESC = "Error to bind to interface: %s\n";

class socket_raw
{
public:
  socket_raw (std::function<void(const char*, size_t)> __output) : _M_output(__output) {
  }

  ~socket_raw () {}

  std::error_code
  init_write_socket (const std::string &__interface)
  {
    _M_write.fd = ::socket (PF_PACKET, SOCK_DGRAM, htons (0x00));
    if (_M_write.fd == -1)
      {
        return std::make_error_code (std::errc::bad_file_descriptor);
      }
    if (setsockopt (_M_write.fd, SOL_PACKET, PACKET_VERSION,
                    &(_M_write.packet_version),
                    sizeof (_M_write.packet_version)))
      {
        return std::make_error_code (std::errc::invalid_argument);
      }
    auto ret = setup_ring_buffer (_M_write, RingType::WRITE);
    if (ret)
      {
        return ret;
      }
    ret = create_mmap (_M_write);
    if (ret)
      {
        return ret;
      }
    return bind_to_interface (_M_write, __interface, 0x00);
    // auto err = enable_timestamp (_M_write);
  }

  std::error_code
  init_read_socket_async (const std::string &__interface)
  {
    _M_is_running = true;

    _M_read.fd = ::socket (PF_PACKET, SOCK_RAW, htons (AF_INET));
    if (_M_read.fd == -1)
      {
        return std::make_error_code (std::errc::bad_file_descriptor);
      }
    if (setsockopt (_M_read.fd, SOL_PACKET, PACKET_VERSION,
                    &(_M_read.packet_version),
                    sizeof (_M_read.packet_version)))
      {
        return std::make_error_code (std::errc::invalid_argument);
      }

      setup_ring_buffer (_M_read, RingType::READ);
      create_mmap(_M_read);
    _M_thread.reset (new std::thread ([&] () { read_async (); }));
    return std::error_code ();
  }

  void
  stop_read ()
  {
    _M_is_running = false;
    teardown_socket ();
    if (_M_thread->joinable ())
      {
        _M_thread->join ();
      }
  }

  void
  config (const std::string &__interface)
  {
    struct ifreq mac_data;
    strcpy (mac_data.ifr_ifrn.ifrn_name, __interface.c_str ());
    auto ret = ioctl (_M_read.fd, SIOCGIFHWADDR, (char *)&mac_data);
  }

  char *
  aquire_buffer (size_t &__len)
  {
    auto buffer = get_next_frame_to_write (_M_write.buffer,
                                           _M_write.buffer.current_pk);
    
    auto payload = buffer + (TPACKET3_HDRLEN);
    __len = _M_write.buffer.req.tp_frame_size - (TPACKET3_HDRLEN);
    return payload;
  }

  std::error_code 
  send (size_t __len)
  {
    // aqui segundo a documentação como estamos usando SOCK_DGRAM the phisycal
    // header will be write by the kernel when we pass an address to sendto or
    // sendmsg

    auto buffer = get_next_frame_to_write (_M_write.buffer,
                                           _M_write.buffer.current_pk);
    tpacket3_hdr *tx = (tpacket3_hdr *)buffer;
    tx->tp_next_offset = 0;
    tx->tp_status = TP_STATUS_SEND_REQUEST;
    tx->tp_len = __len;
    tx->tp_snaplen = __len;
    int ret = sendto (_M_write.fd, NULL, 0, 0, NULL, 0);
    if (ret == -1)
      {
        return std::error_code (errno, std::system_category ());
      }
    ++_M_write.buffer.current_pk;
    return std::error_code();
  }

  void
  send_to (sockaddr_ll &__address, size_t __len)
  {

    auto buffer = get_next_frame_to_write (_M_write.buffer,
                                           _M_write.buffer.current_pk);
    tpacket3_hdr *tx = (tpacket3_hdr *)buffer;
    tx->tp_len = __len;
    tx->tp_snaplen = __len;
    int ret = sendto (_M_write.fd, NULL, 0, 0, (sockaddr *)&__address,
                      sizeof (__address));
    if (ret == -1)
      {
        // error to send
      }
    ++_M_write.buffer.current_pk;
  }

private:
  inline
  char *
  get_next_frame_to_write (ring &__ring, int n) const
  {
    auto f0 = ((char *)__ring.rd[0].iov_base) + (n * __ring.req.tp_frame_size);
    return f0;
  }
  std::error_code
  bind_to_interface (_socket &__socket, const std::string &__interface, int __protocol = ETH_P_IP)
  {
    struct ifreq s_ifr;
    strcpy (s_ifr.ifr_ifrn.ifrn_name, __interface.c_str ());
    ioctl (__socket.fd, SIOCGIFINDEX, &s_ifr);

    __socket.addr.sll_family = AF_PACKET;
    __socket.addr.sll_protocol = htons (__protocol);
    __socket.addr.sll_ifindex
        = s_ifr.ifr_ifru.ifru_ivalue; // index of interface
    //_M_sock.addr.sll_pkttype = PACKET_UNICAST;

    if (bind (__socket.fd, (struct sockaddr *)&(__socket.addr),
              sizeof (struct sockaddr_ll)))
      {
        return std::error_code (errno, std::system_category ());
      }
    return std::error_code();
  }

  int
  get_binary_ip (const std::string &__ipv4)
  {
    int ip;
    if (inet_pton (AF_INET, __ipv4.c_str (), &ip) <= 0)
      {
        return -1;
      }
    return ip;
  }

  int
  get_inteface_index (int __fd, const std::string &__interface)
  {
    struct ifreq s_ifr;
    strcpy (s_ifr.ifr_ifrn.ifrn_name, __interface.c_str ());
    ioctl (__fd, SIOCSHWTSTAMP, &s_ifr);
    if (ioctl (__fd, SIOCGIFINDEX, &s_ifr) < 0)
      {
        return -1;
      }
    return s_ifr.ifr_ifru.ifru_ivalue;
  }

  enum class RingType : std::int32_t
  {
    READ = PACKET_RX_RING,
    WRITE = PACKET_TX_RING
  };

  /**
   * Configuração do ring buffer onde cada mensagem do socket
   * será lida ou escrita.
   * cada bloco é alocado por paginas em pontecia de 2.
   * o tamanho do bloco deve ser multiplo do tamanho do frame.
   * entao aqui vamos usar frames de 2046 já que as paginas geralmente são 4096
   * ou 8192 sendo assim podemos utilizar
   */
  std::error_code 
  setup_ring_buffer (_socket &__socket, const RingType __type)
  {
    constexpr std::uint32_t BlockSizeOder = 2;
    constexpr std::uint32_t BlocksNumber = 1 << 10;
    constexpr std::uint32_t TimeoutMicro = 64;
    constexpr std::uint32_t OffSetPriv = 0;

    memset (&__socket.buffer.req, 0x00, sizeof (__socket.buffer.req));

    __socket.buffer.req.tp_block_size = (getpagesize () << BlockSizeOder);
    __socket.buffer.req.tp_frame_size = TPACKET_ALIGNMENT << 7;
    __socket.buffer.req.tp_block_nr = BlocksNumber;
    __socket.buffer.req.tp_frame_nr = __socket.buffer.req.tp_block_size
                                      / __socket.buffer.req.tp_frame_size
                                      * __socket.buffer.req.tp_block_nr;

    if (__type == RingType::READ)
      {
        __socket.buffer.req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
        __socket.buffer.req.tp_retire_blk_tov = TimeoutMicro;
        __socket.buffer.req.tp_sizeof_priv = OffSetPriv;
      }

    if (setsockopt (
            __socket.fd, SOL_PACKET, static_cast<std::int32_t> (__type),
            (void *)&(__socket.buffer.req), sizeof (__socket.buffer.req)))
      {
        return std::error_code (errno, std::system_category ());
      }
    return std::error_code();
  }

  /**
   * Para criar o mapa usamos a função  create mmap
   * o tamanho do mapa deve ser o número de blocos
   * após isso mapeamos cada um dos blocos na estrutura
   * iovec sequencialmente a partir do inicio  do mapa alocado
   */
  std::error_code
  create_mmap (_socket &__socket)
  {
    __socket.buffer.map = static_cast<uint8_t *> (mmap (
        NULL,
        __socket.buffer.req.tp_block_size * __socket.buffer.req.tp_block_nr,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, __socket.fd, 0));
    if (__socket.buffer.map == MAP_FAILED)
      {
        return std::error_code (errno, std::system_category ());
      }
    __socket.buffer.rd = static_cast<iovec *> (malloc (
        __socket.buffer.req.tp_block_nr * sizeof (*__socket.buffer.rd)));
    for (auto i = 0; i < __socket.buffer.req.tp_block_nr; ++i)
      {
        __socket.buffer.rd[i].iov_base
            = __socket.buffer.map + (i * __socket.buffer.req.tp_block_size);
        __socket.buffer.rd[i].iov_len = __socket.buffer.req.tp_block_size;
      }
      return std::error_code();
  }

  void
  config_poll (_socket &__socket)
  {
    memset (&__socket.pfd, 0, sizeof (__socket.pfd));
    __socket.pfd.fd = __socket.fd;
    __socket.pfd.events = POLLIN | POLLERR;
    __socket.pfd.revents = 0;
  }

  void
  update_statistics (_socket &__socket)
  {
    int err;
    tpacket_stats_v3 stats;
    socklen_t len = sizeof (stats);
    err = getsockopt (__socket.fd, SOL_PACKET, PACKET_STATISTICS, &stats,
                      &len);
    printf ("\nReceived %u packets,  %u dropped, freeze_q_cnt: %u\n",
            stats.tp_packets, stats.tp_drops, stats.tp_freeze_q_cnt);
  }

  bool
  __v3_tx_kernel_ready (struct tpacket3_hdr *hdr)
  {
    return !(hdr->tp_status & (TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING));
  }

  void
  read_async ()
  {
    block_desc *pbd;
    int err;
    unsigned int block_num = 0;

    while (_M_is_running)
      {
        pbd = (struct block_desc *)_M_read.buffer.rd[block_num].iov_base;
        if ((pbd->h1.block_status & TP_STATUS_USER) == 0x00)
          {
            poll (&_M_read.pfd, 1, -1);
            continue;
          }
        walk_block (pbd);
        flush_block (pbd);
        block_num = (block_num + 1) % _M_read.buffer.req.tp_block_nr;
      }
  }

  void
  walk_block (block_desc *pbd)
  {
    auto num_pkts = pbd->h1.num_pkts;
    auto ppd = (tpacket3_hdr *)((uint8_t *)pbd + pbd->h1.offset_to_first_pkt);

    for (auto i = 0; i < num_pkts; ++i)
      {
        filter_and_dispatch_packet (ppd);
        ppd = (tpacket3_hdr *)((uint8_t *)ppd + ppd->tp_next_offset);
      }
  }

  void
  filter_and_dispatch_packet (tpacket3_hdr *ppd)
  {
    sockaddr_ll *src_addr
        = (sockaddr_ll *)((uint8_t *)ppd + sizeof (tpacket3_hdr));

 //   if(src_addr->sll_pkttype == PACKET_HOST || (src_addr->sll_pkttype == PACKET_OUTGOING && _M_loopback))
    {
        _M_output((const char*)((uint8_t *)ppd + ppd->tp_mac), (ppd->tp_len - ppd->tp_mac));
    }
    

    /*
    constexpr int UDP_PROTOCOL = 17;
    clock_gettime (CLOCK_MONOTONIC, &_timer);
    auto eth = (eth_hdr *)((uint8_t *)ppd + ppd->tp_mac);
    auto ip = (ip_hdr *)((uint8_t *)eth + ETH_HLEN);

                    if ((src_addr->sll_pkttype == PACKET_OUTGOING  &&
       !_M_loopback) && src_addr->sll_pkttype != PACKET_MULTICAST ||
                                    !(ntohs(eth->h_proto) == ETH_P_IP &&
                                            ip->protocol == UDP_PROTOCOL &&
                                            ip->daddr == _M_group &&
                                            ntohs(udp->dest) == _M_port)
                       ) {
                            return;
                    }
    */

    // packet.timestamp_ns = (uint64_t)_timer.tv_nsec;
    // packet.timestamp_ns = (uint64_t)ppd->tp_sec;
  }

  void
  flush_block (block_desc *pbd)
  {
    pbd->h1.block_status = TP_STATUS_KERNEL;
  }

  void
  teardown_socket ()
  {
    /*
munmap (_M_ring.map, _M_ring.req.tp_block_size * _M_ring.req.tp_block_nr);
free (_M_ring.rd);
close (_M_sock.fd);
*/
  }

private:
  bool _M_init = false;
  bool _M_loopback = false;
  bool _M_is_running = false;

  std::unique_ptr<std::thread> _M_thread;
  std::uint32_t _M_group;
  std::uint16_t _M_port;
  std::string _M_interface;
  std::string _M_address;
  struct timespec _timer;
  // read
  _socket _M_read;
  _socket _M_write;
  std::function<void(const char*, size_t)> _M_output;
};
}
#endif // PACKAGE_MULTICAST_UDP_SOCKET_LIBRARY_H