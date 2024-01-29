#include "socket_raw.hpp"

//=========== Linux ==============//
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

namespace io::network
{

tcp_client::tcp_client (std::string __interface, std::string __address,
                        short __port)
{
  /*
  init_socket();
  auto ret = init_write_socket();
  ret = init_read_socket();
  v3_fill();
  setup_ring_buffer();
  create_mmap();
  config_poll();
  _M_interface = __interface;
  _M_address = __address;
  _M_port = __port;
  if (!bind_to_interface(_M_interface))
  {
          char msg[500];
          sprintf(msg, BIND_ERROR_DESC, _M_interface.c_str());
          throw
  std::system_error(static_cast<int>(ErrorCode::bind_interface_error),
  std::generic_category(), msg);
  }
  */
}

std::error_code
tcp_client::init_write_socket ()
{
  auto ret = init_socket (_M_write);
  if (ret)
    {
      return ret;
    }
  v3_fill (_M_write);
}

int
tcp_client::init_read_socket ()
{
  return 1;
}

void
tcp_client::connect ()
{
  _M_is_running = true;
  _M_thread.reset (new std::thread ([&] () { read_async (); }));
}

void
tcp_client::disconnect ()
{
  _M_is_running = false;
  teardown_socket ();
  if (_M_thread->joinable ())
    {
      _M_thread->join ();
    }
}

bool
tcp_client::bind_to_interface (const std::string &__interface)
{
  struct ifreq s_ifr;
  strcpy (s_ifr.ifr_ifrn.ifrn_name, __interface.c_str ());
  ioctl (_M_sock.fd, SIOCGIFINDEX, &s_ifr);

  _M_sock.addr.sll_family = AF_PACKET;
  _M_sock.addr.sll_protocol = htons (ETH_P_IP);
  _M_sock.addr.sll_ifindex = s_ifr.ifr_ifru.ifru_ivalue; // index of interface
  //_M_sock.addr.sll_pkttype = PACKET_UNICAST;

  if (bind (_M_sock.fd, (struct sockaddr *)&(_M_sock.addr),
            sizeof (struct sockaddr_ll)))
    {
      return false;
    }
  return true;
}

int
tcp_client::get_binary_ip (const std::string &__ipv4)
{
  int ip;
  if (inet_pton (AF_INET, __ipv4.c_str (), &ip) <= 0)
    {
      return -1;
    }
  return ip;
}

int
tcp_client::get_inteface_index (const std::string &__interface)
{
  struct ifreq s_ifr;
  strcpy (s_ifr.ifr_ifrn.ifrn_name, __interface.c_str ());
  ioctl (_M_sock.fd, SIOCSHWTSTAMP, &s_ifr);
  if (ioctl (_M_sock.fd, SIOCGIFINDEX, &s_ifr) < 0)
    {
      return -1;
    }
  return s_ifr.ifr_ifru.ifru_ivalue;
}

std::error_code
tcp_client::init_socket (_socket &__socket)
{
  __socket.fd = ::socket (PF_PACKET, SOCK_RAW, htons (0x00));
  if (__socket.fd == -1)
    {
      return std::make_error_code (std::errc::bad_file_descriptor);
    }
  if (setsockopt (__socket.fd, SOL_PACKET, PACKET_VERSION,
                  &(__socket.packet_version),
                  sizeof (__socket.packet_version)))
    {
      return std::make_error_code (std::errc::invalid_argument);
    }
  auto err = enable_timestamp (__socket);
  return err;
}

std::error_code
tcp_client::enable_timestamp (const _socket &__socket) const
{
  int req = SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE
            | SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE
            | SOF_TIMESTAMPING_RAW_HARDWARE;
  if (setsockopt (__socket.fd, SOL_PACKET, SO_TIMESTAMPING, (void *)&req,
                  sizeof (req)))
    {
      return std::make_error_code (std::errc::invalid_argument);
    }
  return std::error_code ();
}

bool
tcp_client::setup_ring_buffer (_socket &__socket, int __type)
{
  memset (&__socket.buffer.req, 0, sizeof (__socket.buffer.req));
  __socket.buffer.req.tp_retire_blk_tov = 64;
  __socket.buffer.req.tp_sizeof_priv = 0;
  __socket.buffer.req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
  __socket.buffer.req.tp_block_size = getpagesize () << 2;
  __socket.buffer.req.tp_frame_size = TPACKET_ALIGNMENT << 7;
  __socket.buffer.req.tp_block_nr = 1 << 10;
  __socket.buffer.req.tp_frame_nr = __socket.buffer.req.tp_block_size
                                    / __socket.buffer.req.tp_frame_size
                                    * __socket.buffer.req.tp_block_nr;

  if (setsockopt (__socket.fd, SOL_PACKET, __type,
                  (void *)&(__socket.buffer.req),
                  sizeof (__socket.buffer.req)))
    {
      return false;
    }
  return true;
}

void
tcp_client::v3_fill (_socket &__socket)
{
}

void
tcp_client::create_mmap (_socket &__socket)
{
  __socket.buffer.map = static_cast<uint8_t *> (mmap (
      NULL,
      __socket.buffer.req.tp_block_size * __socket.buffer.req.tp_block_nr,
      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, __socket.fd, 0));
  if (__socket.buffer.map == MAP_FAILED)
    {
      return;
    }
  __socket.buffer.rd = static_cast<iovec *> (
      malloc (__socket.buffer.req.tp_block_nr * sizeof (*__socket.buffer.rd)));
  for (auto i = 0; i < __socket.buffer.req.tp_block_nr; ++i)
    {
      __socket.buffer.rd[i].iov_base
          = __socket.buffer.map + (i * __socket.buffer.req.tp_block_size);
      __socket.buffer.rd[i].iov_len = __socket.buffer.req.tp_block_size;
    }
}

void
tcp_client::config_poll (_socket &__socket)
{
  memset (&_M_pfd, 0, sizeof (_M_pfd));
  _M_pfd.fd = _M_sock.fd;
  _M_pfd.events = POLLIN | POLLERR;
  _M_pfd.revents = 0;
}

void
tcp_client::update_statistics (_socket &__socket)
{
  int err;
  tpacket_stats_v3 stats;
  socklen_t len = sizeof (stats);
  err = getsockopt (_M_sock.fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
  printf ("\nReceived %u packets,  %u dropped, freeze_q_cnt: %u\n",
          stats.tp_packets, stats.tp_drops, stats.tp_freeze_q_cnt);
}

void
tcp_client::read_async ()
{
  block_desc *pbd;
  int err;
  unsigned int block_num = 0;

  while (_M_is_running)
    {
      pbd = (struct block_desc *)_M_ring.rd[block_num].iov_base;
      if ((pbd->h1.block_status & TP_STATUS_USER) == 0x00)
        {
          poll (&_M_pfd, 1, -1);
          continue;
        }
      walk_block (pbd);
      flush_block (pbd);
      block_num = (block_num + 1) % _M_ring.req.tp_block_nr;
    }
}

void
tcp_client::walk_block (block_desc *pbd)
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
tcp_client::filter_and_dispatch_packet (tpacket3_hdr *ppd)
{
  constexpr int UDP_PROTOCOL = 17;
  clock_gettime (CLOCK_MONOTONIC, &_timer);
  sockaddr_ll *src_addr
      = (sockaddr_ll *)((uint8_t *)ppd + sizeof (tpacket3_hdr));
  auto eth = (eth_hdr *)((uint8_t *)ppd + ppd->tp_mac);
  auto ip = (ip_hdr *)((uint8_t *)eth + ETH_HLEN);

  /*
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
tcp_client::flush_block (block_desc *pbd)
{
  pbd->h1.block_status = TP_STATUS_KERNEL;
}

void
tcp_client::teardown_socket ()
{
  munmap (_M_ring.map, _M_ring.req.tp_block_size * _M_ring.req.tp_block_nr);
  free (_M_ring.rd);
  close (_M_sock.fd);
}
};
