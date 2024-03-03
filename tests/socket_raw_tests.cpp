#include <gtest/gtest.h>
#include <capabilities.hpp>
#include <socket_raw.hpp>
#include <ipv4.hpp>
#include <memory>



class SocketRawTests : public ::testing::Test
{
    protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }

    std::unique_ptr<io::network::socket_raw> socket;
};

TEST(CapabilitiesTests, EnableNetRaw)
{

    auto authok = security::authenticate_user("santana", "Binho1988@@");
    ASSERT_FALSE(authok);
    auto ret = security::capabilities::enable_net_raw();
    ASSERT_FALSE(ret);
}

TEST_F(SocketRawTests, SendPacket)
{
    using namespace io::network;
    bool received = false;
    bool timeout = false;
    std::uint32_t timeout_ms = 1000;

    auto callback = [&](const char *data, std::size_t size) -> void {
        std::cout << "Received " << size << " bytes" << std::endl;
        received = true;
    };        
    socket = std::make_unique<socket_raw>(callback);
    auto ret = socket->init_write_socket("enp4s0");
    ASSERT_FALSE(ret);
   // ret = socket->init_read_socket_async("enp4s0");
    //ASSERT_FALSE(ret);
    std::size_t szbuffer = 0;

    auto buffer = socket->aquire_buffer(szbuffer);
    //check buffer
    EXPECT_NE(buffer, nullptr);

    //fill buffer
    std::uint8_t *ptr = reinterpret_cast<std::uint8_t *>(buffer);
    //fill ip header localhost
    ipv4::header *ip = reinterpret_cast<ipv4::header *>(ptr);
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = 0;
    ip->id = 1;
    ip->ttl = 64;
    ip->frag_off = static_cast<std::uint16_t>(ipv4::fragment_flags::dont_fragment);
    ip->protocol = static_cast<std::uint8_t>(ipv4::protocols::icmp);
    ip->daddr = htonl(ipv4::string_to_ip("127.0.0.1"));
    ip->saddr = ipv4::get_localhost_ip("enp4s0");

    EXPECT_FALSE(socket->send(sizeof(ipv4::header)));
}