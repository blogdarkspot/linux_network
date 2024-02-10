#include <ipv4.hpp>
#include <gtest/gtest.h>

TEST(Ipv4Tests, GetLocalHostFromInterface)
{
    using namespace io::network::ipv4;
    auto localhost = get_localhost_ip("enp4s0");
    #ifndef NDEBUG
    std::cout << "Localhost: " << ip_to_string(ntohl(localhost)) << std::endl;
    #endif
    auto ip = string_to_ip("192.168.0.35");
    EXPECT_EQ(localhost, htonl(ip));
}