#include <functional>
#include <iostream>
#include "tcp_client.hpp"


int main()
{
    auto read_cb = [](const char* __buffer, size_t __len) {
        
    };

    auto tcp_client = io::network::tcp_client("enp0s3", read_cb);
    //host 127.0.0.1
    std::uint32_t host = 0x00;
    host |=  127 << 24;
    host |= 1;

    try
    {
        tcp_client.connect(host, 500);
    }
    catch(const io::network::network_exception& e)
    {
        std::cerr << e.what() << '\n';
    }

    return 0;
    
}