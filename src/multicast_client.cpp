#include <iostream>
#include <string>
#include <atomic>
#include <csignal>
#include <vector>
#include <cstdint>
#include <ctime>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "io/multicast_udp_receiver.h"

using namespace io::network;

static std::atomic<bool> g_stop{false};
static void sigint_handler(int) { g_stop = true; }

static bool is_ipv4_multicast(const std::string &addr) {
    in_addr in;
    if (inet_pton(AF_INET, addr.c_str(), &in) != 1) return false;
    uint32_t a = ntohl(in.s_addr);
    uint8_t first = (a >> 24) & 0xFF;
    return (first >= 224 && first <= 239);
}

static std::uint64_t realtime_now_ns() {
    timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    constexpr std::uint64_t NSEC_PER_SEC = 1000000000ULL;
    return static_cast<std::uint64_t>(ts.tv_sec) * NSEC_PER_SEC +
           static_cast<std::uint64_t>(ts.tv_nsec);
}

struct packet_sample {
    std::uint64_t nic_ts_ns;
    std::size_t len;
    std::string payload;
};

int main(int argc, char **argv) {
    std::signal(SIGINT, sigint_handler);

    std::string iface = (argc > 1) ? argv[1] : "lo";
    std::string group = (argc > 2) ? argv[2] : "239.0.0.1";
    int port = (argc > 3) ? std::stoi(argv[3]) : 5000;

    if (!is_ipv4_multicast(group)) {
        std::cerr << "error: group address must be an IPv4 multicast address (224.0.0.0/4): " << group << "\n";
        return 2;
    }

    network_config cfg;
    cfg.interface = iface;
    cfg.address = group;
    cfg.port = static_cast<std::uint16_t>(port);
    cfg.group = 0;          // factory will derive if zero
    cfg.loopback = true;    // subscribe loopback

    std::unique_ptr<multicast_udp_receiver> receiver;
    try {
        receiver = multicast_udp_receiver::make<>(cfg);
    } catch (const std::system_error &e) {
        std::cerr << "failed to create receiver: " << e.what() << "\n";
        return 1;
    }

    std::cout << "Listening on interface=" << cfg.interface
              << " group=" << cfg.address << ":" << cfg.port
              << " (loopback=" << std::boolalpha << cfg.loopback << ")\n";

    bool offset_calibrated = false;
    std::int64_t clock_offset_ns = 0;

    while (!g_stop) {
        std::vector<packet_sample> batch;
        int n = receiver->read_packtes(1000 /*ms*/, [&batch](const udp_packet &pkt) {
            batch.push_back(packet_sample{
                .nic_ts_ns = pkt.timestamp_ns,
                .len = pkt.data_len,
                .payload = std::string(pkt.data, pkt.data_len),
            });
        });
        std::uint64_t read_return_ns = realtime_now_ns();

        for (const auto &pkt : batch) {
            auto raw_delta_ns = static_cast<std::int64_t>(read_return_ns) -
                                static_cast<std::int64_t>(pkt.nic_ts_ns);
            if (!offset_calibrated) {
                clock_offset_ns = raw_delta_ns;
                offset_calibrated = true;
                std::cout << "[calibration] clock_offset_ns=" << clock_offset_ns << "\n";
            }
            auto kernel_queue_ns = raw_delta_ns - clock_offset_ns;
            if (kernel_queue_ns < 0) kernel_queue_ns = 0;

            std::cout << "[packet] len=" << pkt.len
                      << " nic_ts_ns=" << pkt.nic_ts_ns
                      << " read_return_ns=" << read_return_ns
                      << " raw_delta_ns=" << raw_delta_ns
                      << " kernel_queue_ns=" << kernel_queue_ns
                      << " kernel_queue_us=" << (static_cast<double>(kernel_queue_ns) / 1000.0)
                      << "\n";
        }

        if (n < 0) {
            std::cerr << "poll error\n";
            break;
        }
        // continue until SIGINT
    }

    std::cout << "Shutting down\n";
    return 0;
}
