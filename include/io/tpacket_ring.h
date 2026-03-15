#pragma once

#include <cstdint>
#include <cstdlib>
#include <sys/mman.h>
#include <sys/uio.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <cstring>

#include "packet_types.h"

namespace io::network {

class tpacket_ring {
public:
    tpacket_ring() = default;

    // configure defaults for TPACKET_V3 ring (was v3_fill)
    void configure_defaults() {
        memset(&req, 0, sizeof(req));
        req.tp_retire_blk_tov = 64;
        req.tp_sizeof_priv = 0;
        req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
        req.tp_block_size = static_cast<unsigned int>(getpagesize()) << 2;
        req.tp_frame_size = TPACKET_ALIGNMENT << 7;
        req.tp_block_nr = 1 << 10;
        req.tp_frame_nr = req.tp_block_size / req.tp_frame_size * req.tp_block_nr;
    }

    // create ring via setsockopt + mmap; returns false on failure
    bool create(int sockfd) {
        if (setsockopt(sockfd, SOL_PACKET, PACKET_RX_RING, reinterpret_cast<void *>(&req), sizeof(req)) != 0) {
            return false;
        }

        map = static_cast<uint8_t *>(mmap(nullptr, req.tp_block_size * req.tp_block_nr,
                                          PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, sockfd, 0));
        if (map == MAP_FAILED) {
            map = nullptr;
            return false;
        }

        rd = static_cast<iovec *>(malloc(req.tp_block_nr * sizeof(*rd)));
        if (!rd) {
            munmap(map, req.tp_block_size * req.tp_block_nr);
            map = nullptr;
            return false;
        }

        for (unsigned int i = 0; i < req.tp_block_nr; ++i) {
            rd[i].iov_base = map + (i * req.tp_block_size);
            rd[i].iov_len = req.tp_block_size;
        }
        block_num = 0;
        return true;
    }

    void destroy(int /*sockfd*/) {
        if (map) {
            munmap(map, req.tp_block_size * req.tp_block_nr);
            map = nullptr;
        }
        if (rd) {
            free(rd);
            rd = nullptr;
        }
    }

    // helpers used by multicast_udp_receiver
    block_desc *current_block() const {
        return reinterpret_cast<block_desc *>(rd ? rd[block_num].iov_base : nullptr);
    }

    void advance() {
        block_num = (block_num + 1) % req.tp_block_nr;
    }

    void mark_block_kernel(block_desc *pbd) {
        if (pbd) pbd->h1.block_status = TP_STATUS_KERNEL;
    }

    // public members for compatibility where needed
    tpacket_req3 req{};
    uint8_t *map = nullptr;
    iovec *rd = nullptr;
    unsigned int block_num = 0;
};
} // namespace io::network