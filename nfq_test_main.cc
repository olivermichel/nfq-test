
#include <iostream>
#include <iomanip>

#include "netfilter_queue.h"

int main(int argc, char** argv) {

    netfilter_queue nfq(0, [](netfilter_queue& q, struct nfq_data* nfd) -> int {

        unsigned char* pl = nullptr;
        auto* ph = nfq_get_msg_packet_hdr(nfd);
        auto packet_id = ntohl(ph->packet_id);
        auto pl_len = nfq_get_payload(nfd, &pl);
        auto pkt_dir = netfilter_queue::pkt_dir(nfd);
        auto pkt_dir_str = netfilter_queue::pkt_dir_string_long( pkt_dir);

        std::cout << pkt_dir_str << " packet" << std::endl
            << "    id=" << packet_id << std::endl
            << "    indev=" << std::dec << nfq_get_indev(nfd) << std::endl
            << "    outdev=" << std::dec << nfq_get_outdev(nfd) << std::endl
            << "    nfmark=" << std::dec << nfq_get_nfmark(nfd) << std::endl
            << "    pl_len=" << std::dec << pl_len << std::endl
            << "    pl=0x";

        for (auto i = 0; i < pl_len; i++) {
            std::cout << std::setw(2) << std::setfill('0') << std::hex << (unsigned) *(pl + i);
        }

        std::cout << std::endl;

        return q.accept_pkt(packet_id);
    });

    while (nfq.receive_pkt()) { }

    return 0;
}
