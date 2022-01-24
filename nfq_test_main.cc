#include <iostream>

#include <netinet/in.h> // must be included before netfilter.h
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <iomanip>

static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data) {

    unsigned char* pl_ptr = nullptr;
    auto* ph = nfq_get_msg_packet_hdr(nfa);
    auto packet_id = ntohl(ph->packet_id);
    auto pl_len = nfq_get_payload(nfa, &pl_ptr);

    if (pl_len == -1) {
        fprintf(stderr, "nfq_get_payload() failed: nfq_errno=%i\n", nfq_errno);
    }

    if (nfq_get_indev(nfa) == 0 && nfq_get_outdev(nfa) > 0) {
        std::cout << "egress pkt:  id=";
    } else if (nfq_get_indev(nfa) > 0 && nfq_get_outdev(nfa) == 0) {
        std::cout << "ingress pkt: id=";
    }

    std::cout << packet_id << std::endl
              << "             indev=" << std::dec << nfq_get_indev(nfa) << std::endl
              << "             outdev=" << std::dec << nfq_get_outdev(nfa) << std::endl
              << "             nfmark=" << std::dec << nfq_get_nfmark(nfa) << std::endl
              << "             pl_len=" << std::dec << pl_len << std::endl
              << "             pl=0x";

    for (auto i = 0; i < pl_len; i++) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (unsigned) *(pl_ptr + i);
    }

    std::cout << std::endl;

    // drop every other packet
    auto verdict = packet_id % 2 ? NF_ACCEPT : NF_DROP;
    return nfq_set_verdict(qh, packet_id, verdict, 0, nullptr);
}

int main(int argc, char** argv) {

    // opening library handle
    auto* h = nfq_open();
    if (!h) {
        fprintf(stderr, "nfq_open() failed: nfq_errno=%i\n", nfq_errno);
        exit(1);
    }

    // binding this socket to queue 0
    auto* qh = nfq_create_queue(h, 0, &cb, nullptr);
    if (!qh) {
        fprintf(stderr, "nfq_create_queue() failed: nfq_errno=%i\n", nfq_errno);
        exit(1);
    }

    // setting copy_packet mode
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "nfq_set_mode() failed: nfq_errno=%i\n", nfq_errno);
        exit(1);
    }

    auto fd = nfq_fd(h);
    long bytes_received = 0;
    char buf[4096] __attribute__ ((aligned));

    while ((bytes_received = recv(fd, buf, sizeof(buf), 0))) {
        nfq_handle_packet(h, buf, (int) bytes_received);
    }

    nfq_destroy_queue(qh);

    // close library handle
    if (nfq_close(h) != 0) {
        fprintf(stderr, "nfq_close() failed: nfq_errno=%i\n", nfq_errno);
        exit(1);
    }

    return 0;
}
