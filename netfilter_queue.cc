
#include "netfilter_queue.h"

#include <utility>
#include <stdexcept>

enum netfilter_queue::pkt_dir netfilter_queue::pkt_dir(struct nfq_data* nfd) {

    if (nfq_get_indev(nfd) == 0 && nfq_get_outdev(nfd) > 0) {
        return pkt_dir::egress;
    } else if (nfq_get_indev(nfd) > 0 && nfq_get_outdev(nfd) == 0) {
        return pkt_dir::ingress;
    }

    return pkt_dir::unknown;
}

std::string netfilter_queue::pkt_dir_string(const enum netfilter_queue::pkt_dir& pkt_dir) {

    switch (pkt_dir) {
        case netfilter_queue::pkt_dir::ingress: return "i";
        case netfilter_queue::pkt_dir::egress:  return "e";
        default:                                return "u";
    }
}

std::string netfilter_queue::pkt_dir_string_long(const enum netfilter_queue::pkt_dir& pkt_dir) {

    switch (pkt_dir) {
        case netfilter_queue::pkt_dir::ingress: return "ingress";
        case netfilter_queue::pkt_dir::egress:  return "egress";
        default:                                return "unknown";
    }
}

netfilter_queue::netfilter_queue(unsigned queue_id, pkt_handler_t pkt_handler)
    : _pkt_handler(std::move(pkt_handler)) {

    // open library handle
    _h = nfq_open();
    if (!_h) {
        throw std::runtime_error("netfilter_queue: nfq_open() failed: nfq_errno="
                                 + std::to_string(nfq_errno));
    }

    // bind to queue
    _qh = nfq_create_queue(_h, queue_id, netfilter_queue::_nfq_callback, this);
    if (!_qh) {
        throw std::runtime_error("netfilter_queue: nfq_create_queue() failed: nfq_errno="
                                 + std::to_string(nfq_errno));
    }

    // set COPY_PACKET mode (enables payload access)
    if (nfq_set_mode(_qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        throw std::runtime_error("netfilter_queue: nfq_set_mode() failed: nfq_errno="
                                 + std::to_string(nfq_errno));
    }
}

int netfilter_queue::fd() const {

    return nfq_fd(_h);
}

long netfilter_queue::receive_pkt() {

    char rx_buf[2048] __attribute__ ((aligned));
    long rx_bytes = ::recv(nfq_fd(_h), rx_buf, sizeof(rx_buf), 0);
    nfq_handle_packet(_h, rx_buf, (int) rx_bytes);
    return rx_bytes;
}

int netfilter_queue::accept_pkt(unsigned pkt_id) {

    return nfq_set_verdict(_qh, pkt_id, NF_ACCEPT, 0, nullptr);
}

int netfilter_queue::accept_pkt(struct nfq_data* nfd) {

    auto* ph = nfq_get_msg_packet_hdr(nfd);
    auto pkt_id = ntohl(ph->packet_id);
    return nfq_set_verdict(_qh, pkt_id, NF_ACCEPT, 0, nullptr);
}

int netfilter_queue::drop_pkt(unsigned pkt_id) {

    return nfq_set_verdict(_qh, pkt_id, NF_DROP, 0, nullptr);
}

int netfilter_queue::drop_pkt(struct nfq_data* nfd) {

    auto* ph = nfq_get_msg_packet_hdr(nfd);
    auto pkt_id = ntohl(ph->packet_id);
    return nfq_set_verdict(_qh, pkt_id, NF_DROP, 0, nullptr);
}

netfilter_queue::~netfilter_queue() {

    if (_qh)
        nfq_destroy_queue(_qh);

    if (_h)
        nfq_close(_h);
}

int netfilter_queue::_nfq_callback(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
        struct nfq_data* nfa, void* data) {

    auto* queue_wrapper = static_cast<netfilter_queue*>(data);
    return queue_wrapper->_pkt_handler(*queue_wrapper, nfa);
}
