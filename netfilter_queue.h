
#ifndef NETFILTER_QUEUE_H
#define NETFILTER_QUEUE_H

#include <netinet/in.h> // must be included before netfilter.h
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <functional>

class netfilter_queue {
public:

    typedef std::function<int (netfilter_queue&, struct nfq_data*)> pkt_handler_t;

    enum class pkt_dir {
        unknown = 0,
        ingress = 1,
        egress  = 2
    };

    static pkt_dir pkt_dir(struct nfq_data* nfd);
    static std::string pkt_dir_string(const enum pkt_dir& pkt_dir);
    static std::string pkt_dir_string_long(const enum pkt_dir& pkt_dir);

    explicit netfilter_queue(unsigned queue_id, pkt_handler_t pkt_handler);
    netfilter_queue(const netfilter_queue&) = delete;
    netfilter_queue& operator=(const netfilter_queue&) = delete;
    netfilter_queue(netfilter_queue&&) = default;
    netfilter_queue& operator=(netfilter_queue&&) = default;

    [[nodiscard]] int fd() const;
    long receive_pkt();
    int accept_pkt(unsigned pkt_id);
    int accept_pkt(struct nfq_data* nfd);
    int drop_pkt(unsigned pkt_id);
    int drop_pkt(struct nfq_data* nfd);

    virtual ~netfilter_queue();

private:

    static int _nfq_callback(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa,
                             void* data);

    struct nfq_handle* _h = nullptr;
    struct nfq_q_handle* _qh = nullptr;
    pkt_handler_t _pkt_handler;
};

#endif
