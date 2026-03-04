#include "shim.h"
#include <string.h>

uint16_t shim_rte_eth_rx_burst(uint16_t port_id, uint16_t queue_id,
                                struct rte_mbuf **rx_pkts, uint16_t nb_pkts) {
    return rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
}

uint16_t shim_rte_eth_tx_burst(uint16_t port_id, uint16_t queue_id,
                                struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
    return rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
}

struct rte_mbuf *shim_rte_pktmbuf_alloc(struct rte_mempool *mp) {
    return rte_pktmbuf_alloc(mp);
}

void shim_rte_pktmbuf_free(struct rte_mbuf *m) {
    rte_pktmbuf_free(m);
}

char *shim_rte_pktmbuf_mtod(struct rte_mbuf *m) {
    return rte_pktmbuf_mtod(m, char *);
}

uint16_t shim_rte_pktmbuf_data_len(const struct rte_mbuf *m) {
    return rte_pktmbuf_data_len(m);
}

char *shim_rte_pktmbuf_append(struct rte_mbuf *m, uint16_t len) {
    return rte_pktmbuf_append(m, len);
}

char *shim_rte_pktmbuf_prepend(struct rte_mbuf *m, uint16_t len) {
    return rte_pktmbuf_prepend(m, len);
}

char *shim_rte_pktmbuf_adj(struct rte_mbuf *m, uint16_t len) {
    return rte_pktmbuf_adj(m, len);
}

int shim_rte_pktmbuf_trim(struct rte_mbuf *m, uint16_t len) {
    return rte_pktmbuf_trim(m, len);
}

void shim_rte_pktmbuf_reset(struct rte_mbuf *m) {
    rte_pktmbuf_reset(m);
}

int shim_rte_pktmbuf_alloc_bulk(struct rte_mempool *pool,
                                 struct rte_mbuf **mbufs, unsigned count) {
    return rte_pktmbuf_alloc_bulk(pool, mbufs, count);
}

struct rte_eth_conf shim_create_rss_port_conf(uint64_t rss_hf) {
    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof(conf));
    conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    conf.rx_adv_conf.rss_conf.rss_key = NULL;  /* use default key */
    conf.rx_adv_conf.rss_conf.rss_hf = rss_hf;
    return conf;
}

uint64_t shim_rss_ip_udp_flags(void) {
    return RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP;
}

struct rte_ring *shim_rte_ring_create(const char *name, unsigned count,
                                       int socket_id, unsigned flags) {
    return rte_ring_create(name, count, socket_id, flags);
}

void shim_rte_ring_free(struct rte_ring *r) {
    rte_ring_free(r);
}

int shim_rte_ring_sp_enqueue(struct rte_ring *r, void *obj) {
    return rte_ring_sp_enqueue(r, obj);
}

unsigned shim_rte_ring_sp_enqueue_burst(struct rte_ring *r,
                                         void * const *objs, unsigned n,
                                         unsigned *free_space) {
    return rte_ring_sp_enqueue_burst(r, objs, n, free_space);
}

unsigned shim_rte_ring_sc_dequeue_burst(struct rte_ring *r, void **objs,
                                         unsigned n, unsigned *available) {
    return rte_ring_sc_dequeue_burst(r, objs, n, available);
}
