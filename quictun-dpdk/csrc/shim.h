#ifndef QUICTUN_DPDK_SHIM_H
#define QUICTUN_DPDK_SHIM_H

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_eal.h>
#include <rte_bus_vdev.h>

/*
 * C shim wrappers for inline DPDK functions.
 *
 * Many performance-critical DPDK functions are static inline in headers,
 * which means bindgen can see their declarations but Rust can't call them
 * directly through FFI.  These trivial wrappers make them callable.
 */

uint16_t shim_rte_eth_rx_burst(uint16_t port_id, uint16_t queue_id,
                                struct rte_mbuf **rx_pkts, uint16_t nb_pkts);

uint16_t shim_rte_eth_tx_burst(uint16_t port_id, uint16_t queue_id,
                                struct rte_mbuf **tx_pkts, uint16_t nb_pkts);

struct rte_mbuf *shim_rte_pktmbuf_alloc(struct rte_mempool *mp);

void shim_rte_pktmbuf_free(struct rte_mbuf *m);

char *shim_rte_pktmbuf_mtod(struct rte_mbuf *m);

uint16_t shim_rte_pktmbuf_data_len(const struct rte_mbuf *m);

char *shim_rte_pktmbuf_append(struct rte_mbuf *m, uint16_t len);

char *shim_rte_pktmbuf_prepend(struct rte_mbuf *m, uint16_t len);

char *shim_rte_pktmbuf_adj(struct rte_mbuf *m, uint16_t len);

int shim_rte_pktmbuf_trim(struct rte_mbuf *m, uint16_t len);

void shim_rte_pktmbuf_reset(struct rte_mbuf *m);

int shim_rte_pktmbuf_alloc_bulk(struct rte_mempool *pool,
                                 struct rte_mbuf **mbufs, unsigned count);

/*
 * Create an rte_eth_conf with RSS enabled for multi-queue.
 * rss_hf: RSS hash function bitmask (e.g., RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP).
 */
struct rte_eth_conf shim_create_rss_port_conf(uint64_t rss_hf);

/*
 * Return the RSS hash flags for IPv4 + UDP.
 */
uint64_t shim_rss_ip_udp_flags(void);

#endif /* QUICTUN_DPDK_SHIM_H */
