/*
 * ip_vs_xmit.c: various packet transmitters for IPVS
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *              Julian Anastasov <ja@ssi.bg>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Changes:
 *
 */

#define KMSG_COMPONENT "IPVS"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include "ofp_vs.h"

static inline void
ipv4_cksum(struct iphdr *iphdr, struct rte_mbuf *skb)
{
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(skb, struct ether_hdr *);
	uint16_t ethertype;

	iphdr->check = 0;
	skb->ol_flags |= PKT_TX_OUTER_IP_CKSUM;
	if (sysctl_ip_vs_csum_offload) {
		/* Use hardware csum offload */
		skb->ol_flags |= PKT_TX_IPV4;
		skb->ol_flags |= PKT_TX_IP_CKSUM;
		skb->l3_len = ip_hdrlen(iphdr);
		skb->l2_len = sizeof(struct ether_hdr);
		ethertype = rte_be_to_cpu_16(eth_hdr->ether_type);

		if (ethertype == ETHER_TYPE_VLAN) {
			skb->l2_len  += sizeof(struct vlan_hdr);
		}

	} else {
		iphdr->check = ofp_vs_ipv4_cksum(iphdr);
	}
}

/* just for fullnat mode */
static int
ip_vs_fast_xmit(struct rte_mbuf *skb, struct ip_vs_protocol *pp,
		struct ip_vs_conn *cp)
{
	return -1;
}

static int
ip_vs_fast_response_xmit(struct rte_mbuf *skb,
			 struct ip_vs_protocol *pp,
			 struct ip_vs_conn *cp)
{
	return -1;
}

/*
 *      FULLNAT transmitter (only for outside-to-inside fullnat forwarding)
 *      Not used for related ICMP
 */
int
ip_vs_fnat_xmit(struct rte_mbuf *skb, struct ip_vs_conn *cp,
		struct ip_vs_protocol *pp)
{
	struct iphdr *iphdr = ip_hdr(skb);
	
	EnterFunction(10);
	/* check if it is a connection of no-client-port */
	if (unlikely(cp->flags & IP_VS_CONN_F_NO_CPORT)) {
		__be16 *p;
		p = (__be16 *)((unsigned char *)iphdr + iphdr->ihl * 4);
		if (p == NULL)
			goto tx_error;
		ip_vs_conn_fill_cport(cp, *p);
		IP_VS_DBG(10, "filled cport=%d\n", ntohs(*p));
	}

	//ip_vs_save_xmit_outside_info(skb, cp);

	if (sysctl_ip_vs_fast_xmit_inside && !ip_vs_fast_xmit(skb, pp, cp))
		return NF_STOLEN;

	iphdr->saddr = cp->laddr.ip;
	iphdr->daddr = cp->daddr.ip;

	ipv4_cksum(iphdr, skb);

	if (pp->fnat_in_handler && !pp->fnat_in_handler(skb, pp, cp))
		goto tx_error;
	
	LeaveFunction(10);
	return ofp_ip_output((odp_packet_t)skb, NULL);

tx_error:
	rte_pktmbuf_free(skb);
	LeaveFunction(10);
	return NF_STOLEN;
}

/* Response transmit to client
 * Used for FULLNAT.
 */
int
ip_vs_fnat_response_xmit(struct rte_mbuf *skb, struct ip_vs_protocol *pp,
			 struct ip_vs_conn *cp, int ihl)
{
	struct iphdr *iphdr = ip_hdr(skb);

	EnterFunction(10);

	//ip_vs_save_xmit_inside_info(skb, cp);

	if (sysctl_ip_vs_fast_xmit &&
	    !ip_vs_fast_response_xmit(skb, pp, cp))
		return NF_STOLEN;
		
	iphdr->saddr = cp->vaddr.ip;
	iphdr->daddr = cp->caddr.ip;
	ipv4_cksum(iphdr, skb);

	if (pp->fnat_out_handler && !pp->fnat_out_handler(skb, pp, cp))
			goto err;
	
	LeaveFunction(10);
	return ofp_ip_output((odp_packet_t)skb, NULL);

err:
	rte_pktmbuf_free(skb);
	LeaveFunction(10);
	return NF_STOLEN;
}
