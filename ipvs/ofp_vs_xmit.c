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

	//ip_cksum(iphdr, skb);

	if (pp->fnat_in_handler && !pp->fnat_in_handler(skb, pp, cp))
		goto tx_error;

	ofp_ip_output((odp_packet_t)skb, NULL);
	LeaveFunction(10);
	return NF_STOLEN;

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
	//ip_cksum(iphdr, skb);

	if (pp->fnat_out_handler && !pp->fnat_out_handler(skb, pp, cp))
			goto err;

	ofp_ip_output((odp_packet_t)skb, NULL);
	LeaveFunction(10);
	return NF_STOLEN;

err:
	rte_pktmbuf_free(skb);
	LeaveFunction(10);
	return NF_STOLEN;
}
