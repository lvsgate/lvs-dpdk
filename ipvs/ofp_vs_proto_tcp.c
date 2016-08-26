/*
 * IPVS         An implementation of the IP virtual server support for the
 *              LINUX operating system.  IPVS is now implemented as a module
 *              over the NetFilter framework. IPVS can be used to build a
 *              high-performance and highly available server based on a
 *              cluster of servers.
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *              Peter Kese <peter.kese@ijs.si>
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

#include "net/ip_vs.h"

/*
 *	Timeout table[state]
 */
int sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_LAST + 1] = {
	[IP_VS_TCP_S_NONE] = 2,
	[IP_VS_TCP_S_ESTABLISHED] = 90,
	[IP_VS_TCP_S_SYN_SENT] = 3,
	[IP_VS_TCP_S_SYN_RECV] = 30,
	[IP_VS_TCP_S_FIN_WAIT] = 7,
	[IP_VS_TCP_S_TIME_WAIT] = 7,
	[IP_VS_TCP_S_CLOSE] = 3,
	[IP_VS_TCP_S_CLOSE_WAIT] = 7,
	[IP_VS_TCP_S_LAST_ACK] = 7,
	[IP_VS_TCP_S_LISTEN] = 2 * 60,
	[IP_VS_TCP_S_SYNACK] = 30,
	[IP_VS_TCP_S_LAST] = 2,
};

struct ip_vs_protocol ip_vs_protocol_tcp = {
  .name = "TCP",
};
