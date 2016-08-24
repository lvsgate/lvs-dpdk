/**
 * Copyright (c) 2016 lvsgate@163.com
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/errno.h>


#include "ofp_vs.h"

static int ipvs_genl_family;

/*
 *	Hash table: for virtual service lookups
 */
#define IP_VS_SVC_TAB_BITS 12
#define IP_VS_SVC_TAB_SIZE (1 << IP_VS_SVC_TAB_BITS)
#define IP_VS_SVC_TAB_MASK (IP_VS_SVC_TAB_SIZE - 1)

/* the service table hashed by <protocol, addr, port> */
DEFINE_PER_CPU(struct list_head *, ip_vs_svc_tab_percpu);

extern int sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_LAST + 1];

static struct nl_sock *sock = NULL;

static void *ofp_vs_ctl_thread(void *arg)
{
  int err;
  odp_bool_t *is_running = NULL;

  (void)arg;

  is_running = ofp_get_processing_state();
	if (is_running == NULL) {
		OFP_ERR("ofp_get_processing_state failed\n");
		ofp_term_local();
	  goto out;	
	}

  if (sock == NULL) {
    OFP_ERR("nl_sock is NULL\n");
		ofp_term_local();
	  goto out;
  }
  
  OFP_INFO("ofp_vs_ctl_thread thread is running.\n");
  while (*is_running) {
    if ((err = -nl_recvmsgs_default(sock)) > 0) {
      OFP_ERR("nl_recvmsgs_default return %d\n", err);
      //goto out;
    }
    OFP_DBG("nl recv data\n");
    //sleep(1);
	}

out:

  OFP_INFO("ofp_vs_ctl_thread exiting");
	return NULL;
}

static odph_linux_pthread_t ofp_vs_ctl_pthread;
void ofp_vs_ctl_thread_start(odp_instance_t instance, int core_id)
{
	odp_cpumask_t cpumask;
	odph_linux_thr_params_t thr_params;

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, core_id);

	thr_params.start = ofp_vs_ctl_thread;
	thr_params.arg = NULL;
	thr_params.thr_type = ODP_THREAD_CONTROL;
	thr_params.instance = instance;
	odph_linux_pthread_create(&ofp_vs_ctl_pthread,
				  &cpumask,
				  &thr_params
				);
}

/* Policy used for first-level command attributes */
static struct nla_policy ip_vs_cmd_policy[IPVS_CMD_ATTR_MAX + 1] = {
	[IPVS_CMD_ATTR_SERVICE] = {.type = NLA_NESTED},
	[IPVS_CMD_ATTR_DEST] = {.type = NLA_NESTED},
	[IPVS_CMD_ATTR_DAEMON] = {.type = NLA_NESTED},
	[IPVS_CMD_ATTR_TIMEOUT_TCP] = {.type = NLA_U32},
	[IPVS_CMD_ATTR_TIMEOUT_TCP_FIN] = {.type = NLA_U32},
	[IPVS_CMD_ATTR_TIMEOUT_UDP] = {.type = NLA_U32},
	[IPVS_CMD_ATTR_LADDR] = {.type = NLA_NESTED},
}; 

/* Policy used for attributes in nested attribute IPVS_CMD_ATTR_DAEMON */
static const struct nla_policy ip_vs_daemon_policy[IPVS_DAEMON_ATTR_MAX + 1] = {
	[IPVS_DAEMON_ATTR_STATE] = {.type = NLA_U32},
	[IPVS_DAEMON_ATTR_MCAST_IFN] = {.type = NLA_STRING,
					.minlen = IP_VS_IFNAME_MAXLEN},
	[IPVS_DAEMON_ATTR_SYNC_ID] = {.type = NLA_U32},
};

/* Policy used for attributes in nested attribute IPVS_CMD_ATTR_SERVICE */
static const struct nla_policy ip_vs_svc_policy[IPVS_SVC_ATTR_MAX + 1] = {
	[IPVS_SVC_ATTR_AF] = {.type = NLA_U16},
	[IPVS_SVC_ATTR_PROTOCOL] = {.type = NLA_U16},
	[IPVS_SVC_ATTR_ADDR] = {.type = NLA_UNSPEC,
				.minlen = sizeof(union nf_inet_addr)},
	[IPVS_SVC_ATTR_PORT] = {.type = NLA_U16},
	[IPVS_SVC_ATTR_FWMARK] = {.type = NLA_U32},
	[IPVS_SVC_ATTR_SCHED_NAME] = {.type = NLA_STRING,
				      .minlen = IP_VS_SCHEDNAME_MAXLEN},
	[IPVS_SVC_ATTR_FLAGS] = {.type = NLA_UNSPEC,
				 .minlen = sizeof(struct ip_vs_flags)},
	[IPVS_SVC_ATTR_TIMEOUT] = {.type = NLA_U32},
	[IPVS_SVC_ATTR_NETMASK] = {.type = NLA_U32},
	[IPVS_SVC_ATTR_STATS] = {.type = NLA_NESTED},
};

/* Policy used for attributes in nested attribute IPVS_CMD_ATTR_DEST */
static const struct nla_policy ip_vs_dest_policy[IPVS_DEST_ATTR_MAX + 1] = {
	[IPVS_DEST_ATTR_ADDR] = {.type = NLA_UNSPEC,
				 .minlen = sizeof(union nf_inet_addr)},
	[IPVS_DEST_ATTR_PORT] = {.type = NLA_U16},
	[IPVS_DEST_ATTR_FWD_METHOD] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_WEIGHT] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_U_THRESH] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_L_THRESH] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_ACTIVE_CONNS] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_INACT_CONNS] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_PERSIST_CONNS] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_STATS] = {.type = NLA_NESTED},
};

static const struct nla_policy ip_vs_laddr_policy[IPVS_LADDR_ATTR_MAX + 1] = {
	[IPVS_LADDR_ATTR_ADDR] = {.type = NLA_UNSPEC,
				  .minlen = sizeof(union nf_inet_addr)},
	[IPVS_LADDR_ATTR_PORT_CONFLICT] = {.type = NLA_U64},
	[IPVS_LADDR_ATTR_CONN_COUNTS] = {.type = NLA_U32},
};

static struct nl_msg *ipvs_nl_message(int cmd, int flags)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return NULL;

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ipvs_genl_family, 0, flags,
		    cmd, IPVS_GENL_VERSION);

	return msg;
}

/*
 *	Returns hash value for virtual service
 */
static __inline__ unsigned
ip_vs_svc_hashkey(int af, unsigned proto, const union nf_inet_addr *addr)
{
	__be32 addr_fold = addr->ip;

#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		addr_fold = addr->ip6[0] ^ addr->ip6[1] ^
		    addr->ip6[2] ^ addr->ip6[3];
#endif

	return (proto ^ ntohl(addr_fold)) & IP_VS_SVC_TAB_MASK;
}


static int ip_vs_svc_hash_cpuid(struct ip_vs_service *svc, int cpu)
{
	unsigned hash;
	struct list_head *ip_vs_svc_tab;

	if (svc->flags & IP_VS_SVC_F_HASHED) {
		pr_err("%s(): request for already hashed, called from %pF\n",
		       __func__, __builtin_return_address(0));
		return 0;
	}

	if (svc->fwmark == 0) {
		/*
		 *  Hash it by <protocol,addr,port> in ip_vs_svc_table
		 */
		hash = ip_vs_svc_hashkey(svc->af, svc->protocol, &svc->addr);
		ip_vs_svc_tab = per_cpu(ip_vs_svc_tab_percpu, cpu);
		list_add(&svc->s_list, ip_vs_svc_tab + hash);
	} else {
    return 0;
	}

	svc->flags |= IP_VS_SVC_F_HASHED;
	/* increase its refcnt because it is referenced by the svc table */
	atomic_inc(&svc->refcnt);
	return 1;
}

/*
 *	Unhashes a service from ip_vs_svc_table/ip_vs_svc_fwm_table.
 *	Should be called with locked tables.
 */
static int ip_vs_svc_unhash(struct ip_vs_service *svc)
{
	if (!(svc->flags & IP_VS_SVC_F_HASHED)) {
		pr_err("%s(): request for unhash flagged, called from %pF\n",
		       __func__, __builtin_return_address(0));
		return 0;
	}

	if (svc->fwmark == 0) {
		/* Remove it from the ip_vs_svc_table table */
		list_del(&svc->s_list);
	} else {
    return 0;
		/* Remove it from the ip_vs_svc_fwm_table table */
		//list_del(&svc->f_list);
	}

	svc->flags &= ~IP_VS_SVC_F_HASHED;
	atomic_dec(&svc->refcnt);
	return 1;
}

/*
 *	Get service by {proto,addr,port} in the service table.
 */
static inline struct ip_vs_service *__ip_vs_service_get(int af, __u16 protocol,
							const union nf_inet_addr
							*vaddr, __be16 vport)
{
	unsigned hash;
	struct ip_vs_service *svc;
	struct list_head *ip_vs_svc_tab;

	ip_vs_svc_tab = __get_cpu_var(ip_vs_svc_tab_percpu);
	/* Check for "full" addressed entries */
	hash = ip_vs_svc_hashkey(af, protocol, vaddr);

	list_for_each_entry(svc, ip_vs_svc_tab + hash, s_list) {
		if ((svc->af == af)
		    && ip_vs_addr_equal(af, &svc->addr, vaddr)
		    && (svc->port == vport)
		    && (svc->protocol == protocol)) {
			/* HIT */
			//atomic_inc(&svc->usecnt);
			return svc;
		}
	}

	return NULL;
}

/*
 *	Get service by {fwmark} in the service table.
 */
static inline struct ip_vs_service *__ip_vs_svc_fwm_get(int af, __u32 fwmark)
{
  (void)af;
  (void)fwmark;
  return NULL;
}

static int ip_vs_genl_parse_service(struct ip_vs_service_user_kern *usvc,
				    struct nlattr *nla, int full_entry)
{
	struct nlattr *attrs[IPVS_SVC_ATTR_MAX + 1];
	struct nlattr *nla_af, *nla_port, *nla_fwmark, *nla_protocol, *nla_addr;

	/* Parse mandatory identifying service fields first */
	if (nla == NULL ||
	    nla_parse_nested(attrs, IPVS_SVC_ATTR_MAX, nla, ip_vs_svc_policy))
		return -EINVAL;

	nla_af = attrs[IPVS_SVC_ATTR_AF];
	nla_protocol = attrs[IPVS_SVC_ATTR_PROTOCOL];
	nla_addr = attrs[IPVS_SVC_ATTR_ADDR];
	nla_port = attrs[IPVS_SVC_ATTR_PORT];
	nla_fwmark = attrs[IPVS_SVC_ATTR_FWMARK];

	if (!(nla_af && (nla_fwmark || (nla_port && nla_protocol && nla_addr))))
		return -EINVAL;

	memset(usvc, 0, sizeof(*usvc));

	usvc->af = nla_get_u16(nla_af);
#ifdef CONFIG_IP_VS_IPV6
	if (usvc->af != AF_INET && usvc->af != AF_INET6)
#else
	if (usvc->af != AF_INET)
#endif
		return -EAFNOSUPPORT;

	if (nla_fwmark) {
		usvc->protocol = IPPROTO_TCP;
		usvc->fwmark = nla_get_u32(nla_fwmark);
	} else {
		usvc->protocol = nla_get_u16(nla_protocol);
		nla_memcpy(&usvc->addr, nla_addr, sizeof(usvc->addr));
		usvc->port = nla_get_u16(nla_port);
		usvc->fwmark = 0;
	}

	/* If a full entry was requested, check for the additional fields */
	if (full_entry) {
		struct nlattr *nla_sched, *nla_flags, *nla_timeout,
		    *nla_netmask, *nla_est_timeout;
		struct ip_vs_flags flags;
		struct ip_vs_service *svc;

		nla_sched = attrs[IPVS_SVC_ATTR_SCHED_NAME];
		nla_flags = attrs[IPVS_SVC_ATTR_FLAGS];
		nla_timeout = attrs[IPVS_SVC_ATTR_TIMEOUT];
		nla_netmask = attrs[IPVS_SVC_ATTR_NETMASK];
		nla_est_timeout = attrs[IPVS_SVC_ATTR_EST_TIMEOUT];

		if (!(nla_sched && nla_flags && nla_timeout && nla_netmask))
			return -EINVAL;

		nla_memcpy(&flags, nla_flags, sizeof(flags));

		/* prefill flags from service if it already exists */
		if (usvc->fwmark)
			svc = __ip_vs_svc_fwm_get(usvc->af, usvc->fwmark);
		else
			svc = __ip_vs_service_get(usvc->af, usvc->protocol,
						  &usvc->addr, usvc->port);
		if (svc) {
			usvc->flags = svc->flags;
			//ip_vs_service_put(svc);
		} else
			usvc->flags = 0;

		/* set new flags from userland */
		usvc->flags = (usvc->flags & ~flags.mask) |
		    (flags.flags & flags.mask);
		usvc->sched_name = nla_data(nla_sched);
		usvc->timeout = nla_get_u32(nla_timeout);
		usvc->netmask = nla_get_u32(nla_netmask);
		if(IPPROTO_TCP == usvc->protocol) {
			if(nla_est_timeout) /* Be compatible with different version of libipvs2.6 */
				usvc->est_timeout = nla_get_u32(nla_est_timeout);
			if(!usvc->est_timeout)
				usvc->est_timeout = sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_ESTABLISHED] ;
		}
	}

	return 0;
}

static struct ip_vs_service *ip_vs_genl_find_service(struct nlattr *nla)
{
	struct ip_vs_service_user_kern usvc;
	int ret;

	ret = ip_vs_genl_parse_service(&usvc, nla, 0);
	if (ret)
		return ERR_PTR(ret);

	if (usvc.fwmark)
		return __ip_vs_svc_fwm_get(usvc.af, usvc.fwmark);
	else
		return __ip_vs_service_get(usvc.af, usvc.protocol,
					   &usvc.addr, usvc.port);
}

static int ip_vs_genl_fill_service(struct sk_buff *skb,
				   struct ip_vs_service *svc)
{
	int cpu;
	struct ip_vs_stats tmp_stats;
	struct ip_vs_service *this_svc;
	struct nlattr *nl_service;
	struct ip_vs_flags flags = {.flags = svc->flags,
		.mask = ~0
	};

	nl_service = nla_nest_start(skb, IPVS_CMD_ATTR_SERVICE);
	if (!nl_service)
		return -EMSGSIZE;

	NLA_PUT_U16(skb, IPVS_SVC_ATTR_AF, svc->af);

	if (svc->fwmark) {
		NLA_PUT_U32(skb, IPVS_SVC_ATTR_FWMARK, svc->fwmark);
	} else {
		NLA_PUT_U16(skb, IPVS_SVC_ATTR_PROTOCOL, svc->protocol);
		NLA_PUT(skb, IPVS_SVC_ATTR_ADDR, sizeof(svc->addr), &svc->addr);
		NLA_PUT_U16(skb, IPVS_SVC_ATTR_PORT, svc->port);
	}

	NLA_PUT_STRING(skb, IPVS_SVC_ATTR_SCHED_NAME, svc->scheduler->name);
	NLA_PUT(skb, IPVS_SVC_ATTR_FLAGS, sizeof(flags), &flags);
	NLA_PUT_U32(skb, IPVS_SVC_ATTR_TIMEOUT, svc->timeout);
	NLA_PUT_U32(skb, IPVS_SVC_ATTR_NETMASK, svc->netmask);
	NLA_PUT_U32(skb, IPVS_SVC_ATTR_EST_TIMEOUT, svc->est_timeout);

	memset((void*)(&tmp_stats), 0, sizeof(struct ip_vs_stats));
	this_svc = svc->svc0;
	for_each_possible_cpu(cpu) {
		tmp_stats.conns += this_svc->stats.conns;
		tmp_stats.inpkts += this_svc->stats.inpkts;
		tmp_stats.outpkts += this_svc->stats.outpkts;
		tmp_stats.inbytes += this_svc->stats.inbytes;
		tmp_stats.outbytes += this_svc->stats.outbytes;

		this_svc++;
	}

	if (ip_vs_genl_fill_stats(skb, IPVS_SVC_ATTR_STATS, &tmp_stats))
		goto nla_put_failure;

	nla_nest_end(skb, nl_service);

	return 0;

      nla_put_failure:
	nla_nest_cancel(skb, nl_service);
	return -EMSGSIZE;
}

static int ip_vs_genl_get_cmd(struct nl_cache_ops *ops,
                              struct genl_cmd *cmd,
                              struct genl_info *info,
                              void *arg)
{
	struct nl_msg *msg;
	//struct nlattr *nl_attr;
	int ret, cmd_id, reply_cmd;

  (void)arg;
  (void)ops;
	cmd_id = info->genlhdr->cmd;
  
  OFP_INFO("Get command: %s\n", cmd->c_name);

	if (cmd_id == IPVS_CMD_GET_SERVICE)
		reply_cmd = IPVS_CMD_NEW_SERVICE;
	else if (cmd_id == IPVS_CMD_GET_INFO)
		reply_cmd = IPVS_CMD_SET_INFO;
  /*
	else if (cmd_id == IPVS_CMD_GET_CONFIG)
		reply_cmd = IPVS_CMD_SET_CONFIG;
  */
	else {
		OFP_ERR("unknown Generic Netlink command\n");
		return -EINVAL;
	}

  msg = ipvs_nl_message(reply_cmd, 0);
	if (!msg)
		return -ENOMEM;

  switch (cmd_id) {
  case IPVS_CMD_GET_INFO:
		NLA_PUT_U32(msg, IPVS_INFO_ATTR_VERSION, IP_VS_VERSION_CODE);
		NLA_PUT_U32(msg, IPVS_INFO_ATTR_CONN_TAB_SIZE, IP_VS_CONN_TAB_SIZE);
		break;

  case IPVS_CMD_GET_SERVICE:
		{
			struct ip_vs_service *svc;

			svc =
			    ip_vs_genl_find_service(info->
						    attrs
						    [IPVS_CMD_ATTR_SERVICE]);
			if (IS_ERR(svc)) {
				ret = PTR_ERR(svc);
				goto out;
			} else if (svc) {
				ret = ip_vs_genl_fill_service(msg, svc);
			//	ip_vs_service_put(svc);
				if (ret)
					goto nla_put_failure;
			} else {
				ret = -ESRCH;
				goto out;
			}

			break;
		}
  }

	ret = nl_send_auto_complete(sock, msg);
  if (ret < 0)
    OFP_ERR("nl_send_auto_complete return %d\n", ret);
  goto out; 

nla_put_failure:
  pr_err("not enough space in Netlink message\n");
	ret = -EMSGSIZE;

out:
  nlmsg_free(msg);
  return ret;
}

static int ip_vs_genl_dump_laddrs(struct nl_cache_ops *ops,
                              struct genl_cmd *cmd,
                              struct genl_info *info,
                              void *arg)
{
  (void)arg;
  (void)ops;
  OFP_INFO("Dump command: %s\n", cmd->c_name);
  return 0;
}

static int ip_vs_genl_dump_dests(struct nl_cache_ops *ops,
                              struct genl_cmd *cmd,
                              struct genl_info *info,
                              void *arg)
{
  (void)arg;
  (void)ops;
  OFP_INFO("Dump command: %s\n", cmd->c_name);
  return 0;
}

static int ip_vs_genl_dump_daemons(struct nl_cache_ops *ops,
                              struct genl_cmd *cmd,
                              struct genl_info *info,
                              void *arg)
{
  (void)arg;
  (void)ops;
  OFP_INFO("Dump command: %s\n", cmd->c_name);
  return 0;
}

static int ip_vs_genl_dump_services(struct nl_cache_ops *ops,
                              struct genl_cmd *cmd,
                              struct genl_info *info,
                              void *arg)
{
  (void)arg;
  (void)ops;
  OFP_INFO("Dump command: %s\n", cmd->c_name);
  return 0;
}


static int ofp_vs_nl_msg_handler(struct nl_msg *msg, void *arg)
{
  genl_handle_msg(msg, arg);
	return NL_OK;
}


static int ip_vs_genl_set_cmd(struct nl_cache_ops *ops,
                              struct genl_cmd *cmd,
                              struct genl_info *info,
                              void *arg)
{
  int cmd_id = info->genlhdr->cmd;
  (void)arg;
  (void)ops;
  OFP_INFO("Set command: %d %s\n", cmd_id, cmd->c_name);
  return 0;
}


static struct genl_cmd ip_vs_genl_cmds[] = {
  {
    .c_id = IPVS_CMD_NEW_SERVICE,
    .c_name = "IPVS_CMD_NEW_SERVICE",
    .c_maxattr = IPVS_CMD_ATTR_MAX,
    .c_attr_policy = ip_vs_cmd_policy,
    .c_msg_parser = &ip_vs_genl_set_cmd,
  },
	{
	 .c_id = IPVS_CMD_SET_SERVICE,
   .c_name = "IPVS_CMD_SET_SERVICE",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_DEL_SERVICE,
   .c_name = "IPVS_CMD_DEL_SERVICE",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_GET_SERVICE,
   .c_name = "IPVS_CMD_GET_SERVICE",
	 .c_msg_parser = ip_vs_genl_dump_services,
	 .c_attr_policy = ip_vs_cmd_policy,
	 },
	{
	 .c_id = IPVS_CMD_NEW_DEST,
   .c_name = "IPVS_CMD_NEW_DEST",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_SET_DEST,
   .c_name = "IPVS_CMD_SET_DEST",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_DEL_DEST,
   .c_name = "IPVS_CMD_DEL_DEST",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_GET_DEST,
   .c_name = "IPVS_CMD_GET_DEST",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_dump_dests,
	 },
	{
	 .c_id = IPVS_CMD_NEW_DAEMON,
   .c_name = "IPVS_CMD_NEW_DAEMON",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_DEL_DAEMON,
   .c_name = "IPVS_CMD_DEL_DAEMON",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_GET_DAEMON,
   .c_name = "IPVS_CMD_GET_DAEMON",
	 .c_msg_parser = ip_vs_genl_dump_daemons,
	 },
   /*
	{
	 .c_id = IPVS_CMD_SET_CONFIG,
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_GET_CONFIG,
	 .c_msg_parser = ip_vs_genl_get_cmd,
	 },
   */
	{
	 .c_id = IPVS_CMD_GET_INFO,
   .c_name = "IPVS_CMD_GET_INFO",
	 .c_msg_parser = ip_vs_genl_get_cmd,
	 },
	{
	 .c_id = IPVS_CMD_ZERO,
   .c_name = "IPVS_CMD_ZERO",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_FLUSH,
   .c_name = "IPVS_CMD_FLUSH",
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_NEW_LADDR,
   .c_name = "IPVS_CMD_NEW_LADDR",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_DEL_LADDR,
   .c_name = "IPVS_CMD_DEL_LADDR",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_GET_LADDR,
   .c_name = "IPVS_CMD_GET_LADDR",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_dump_laddrs,
	 },
};

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
static struct genl_ops ip_vs_genl_ops = {
   //.o_id = GENL_ID_GENERATE,
	 .o_cmds = ip_vs_genl_cmds,
   .o_name = IPVS_GENL_NAME,
	 .o_ncmds = ARRAY_SIZE(ip_vs_genl_cmds),
};

static int ip_vs_genl_register(void)
{
	return genl_register_family(&ip_vs_genl_ops);
}

static void ip_vs_genl_unregister(void)
{
	genl_unregister_family(&ip_vs_genl_ops);
}

static void free_svc_tab(void)
{
	int cpu;
	struct list_head *ip_vs_svc_tab;

	for_each_possible_cpu(cpu) {
		ip_vs_svc_tab = per_cpu(ip_vs_svc_tab_percpu, cpu);

		/* free NULL is OK  */
		rte_free(ip_vs_svc_tab);
	}
}

static int alloc_svc_tab(void)
{
	int cpu;
	struct list_head *tmp;

	/* clear percpu svc_tab */
	for_each_possible_cpu(cpu) {
		per_cpu(ip_vs_svc_tab_percpu, cpu) = NULL;
	}

	for_each_possible_cpu(cpu) {
		unsigned socket_id = rte_lcore_to_socket_id(cpu);
    
    tmp = rte_malloc_socket("ip_vs_svc_tab",
			sizeof(struct list_head) * IP_VS_SVC_TAB_SIZE,
			0, socket_id);

		if (!tmp) {
			OFP_ERR("cannot allocate svc_tab.\n");
			return -ENOMEM;
		}

		per_cpu(ip_vs_svc_tab_percpu, cpu) = tmp;
	}

	return 0;
}

int ofp_vs_ctl_init(odp_instance_t instance, ofp_init_global_t *app_init_params)
{
  int ret;

  sock = nl_socket_alloc();
  if (NULL == sock) {
    ret = -ENOMEM;
    OFP_ERR("ip_vs_genl_register failed\n");
    goto cleanup;
  }

  nl_socket_set_nonblocking(sock);
  nl_socket_set_local_port(sock, 101);
  genl_connect(sock);

  if ((ret = ip_vs_genl_register()) < 0) {
    OFP_ERR("ip_vs_genl_register failed\n");
    goto cleanup; 
  }

  if ((ret = genl_ops_resolve(sock, &ip_vs_genl_ops)) < 0) {
    OFP_ERR("genl_osp_resolve return %d\n", ret);
    goto cleanup_genl; 
  }

  if (genl_ctrl_resolve(sock, "nlctrl") != GENL_ID_CTRL) {
		OFP_ERR("Resolving of \"nlctrl\" failed");
    goto cleanup_genl; 
  }

  if ((ipvs_genl_family = genl_ctrl_resolve(sock, IPVS_GENL_NAME)) < 0)
		goto cleanup_genl;

  nl_socket_set_peer_port(sock, 100);
  
  if ((ret = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
                          ofp_vs_nl_msg_handler, NULL)) != 0) {
    OFP_ERR("nl_socket_modify_cb failed %s\n", strerror(errno));
		goto cleanup_genl;
  }

  nl_socket_disable_seq_check(sock);

  ret = alloc_svc_tab();
	if (ret) {
		goto cleanup_svctab;
	}

	/* ofp_vs_ctl thread */
	ofp_vs_ctl_thread_start(instance, app_init_params->linux_core_id);

  OFP_INFO("ofp_vs_ctl_init ok\n");
  return ret;
  
cleanup_svctab:
	free_svc_tab();
cleanup_genl:
  ip_vs_genl_unregister(); 
cleanup:
  if (sock) {
    nl_close(sock);
    nl_socket_free(sock);
    sock = NULL;
  }
  return ret;
}

void ofp_vs_ctl_finish(void)
{
	free_svc_tab();
  ip_vs_genl_unregister();
 
  if (sock) {
    OFP_DBG("close nl sock\n");
    nl_close(sock);
    nl_socket_free(sock);
  }
  //odph_linux_pthread_join(&ofp_vs_ctl_thread, 1);
}
