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

/*
 *	Hash table: for virtual service lookups
 */
#define IP_VS_SVC_TAB_BITS 12
#define IP_VS_SVC_TAB_SIZE (1 << IP_VS_SVC_TAB_BITS)
#define IP_VS_SVC_TAB_MASK (IP_VS_SVC_TAB_SIZE - 1)

/* the service table hashed by <protocol, addr, port> */
DEFINE_PER_CPU(struct list_head *, ip_vs_svc_tab_percpu);

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
    if ((err = -nl_recvmsgs_default(sock)) > 0 && (err != NLE_AGAIN)) {
      OFP_ERR("nl_recvmsgs_default return %d %s\n", err, strerror(errno));
      goto out;
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
static const struct nla_policy ip_vs_cmd_policy[IPVS_CMD_ATTR_MAX + 1] = {
	[IPVS_CMD_ATTR_SERVICE] = {.type = NLA_NESTED},
	[IPVS_CMD_ATTR_DEST] = {.type = NLA_NESTED},
	[IPVS_CMD_ATTR_DAEMON] = {.type = NLA_NESTED},
	[IPVS_CMD_ATTR_TIMEOUT_TCP] = {.type = NLA_U32},
	[IPVS_CMD_ATTR_TIMEOUT_TCP_FIN] = {.type = NLA_U32},
	[IPVS_CMD_ATTR_TIMEOUT_UDP] = {.type = NLA_U32},
	[IPVS_CMD_ATTR_LADDR] = {.type = NLA_NESTED},
}; 

static int ip_vs_genl_set_cmd(struct nl_cache_ops *ops,
                              struct genl_cmd *cmd,
                              struct genl_info *info,
                              void *arg)
{
  int cmd_id = info->genlhdr->cmd;
  OFP_INFO("Set command: %d %s\n", cmd_id, cmd->c_name);
  return 0;
}

static int ip_vs_genl_get_cmd(struct nl_cache_ops *ops,
                              struct genl_cmd *cmd,
                              struct genl_info *info,
                              void *arg)
{
  void *reply;
	int ret, cmd_id, reply_cmd;

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

  return 0;
}

static int ip_vs_genl_dump_laddrs(struct nl_cache_ops *ops,
                              struct genl_cmd *cmd,
                              struct genl_info *info,
                              void *arg)
{
  
  OFP_INFO("Dump command: %s\n", cmd->c_name);
  return 0;
}

static int ip_vs_genl_dump_dests(struct nl_cache_ops *ops,
                              struct genl_cmd *cmd,
                              struct genl_info *info,
                              void *arg)
{
  OFP_INFO("Dump command: %s\n", cmd->c_name);
  return 0;
}

static int ip_vs_genl_dump_daemons(struct nl_cache_ops *ops,
                              struct genl_cmd *cmd,
                              struct genl_info *info,
                              void *arg)
{
  OFP_INFO("Dump command: %s\n", cmd->c_name);
  return 0;
}

static int ip_vs_genl_dump_services(struct nl_cache_ops *ops,
                              struct genl_cmd *cmd,
                              struct genl_info *info,
                              void *arg)
{
  OFP_INFO("Dump command: %s\n", cmd->c_name);
  return 0;
}


static int ofp_vs_nl_msg_handler(struct nl_msg *msg, void *arg)
{
  genl_handle_msg(msg, NULL);
	return NL_OK;
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
	 .c_msg_parser = ip_vs_genl_get_cmd,
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
