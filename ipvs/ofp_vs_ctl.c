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

#include "ofp.h"
#include "ofp_vs.h"
#include "ip_vs.h"

static struct nl_sock *sock = NULL;

static void *ofp_vs_ctl(void *arg)
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
  
  OFP_INFO("ofp_vs_ctl thread is running.\n");
  while (*is_running) {
    if ((err = -nl_recvmsgs_default(sock)) > 0) {
      OFP_ERR("nl_recvmsgs_default return %d %s\n", err, strerror(errno));
      goto out;
    }
	}

out:

  OFP_INFO("ofp_vs_ctl exiting");
	return NULL;
}

static odph_linux_pthread_t ofp_vs_ctl_thread;
void ofp_vs_ctl_thread_start(odp_instance_t instance, int core_id)
{
	odp_cpumask_t cpumask;
	odph_linux_thr_params_t thr_params;

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, core_id);

	thr_params.start = ofp_vs_ctl;
	thr_params.arg = NULL;
	thr_params.thr_type = ODP_THREAD_CONTROL;
	thr_params.instance = instance;
	odph_linux_pthread_create(&ofp_vs_ctl_thread,
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
	[IPVS_CMD_ATTR_SNATDEST] = {.type = NLA_NESTED},
	[IPVS_CMD_ATTR_SNATIP] = {.type = NLA_NESTED},
}; 

static int ip_vs_genl_set_cmd(struct nl_cache_ops *ops,
                              struct genl_cmd *cmd,
                              struct genl_info *info,
                              void *arg)
{
  OFP_INFO("Set command: %s\n", cmd->c_name);
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
    .c_name = "ip_vs_new_service",
    .c_maxattr = IPVS_CMD_ATTR_MAX,
    .c_attr_policy = ip_vs_cmd_policy,
    .c_msg_parser = &ip_vs_genl_set_cmd,
  },
};

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



int ofp_vs_ctl_init(void)
{
  int ret;

  sock = nl_socket_alloc();
  if (NULL == sock) {
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
    goto cleanup; 
  }

  if (genl_ctrl_resolve(sock, "nlctrl") != GENL_ID_CTRL) {
		OFP_ERR("Resolving of \"nlctrl\" failed");
    goto cleanup; 
  }
  
  if ((ret = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
                          ofp_vs_nl_msg_handler, NULL)) != 0) {
    OFP_ERR("nl_socket_modify_cb failed %s\n", strerror(errno));
		goto cleanup;
  }

  nl_socket_disable_seq_check(sock);

  OFP_INFO("ofp_vs_ctl_init ok, sock port:%u\n", nl_socket_get_local_port(sock));
  return ret;

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
  if (sock) {
    nl_close(sock);
    nl_socket_free(sock);
    sock = NULL;
  }
  ip_vs_genl_unregister();
  odph_linux_pthread_join(&ofp_vs_ctl_thread, 1);
}
