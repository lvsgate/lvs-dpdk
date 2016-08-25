/**
 * Copyright (c) 2016 lvsgate@163.com
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_VS_H__
#define __OFP_VS_H__

#include "ofp.h"

#include <rte_config.h>
#include <rte_malloc.h>
#include <rte_byteorder.h>

#include "ofp_vs_kern_compat.h"
#include "kern_list.h"
#include "net/ip_vs.h"


int ofp_vs_init(odp_instance_t instance, ofp_init_global_t *app_init_params);
void ofp_vs_finish(void);
void ofp_vs_ctl_thread_start(odp_instance_t instance, int core_id);
int ofp_vs_ctl_init(odp_instance_t instance, ofp_init_global_t *app_init_params);
void ofp_vs_ctl_finish(void);

#define IP_VS_CONN_TAB_BITS	20
#define IP_VS_CONN_TAB_SIZE     (1 << IP_VS_CONN_TAB_BITS)
#define IP_VS_CONN_TAB_MASK     (IP_VS_CONN_TAB_SIZE - 1)

#endif
