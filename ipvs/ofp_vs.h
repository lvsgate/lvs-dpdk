/**
 * Copyright (c) 2016 lvsgate@163.com
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_VS_H__
#define __OFP_VS_H__

#include "ofp.h"

int ofp_vs_init(void);
void ofp_vs_finish(void);
void ofp_vs_ctl_thread_start(odp_instance_t instance, int core_id);
int ofp_vs_ctl_init(void);
void ofp_vs_ctl_finish(void);

#endif
