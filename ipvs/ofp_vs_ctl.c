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

#include "ofp.h"
#include "ofp_vs.h"

static void *ofp_vs_ctl(void *arg)
{
  (void)arg;

  while (1) {
		sleep(1);
	}

  OFP_INFO("ofp_vs_ctl exiting");
	return NULL;
}

static odph_linux_pthread_t ofp_vs_ctl_thread;
void ofp_vs_start_ctl_thread(odp_instance_t instance, int core_id)
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
