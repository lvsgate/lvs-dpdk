/*
 * Copyright (c) 2016, lvsgate@163.com
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <getopt.h>
#include <string.h>
#include <signal.h>

#include "ofp.h"

#include "ofp_vs.h"

int ofp_vs_init(void)
{
	int ret;

	if ((ret = ofp_vs_ctl_init()) < 0)
		return ret;
}

void ofp_vs_finish(void)
{
  ofp_vs_ctl_finish();
}
