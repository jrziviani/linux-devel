/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_TC_POP_H
#define __LINUX_TC_POP_H

#include <linux/types.h>
#include <linux/pkt_cls.h>

#define TCA_ACT_POP 28

enum pop_type {
	POP_TYPE_MPLS,
	POP_TYPE_ETH,
	POP_TYPE_MAX
};

struct tc_pop {
	tc_gen;
	enum pop_type	pt;
};

enum {
	TCA_POP_UNSPEC,
	TCA_POP_TM,
	TCA_POP_PAD,
	TCA_POP_PARMS,
	__TCA_POP_MAX
};

#define TCA_POP_MAX (__TCA_POP_MAX - 1)

#endif
