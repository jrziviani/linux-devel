/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_TC_PUSH_H
#define __LINUX_TC_PUSH_H

#include <linux/types.h>
#include <linux/pkt_cls.h>

#define TCA_ACT_PUSH 27

enum push_type {
	PUSH_TYPE_MPLS,
	PUSH_TYPE_ETH,
	PUSH_TYPE_MAX
};

struct tc_push {
	tc_gen;
	enum push_type	pt;
};

enum {
	TCA_PUSH_UNSPEC,
	TCA_PUSH_TM,
	TCA_PUSH_PARMS,
	TCA_PUSH_MPLS_LABEL,
	TCA_PUSH_MPLS_TC,
	TCA_PUSH_MPLS_BOS,
	TCA_PUSH_MPLS_TTL,
	TCA_PUSH_ETH_DMAC,
	TCA_PUSH_ETH_SMAC,
	TCA_PUSH_ETH_PROT,
	TCA_PUSH_PAD,
	__TCA_PUSH_MAX
};

#define TCA_PUSH_MAX (__TCA_PUSH_MAX - 1)

#endif
