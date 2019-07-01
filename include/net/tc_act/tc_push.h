/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_PUSH_H
#define __NET_TC_PUSH_H

#include <net/act_api.h>
#include <linux/tc_act/tc_push.h>

struct tcf_push {
	struct tc_action	common;
	enum push_type		type;
	union {
		struct {
			u32	label;
			u8	tc;
			bool	bos;
			u8	ttl;
		} mpls;
		struct {
			u8	dmac[ETH_ALEN];
			u8	smac[ETH_ALEN];
			u16	prot;
		} eth;
	};
};

#define to_push(a) ((struct tcf_push *)a)

static inline bool is_tcf_push(const struct tc_action *a)
{
#ifdef CONFIG_NET_CLS_ACT
	if (a->ops && a->ops->type != TCA_ACT_PUSH)
		return false;

	return true;
#endif
	return false;
}

#endif /* __NET_TC_PUSH_H */
