/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_POP_H
#define __NET_TC_POP_H

#include <net/act_api.h>
#include <linux/tc_act/tc_pop.h>

struct tcf_pop {
	struct tc_action	common;
	enum pop_type		type;
};

#define to_pop(a) ((struct tcf_pop *)a)

static inline bool is_tcf_pop(const struct tc_action *a)
{
#ifdef CONFIG_NET_CLS_ACT
	if (a->ops && a->ops->type != TCA_ACT_POP)
		return false;

	return true;
#endif
	return false;
}

#endif /* __NET_TC_POP_H */
