/*
 * net/sched/act_pop.c
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Author:	Eli Cohen <eli@mellnaox.com>
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <net/act_api.h>
#include <net/netlink.h>
#include <linux/tc_act/tc_pop.h>
#include <net/tc_act/tc_pop.h>

MODULE_AUTHOR("Eli Cohen");
MODULE_DESCRIPTION("pop actions");
MODULE_LICENSE("GPL");

static unsigned int pop_net_id;
static struct tc_action_ops act_pop_ops;

static const struct nla_policy pop_policy[TCA_POP_MAX + 1] = {
	[TCA_POP_PARMS]	= { .len = sizeof(struct tc_pop) },
};

static int tcf_pop_init(struct net *net, struct nlattr *nla,
			struct nlattr *est, struct tc_action **a,
			int ovr, int bind)
{
	struct tc_action_net *tn = net_generic(net, pop_net_id);
	struct nlattr *tb[TCA_POP_MAX + 1];
	struct tc_pop *parm;
	struct tcf_pop *pop;
	int ret = 0;
	int err;

	if (!nla)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_POP_MAX, nla, pop_policy, NULL);
	if (err < 0)
		return err;

	if (!tb[TCA_POP_PARMS])
		return -EINVAL;

	parm = nla_data(tb[TCA_POP_PARMS]);
	if (!parm)
		return -EINVAL;

	if (parm->pt >= POP_TYPE_MAX)
		return -EINVAL;

	if (!tcf_idr_check(tn, parm->index, a, bind)) {
		ret = tcf_idr_create(tn, parm->index, est, a,
				     &act_pop_ops, bind, true);
		if (ret)
			return ret;
		ret = ACT_P_CREATED;
	} else {
		if (bind)/* dont override defaults */
			return 0;
		tcf_idr_release(*a, bind);
		if (!ovr)
			return -EEXIST;
	}
	pop = to_pop(*a);
	pop->type = parm->pt;

	ASSERT_RTNL();
	pop->tcf_action = parm->action;

	if (ret == ACT_P_CREATED)
		tcf_idr_insert(tn, *a);

	return ret;
}

static int tcf_pop_search(struct net *net, struct tc_action **a, u32 index)
{
	struct tc_action_net *tn = net_generic(net, pop_net_id);

	return tcf_idr_search(tn, a, index);
}

static int tcf_pop_walker(struct net *net, struct sk_buff *skb,
			  struct netlink_callback *cb, int type,
			  const struct tc_action_ops *ops)
{
	struct tc_action_net *tn = net_generic(net, pop_net_id);

	return tcf_generic_walker(tn, skb, cb, type, ops);
}

static int tcf_pop_dump(struct sk_buff *skb, struct tc_action *a,
			int bind, int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tcf_pop *pop = to_pop(a);
	struct tc_pop opt = {
		.index	  = pop->tcf_index,
		.refcnt	  = pop->tcf_refcnt - ref,
		.bindcnt  = pop->tcf_bindcnt - bind,
		.action	  = pop->tcf_action,
		.pt	  = pop->type,
	};
	struct tcf_t t;

	if (nla_put(skb, TCA_POP_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;

	tcf_tm_dump(&t, &pop->tcf_tm);
	if (nla_put_64bit(skb, TCA_POP_TM, sizeof(t), &t, TCA_POP_PAD))
		goto nla_put_failure;

	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_pop_act(struct sk_buff *skb, const struct tc_action *a,
		       struct tcf_result *res)
{
	struct tcf_pop *pop = to_pop(a);
	int action = READ_ONCE(pop->tcf_action);

	bstats_cpu_update(this_cpu_ptr(pop->common.cpu_bstats), skb);

	tcf_lastuse_update(&pop->tcf_tm);

	return action;
}

static struct tc_action_ops act_pop_ops = {
	.kind		=	"pop",
	.type		=	TCA_ACT_POP,
	.owner		=	THIS_MODULE,
	.act		=	tcf_pop_act,
	.init		=	tcf_pop_init,
	.lookup		=	tcf_pop_search,
	.walk		=	tcf_pop_walker,
	.dump		=	tcf_pop_dump,
	.size		=	sizeof(struct tcf_pop),
};

static __net_init int pop_init_net(struct net *net)
{
	struct tc_action_net *tn = net_generic(net, pop_net_id);

	return tc_action_net_init(net, tn, &act_pop_ops);
}

static void __net_exit pop_exit_net(struct net *net)
{
	struct tc_action_net *tn = net_generic(net, pop_net_id);

	tc_action_net_exit(tn);
}

static struct pernet_operations pop_net_ops = {
	.init = pop_init_net,
	.exit = pop_exit_net,
	.id   = &pop_net_id,
	.size = sizeof(struct tc_action_net),
};

static int __init pop_init_module(void)
{
	return tcf_register_action(&act_pop_ops, &pop_net_ops);
}

static void __exit pop_cleanup_module(void)
{
	tcf_unregister_action(&act_pop_ops, &pop_net_ops);
}

module_init(pop_init_module);
module_exit(pop_cleanup_module);
