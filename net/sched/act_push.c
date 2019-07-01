/*
 * net/sched/act_push.c	?????????
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
#include <linux/tc_act/tc_push.h>
#include <net/tc_act/tc_push.h>

MODULE_AUTHOR("Eli Cohen");
MODULE_DESCRIPTION("push actions");
MODULE_LICENSE("GPL");

static unsigned int push_net_id;
static struct tc_action_ops act_push_ops;

#define to_push(a) ((struct tcf_push *)a)

static const struct nla_policy push_policy[TCA_PUSH_MAX + 1] = {
	[TCA_PUSH_PARMS]	= { .len = sizeof(struct tc_push) },
	[TCA_PUSH_MPLS_LABEL]	= { .type = NLA_U32 },
	[TCA_PUSH_MPLS_TC]	= { .type = NLA_U8 },
	[TCA_PUSH_MPLS_BOS]	= { .type = NLA_U8 },
	[TCA_PUSH_MPLS_TTL]	= { .type = NLA_U8 },
	[TCA_PUSH_ETH_DMAC]	= { .len = ETH_ALEN },
	[TCA_PUSH_ETH_SMAC]	= { .len = ETH_ALEN },
	[TCA_PUSH_ETH_PROT]	= { .len = NLA_U16 },
};

static int extract_push_mpls(struct nlattr *tb[], struct tcf_push *push)
{
	push->type = PUSH_TYPE_MPLS;

	if (!tb[TCA_PUSH_MPLS_LABEL])
		return -EINVAL;
	push->mpls.label = nla_get_u32(tb[TCA_PUSH_MPLS_LABEL]);
	if (push->mpls.label & 0xfff00000)
		return -EINVAL;

	if (!tb[TCA_PUSH_MPLS_TC])
		return -EINVAL;

	push->mpls.tc = nla_get_u8(tb[TCA_PUSH_MPLS_TC]);
	if (push->mpls.tc & 0xf8)
		return -EINVAL;

	if (!tb[TCA_PUSH_MPLS_BOS])
		return -EINVAL;
	push->mpls.bos = nla_get_u8(tb[TCA_PUSH_MPLS_BOS]);

	if (!tb[TCA_PUSH_MPLS_TTL])
		return -EINVAL;
	push->mpls.ttl = nla_get_u8(tb[TCA_PUSH_MPLS_TTL]);

	return 0;
}

static int extract_push_eth(struct nlattr *tb[], struct tcf_push *push)
{
	void *addr;

	push->type = PUSH_TYPE_ETH;

	addr = nla_data(tb[TCA_PUSH_ETH_DMAC]);
	if (!addr)
		return -EINVAL;
	ether_addr_copy(push->eth.dmac, addr);

	addr = nla_data(tb[TCA_PUSH_ETH_SMAC]);
	if (!addr)
		return -EINVAL;
	ether_addr_copy(push->eth.smac, addr);

	if (!tb[TCA_PUSH_ETH_PROT])
		return -EINVAL;
	push->eth.prot = nla_get_be16(tb[TCA_PUSH_ETH_PROT]);

	return 0;
}

static int tcf_push_init(struct net *net, struct nlattr *nla,
			 struct nlattr *est, struct tc_action **a,
			 int ovr, int bind)
{
	struct tc_action_net *tn = net_generic(net, push_net_id);
	struct nlattr *tb[TCA_PUSH_MAX + 1];
	struct tc_push *parm;
	struct tcf_push *push;
	int ret = 0;
	int err;

	if (!nla)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_PUSH_MAX, nla, push_policy, NULL);
	if (err < 0)
		return err;

	if (!tb[TCA_PUSH_PARMS])
		return -EINVAL;

	parm = nla_data(tb[TCA_PUSH_PARMS]);
	if (!parm)
		return -EINVAL;

	if (parm->pt >= PUSH_TYPE_MAX)
		return -EINVAL;

	if (!tcf_idr_check(tn, parm->index, a, bind)) {
		ret = tcf_idr_create(tn, parm->index, est, a,
				     &act_push_ops, bind, true);
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
	push = to_push(*a);

	if (parm->pt == PUSH_TYPE_MPLS)
		err = extract_push_mpls(tb, push);
	else
		err = extract_push_eth(tb, push);

	if (err)
		goto parm_err;

	ASSERT_RTNL();
	push->tcf_action = parm->action;

	if (ret == ACT_P_CREATED)
		tcf_idr_insert(tn, *a);

	return ret;

parm_err:
	if (ret == ACT_P_CREATED)
		tcf_idr_release(*a, bind);

	return err;
}

static int tcf_push_search(struct net *net, struct tc_action **a, u32 index)
{
	struct tc_action_net *tn = net_generic(net, push_net_id);

	return tcf_idr_search(tn, a, index);
}

static int tcf_push_walker(struct net *net, struct sk_buff *skb,
			   struct netlink_callback *cb, int type,
			   const struct tc_action_ops *ops)
{
	struct tc_action_net *tn = net_generic(net, push_net_id);

	return tcf_generic_walker(tn, skb, cb, type, ops);
}

static int tcf_push_dump(struct sk_buff *skb, struct tc_action *a,
			 int bind, int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tcf_push *push = to_push(a);
	struct tc_push opt = {
		.index	  = push->tcf_index,
		.refcnt	  = push->tcf_refcnt - ref,
		.bindcnt  = push->tcf_bindcnt - bind,
		.action	  = push->tcf_action,
		.pt	  = push->type,
	};
	struct tcf_t t;

	if (nla_put(skb, TCA_PUSH_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;

	if (push->type == PUSH_TYPE_MPLS) {
		if (nla_put_u32(skb, TCA_PUSH_MPLS_LABEL, push->mpls.label))
			goto nla_put_failure;
		if (nla_put_u8(skb, TCA_PUSH_MPLS_TC, push->mpls.tc))
			goto nla_put_failure;
		if (nla_put_u8(skb, TCA_PUSH_MPLS_BOS, push->mpls.bos))
			goto nla_put_failure;
		if (nla_put_u8(skb, TCA_PUSH_MPLS_TTL, push->mpls.ttl))
			goto nla_put_failure;
	} else {
		if (nla_put(skb, TCA_PUSH_ETH_DMAC, ETH_ALEN, push->eth.dmac))
			goto nla_put_failure;
		if (nla_put(skb, TCA_PUSH_ETH_SMAC, ETH_ALEN, push->eth.smac))
			goto nla_put_failure;
		if (nla_put_be16(skb, TCA_PUSH_ETH_PROT, push->eth.prot))
			goto nla_put_failure;
	}

	tcf_tm_dump(&t, &push->tcf_tm);
	if (nla_put_64bit(skb, TCA_PUSH_TM, sizeof(t), &t, TCA_PUSH_PAD))
		goto nla_put_failure;

	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_push_act(struct sk_buff *skb, const struct tc_action *a,
			struct tcf_result *res)
{
	struct tcf_push *push = to_push(a);
	int action = READ_ONCE(push->tcf_action);

	bstats_cpu_update(this_cpu_ptr(push->common.cpu_bstats), skb);

	tcf_lastuse_update(&push->tcf_tm);

	return action;
}

static struct tc_action_ops act_push_ops = {
	.kind		=	"push",
	.type		=	TCA_ACT_PUSH,
	.owner		=	THIS_MODULE,
	.act		=	tcf_push_act,
	.init		=	tcf_push_init,
	.lookup		=	tcf_push_search,
	.walk		=	tcf_push_walker,
	.dump		=	tcf_push_dump,
	.size		=	sizeof(struct tcf_push),
};

static __net_init int push_init_net(struct net *net)
{
	struct tc_action_net *tn = net_generic(net, push_net_id);

	return tc_action_net_init(net, tn, &act_push_ops);
}

static void __net_exit push_exit_net(struct net *net)
{
	struct tc_action_net *tn = net_generic(net, push_net_id);

	tc_action_net_exit(tn);
}

static struct pernet_operations push_net_ops = {
	.init = push_init_net,
	.exit = push_exit_net,
	.id   = &push_net_id,
	.size = sizeof(struct tc_action_net),
};

static int __init push_init_module(void)
{
	int err;

	err = tcf_register_action(&act_push_ops, &push_net_ops);
	return err;
}

static void __exit push_cleanup_module(void)
{
	tcf_unregister_action(&act_push_ops, &push_net_ops);
}

module_init(push_init_module);
module_exit(push_cleanup_module);
