// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/*
 * Test configurations
 */
#define BACKEND_MAC			mac_one
#define BACKEND_ROUTER_MAC		mac_two
#define CLIENT_IP			v4_pod_one
#define BACKEND_IP			v4_pod_two
#define CLIENT_NODE_IP			v4_ext_one
#define BACKEND_PORT			tcp_src_one
#define CLIENT_INTER_CLUSTER_SNAT_PORT	tcp_src_two
#define CLIENT_CLUSTER_ID		1
#define CLIENT_IDENTITY			(0x00000000 | (CLIENT_CLUSTER_ID << 16) | 0xff01)

/*
 * Datapath configurations
 */

/* Set dummy ifindex for tunnel device */
#define ENCAP_IFINDEX 1

/* Overlapping PodCIDR is only supported for IPv4 for now */
#define ENABLE_IPV4

/* Overlapping PodCIDR depends on tunnel */
#define TUNNEL_MODE

/* Fully enable KPR since kubeproxy doesn't understand cluster aware addressing */
#define ENABLE_NODEPORT

/* Cluster-aware addressing is mandatory for overlapping PodCIDR support */
#define ENABLE_CLUSTER_AWARE_ADDRESSING

/* Import some default values */

/* Import map definitions and some default values */
#include <bpf/config/node.h>

/* Overwrite (local) CLUSTER_ID defined in node_config.h */
#undef CLUSTER_ID
#define CLUSTER_ID 1

/* Need to undef EVENT_SOURCE here since it is defined in
 * both of common.h and bpf_lxc.c.
 */
#undef EVENT_SOURCE

/* Include an actual datapath code */
#include <bpf_lxc.c>

/* Set the LXC source address to be the address of the backend pod */
ASSIGN_CONFIG(__u32, endpoint_ipv4, BACKEND_IP)

#include "lib/ipcache.h"
#include "lib/policy.h"

/*
 * Tests
 */

#define FROM_CONTAINER 0
#define HANDLE_POLICY 1

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_CONTAINER] = &cil_from_container,
		[HANDLE_POLICY] = &handle_policy,
	},
};

static __always_inline int
pktgen_to_lxc(struct __ctx_buff *ctx, bool syn, bool ack)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)BACKEND_ROUTER_MAC,
					  (__u8 *)BACKEND_MAC,
					  CLIENT_NODE_IP, BACKEND_IP,
					  CLIENT_INTER_CLUSTER_SNAT_PORT, BACKEND_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = syn ? 1 : 0;
	l4->ack = ack ? 1 : 0;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

static __always_inline int
pktgen_from_lxc(struct __ctx_buff *ctx, bool syn, bool ack)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)BACKEND_MAC,
					  (__u8 *)BACKEND_ROUTER_MAC,
					  BACKEND_IP, CLIENT_NODE_IP,
					  BACKEND_PORT, CLIENT_INTER_CLUSTER_SNAT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = syn ? 1 : 0;
	l4->ack = ack ? 1 : 0;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

PKTGEN("tc", "01_overlay_to_lxc_syn")
int overlay_to_lxc_syn_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_to_lxc(ctx, true, false);
}

SETUP("tc", "01_overlay_to_lxc_syn")
int overlay_to_lxc_syn_setup(struct __ctx_buff *ctx)
{
	/*
	 * Apply policy based on the remote "real"
	 * identity instead of remote-node identity.
	 */
	policy_add_ingress_allow_entry(CLIENT_IDENTITY, IPPROTO_TCP, BACKEND_PORT);

	/* Emulate metadata filled by ipv4_local_delivery on bpf_overlay */
	local_delivery_fill_meta(ctx, CLIENT_IDENTITY, true, false, true, 0);

	tail_call_static(ctx, entry_call_map, HANDLE_POLICY);

	return TEST_ERROR;
}

CHECK("tc", "01_overlay_to_lxc_syn")
int overlay_to_lxc_syn_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct ipv4_ct_tuple tuple;
	struct ct_entry *entry;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_REDIRECT)
		test_fatal("unexpected status code %d, want %d", *status_code, CTX_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)BACKEND_ROUTER_MAC, ETH_ALEN) != 0)
		test_fatal("src MAC has changed")

	if (memcmp(l2->h_dest, (__u8 *)BACKEND_MAC, ETH_ALEN) != 0)
		test_fatal("dst MAC has changed")

	if (l3->saddr != CLIENT_NODE_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP has changed");

	if (l3->check != bpf_htons(0x4111))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	if (l4->source != CLIENT_INTER_CLUSTER_SNAT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port has changed");

	if (l4->check != bpf_htons(0x1df4))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	/* Check ingress conntrack state is in the default CT */
	tuple.daddr   = CLIENT_NODE_IP;
	tuple.saddr   = BACKEND_IP;
	tuple.dport   = BACKEND_PORT;
	tuple.sport   = CLIENT_INTER_CLUSTER_SNAT_PORT;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.flags   = TUPLE_F_IN;

	entry = map_lookup_elem(&cilium_ct4_global, &tuple);
	if (!entry)
		test_fatal("couldn't find ingress conntrack entry");

	if (!entry->from_tunnel)
		test_fatal("from_tunnel flag is not set on ingress conntrack entry");

	if (entry->src_sec_id != CLIENT_IDENTITY)
		test_fatal("src_security_identity is not client identity");

	test_finish();
}

PKTGEN("tc", "02_lxc_to_overlay_synack")
int lxc_to_overlay_synack_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_lxc(ctx, true, true);
}

SETUP("tc", "02_lxc_to_overlay_synack")
int lxc_to_overlay_synack_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry_with_flags(CLIENT_NODE_IP, 0, REMOTE_NODE_ID,
					CLIENT_NODE_IP, 0, true);

	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);

	return TEST_ERROR;
}

CHECK("tc", "02_lxc_to_overlay_synack")
int lxc_to_overlay_ack_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct ipv4_ct_tuple tuple;
	struct ct_entry *entry;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_REDIRECT)
		test_fatal("unexpected status code %d, want %d", *status_code, CTX_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)BACKEND_MAC, ETH_ALEN) != 0)
		test_fatal("src MAC has changed");

	if (memcmp(l2->h_dest, (__u8 *)BACKEND_ROUTER_MAC, ETH_ALEN) != 0)
		test_fatal("dst MAC has changed");

	if (l3->saddr != BACKEND_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != CLIENT_NODE_IP)
		test_fatal("dst IP has changed");

	if (l3->check != bpf_htons(0x4111))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	if (l4->source != BACKEND_PORT)
		test_fatal("src port has changed");

	if (l4->dest != CLIENT_INTER_CLUSTER_SNAT_PORT)
		test_fatal("dst port has changed");

	if (l4->check != bpf_htons(0x1de4))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	/* Make sure we hit the conntrack entry */
	tuple.saddr   = BACKEND_IP;
	tuple.daddr   = CLIENT_NODE_IP;
	tuple.dport   = BACKEND_PORT;
	tuple.sport   = CLIENT_INTER_CLUSTER_SNAT_PORT;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.flags   = TUPLE_F_IN;

	entry = map_lookup_elem(&cilium_ct4_global, &tuple);
	if (!entry)
		test_fatal("couldn't find egress conntrack entry");

	if (entry->packets != 2)
		test_fatal("tx packet didn't hit conntrack entry");

	test_finish();
}

PKTGEN("tc", "03_overlay_to_lxc_ack")
int overlay_to_lxc_ack_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_to_lxc(ctx, false, true);
}

SETUP("tc", "03_overlay_to_lxc_ack")
int overlay_to_lxc_ack_setup(struct __ctx_buff *ctx)
{
	/* Emulate metadata filled by ipv4_local_delivery on bpf_overlay */
	local_delivery_fill_meta(ctx, CLIENT_IDENTITY, true, false, true, 0);

	tail_call_static(ctx, entry_call_map, HANDLE_POLICY);

	return TEST_ERROR;
}

CHECK("tc", "03_overlay_to_lxc_ack")
int overlay_to_lxc_ack_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct ipv4_ct_tuple tuple;
	struct ct_entry *entry;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_REDIRECT)
		test_fatal("unexpected status code %d, want %d", *status_code, CTX_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)BACKEND_ROUTER_MAC, ETH_ALEN) != 0)
		test_fatal("src MAC has changed")

	if (memcmp(l2->h_dest, (__u8 *)BACKEND_MAC, ETH_ALEN) != 0)
		test_fatal("dst MAC has changed")

	if (l3->saddr != CLIENT_NODE_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP has changed");

	if (l3->check != bpf_htons(0x4111))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	if (l4->source != CLIENT_INTER_CLUSTER_SNAT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port has changed");

	if (l4->check != bpf_htons(0x1de6))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	/* Make sure we hit the conntrack entry */
	tuple.daddr   = CLIENT_NODE_IP;
	tuple.saddr   = BACKEND_IP;
	tuple.dport   = BACKEND_PORT;
	tuple.sport   = CLIENT_INTER_CLUSTER_SNAT_PORT;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.flags   = TUPLE_F_IN;

	entry = map_lookup_elem(&cilium_ct4_global, &tuple);
	if (!entry)
		test_fatal("couldn't find ingress conntrack entry");

	if (entry->packets != 3)
		test_fatal("rx packet didn't hit conntrack entry");

	test_finish();
}
