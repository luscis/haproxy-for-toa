// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Easystack */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#define TCP_TOA_OPTLEN_IPV4	8

struct tcp_toa_option {
	__u8 kind;
	__u8 len;
	__u16 port;
	__u32 addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __be32);
	__type(value, struct tcp_toa_option);
} toa_conn_store SEC(".maps");


SEC("sockops")
int set_toa_tcp_bs(struct bpf_sock_ops *skops) {
	int rv = -1;
	int option_len = 0;
	int op = (int) skops->op;
	struct bpf_sock *sk = skops->sk;
	struct tcp_toa_option opt;
	struct tcp_toa_option *data = NULL;

	if (!sk)
		goto RET;

	data = bpf_sk_storage_get(&toa_conn_store, sk, NULL, 0);
	if (!data)
		goto RET;

	switch (op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		bpf_sock_ops_cb_flags_set(skops,
			skops->bpf_sock_ops_cb_flags |
			BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
		break;

	case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
		rv = 0;
		option_len = TCP_TOA_OPTLEN_IPV4;

		if (skops->args[1] + option_len <= 40) {
			rv = option_len;
		}

		bpf_reserve_hdr_opt(skops, rv, 0);
		break;

	case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
		opt.kind = data->kind;
		opt.len  = TCP_TOA_OPTLEN_IPV4;
		opt.port = data->port;
		opt.addr = data->addr;

		bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0);

		bpf_sock_ops_cb_flags_set(skops,
			skops->bpf_sock_ops_cb_flags &
			~BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
		break;

	default:
		rv = -1;
	}

RET:
	skops->reply = rv;

	return 1;
}

char _license[] SEC("license") = "GPL";
