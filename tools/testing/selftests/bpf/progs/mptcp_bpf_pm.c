// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Your Name */
#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

// 定义事件结构
struct pm_event {
	int type;
	char data[100];
};

// 定义用于从用户空间接收事件的映射
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 10);
	__type(value, struct pm_event);
} event_queue SEC(".maps");

// 用于存储处理结果的映射
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__type(key, int);
	__type(value, int);
} result_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} trigger_map SEC(".maps");

SEC("fentry/mptcp_push_pending_msk")
int BPF_PROG(trace_mptcp_push_pending, struct mptcp_sock *msk)
{
	struct pm_event e;
	int *trigger;
	int zero = 0;
	int key = 0;
	int result;

	trigger = bpf_map_lookup_elem(&trigger_map, &key);
	if (!trigger || *trigger == 0)
		return 0; // 没有触发信号，直接返回

	// 重置触发信号
	bpf_map_update_elem(&trigger_map, &key, &zero, BPF_ANY);

	// 尝试从队列中获取事件（轮询）
	if (bpf_map_pop_elem(&event_queue, &e))
		return 0;

	// 处理事件
	bpf_printk("BPF processing event type: %d, data: %s", e.type, e.data);

	// 根据事件类型进行处理
	if (e.type == 1) {
		result = msk->token; // 示例处理结果
	} else if (e.type == 2) {
		result = 200; // 示例处理结果
	} else {
		result = 300; // 默认处理结果
	}

	// 存储处理结果
	bpf_map_update_elem(&result_map, &key, &result, BPF_ANY);
	key++;

	return 0;
}
