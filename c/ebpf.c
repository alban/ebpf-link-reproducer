#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct bpf_map_def SEC("maps") connections = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(__u64),
  .value_size = sizeof(__u64),
  .max_entries = 1024,
};

struct bpf_iter_meta {
	__bpf_md_ptr(struct seq_file *, seq);
	__u64 session_id;
	__u64 seq_num;
};
struct bpf_iter__bpf_map_elem {
        __bpf_md_ptr(struct bpf_iter_meta *, meta);
        __bpf_md_ptr(struct bpf_map *, map);
        __bpf_md_ptr(void *, key);
        __bpf_md_ptr(void *, value);
};

/* From: tools/lib/bpf/bpf_tracing.h */
/*
 * BPF_SEQ_PRINTF to wrap bpf_seq_printf to-be-printed values
 * in a structure.
 */
#define BPF_SEQ_PRINTF(seq, fmt, args...)				    \
	({								    \
		_Pragma("GCC diagnostic push")				    \
		_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")	    \
		static const char ___fmt[] = fmt;			    \
		unsigned long long ___param[] = { args };		    \
		_Pragma("GCC diagnostic pop")				    \
		int ___ret = bpf_seq_printf(seq, ___fmt, sizeof(___fmt),    \
					    ___param, sizeof(___param));    \
		___ret;							    \
	})

SEC("iter/bpf_map_elem")
int dump_connections(struct bpf_iter__bpf_map_elem *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	__u32 seq_num = ctx->meta->seq_num;
	__u64 *key = ctx->key;
	__u64 *val = ctx->value;
	if (seq_num == 0)
		BPF_SEQ_PRINTF(seq, "--begin--\n");

	if (key == (void *)0 || val == (void *)0) {
		BPF_SEQ_PRINTF(seq, "--end--\n");
		return 0;
	}
	BPF_SEQ_PRINTF(seq, "key: %llu\n", *key);
	BPF_SEQ_PRINTF(seq, "val: %llu\n", *val);

	return 0;
}

char _license[] SEC("license") = "GPL";
