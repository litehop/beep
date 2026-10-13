#include <linux/bpf.h>
extern int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags, struct bpf_dynptr *ptr) __attribute__((section(".ksyms")));
extern void *bpf_dynptr_slice(const struct bpf_dynptr *p, __u32 offset, void *buffer, __u32 buffer__szk) __attribute__((section(".ksyms")));

__attribute__((always_inline)) int beep_dynptr_from_skb(struct __sk_buff *skb, __u64 flags, struct bpf_dynptr *ptr) {
  return bpf_dynptr_from_skb(skb, flags, ptr);
}
__attribute__((always_inline)) void *beep_dynptr_slice(const struct bpf_dynptr *p, __u32 offset, void *buffer, __u32 buffer__szk) {
  return bpf_dynptr_slice(p, offset, buffer, buffer__szk);
}
