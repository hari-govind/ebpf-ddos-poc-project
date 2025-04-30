BPF_TABLE_PINNED("hash", u32, u32, bad_ips, 1024, "/sys/fs/bpf/bad_ips");


int hello(void *ctx) {
  return 0;
}
