#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define PING_THRESHOLD 500
#define PING_TIME_WINDOW_NS 1000000000 // 1sec in ns

#define OPEN_SYN_THRESHOLD 100
#define OPEN_SYN_RESET_INTERVAL 10000000000 // 10sec in ns
#define SYN_FLOOD_TIME_WINDOW_NS 5000000000 // 5sec in ns

enum TCP_FLAG_TYPE {
  SYN, ACK, SYN_ACK, OTH
};

// BPF_HASH(counter_table);

BPF_TABLE_PINNED("hash", u32, u32, bad_ips, 1024, "/sys/fs/bpf/bad_ips");

struct ping_flood_entry {
  u64 last_update;
  u32 packet_count;
};
BPF_HASH(rate_limit_map, u32, struct ping_flood_entry, 1024);

struct syn_flood_entry {
  u32 open_syn_count;
  u64 start_time_window;
  u64 last_update;
};

BPF_HASH(syn_flood_counter, u32, struct syn_flood_entry, 1024);


static __always_inline unsigned char lookup_protocol(struct xdp_md *ctx) {
  unsigned char protocol = 0;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  if (data + sizeof(struct ethhdr) > data_end)
    return 0;
  // Check that it's an IP packet
  if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
    // Return the protocol of this packet
    // 1 = ICMP
    // 6 = TCP
    // 17 = UDP
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end)
      protocol = iph->protocol;
  }
  return protocol;
}

int process_packet(struct xdp_md *ctx) {
  //bpf_trace_printk("got a packet");

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct iphdr *iph = data + sizeof(struct ethhdr);
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
    bpf_trace_printk("aborted");
    return XDP_ABORTED;
  }

  u32 src_ip = iph->saddr;
  u32 val = 1;
  u32 val_syn_ban = 2;

  if (bad_ips.lookup(&src_ip) != NULL) {
    bpf_trace_printk("dropped, bad ip match");
    return XDP_DROP;
  }

  long packet_type = lookup_protocol(ctx);

  if (packet_type == IPPROTO_ICMP) {
    bpf_trace_printk("got UDP packet");
      struct ping_flood_entry *entry = rate_limit_map.lookup(&src_ip);
      u64 current_time = bpf_ktime_get_ns();
      if (entry) {
        if (current_time - entry->last_update < PING_TIME_WINDOW_NS) {
          entry->packet_count++;
          if (entry->packet_count > PING_THRESHOLD) {
            bad_ips.update(&src_ip, &val);
            return XDP_DROP;
          }
        } else {
          entry->last_update = current_time;
          entry->packet_count = 1;
        }
      } else {
        struct ping_flood_entry new_entry;
        __builtin_memset(&new_entry, 0, sizeof(new_entry));
        new_entry.last_update = current_time;
        new_entry.packet_count = 1;
        rate_limit_map.update(&src_ip, &new_entry);
      }
    return XDP_PASS;
  }

  if(packet_type == IPPROTO_TCP) { //TCP
    //bpf_trace_printk("got tcp packet");
  struct syn_flood_entry *entry = syn_flood_counter.lookup(&src_ip);
  u64 current_time = bpf_ktime_get_ns();
  //struct tcphdr *tcp = (struct tcphdr *)((unsigned char *)iph + sizeof(iph));
  struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  if ((void *)(tcp + 1) > data_end) {
    bpf_trace_printk("tcp aborted");
      return XDP_ABORTED;
  }
  
  enum TCP_FLAG_TYPE flag_type = OTH;
  //bpf_trace_printk("TCP seq num %d", tcp->seq);

  if(tcp->syn && tcp->ack) {
    //bpf_trace_printk("got tcp syn ack");
    flag_type = SYN_ACK;
  } else if(tcp->syn) {
    //bpf_trace_printk("syn");
    flag_type = SYN;
  } else if(tcp->ack) {
    //bpf_trace_printk("ack");
    flag_type = ACK;
  }
  //bpf_trace_printk("Flag type: %d", flag_type);
  if(flag_type == SYN || flag_type == ACK) {
    if (entry) {
      if(flag_type == SYN){
        if(current_time - entry->start_time_window  > OPEN_SYN_RESET_INTERVAL) {
          bpf_trace_printk("Map reset, interval elapsed");
          entry->start_time_window = current_time;
          entry->last_update = current_time;
          entry->open_syn_count = 1;
          return XDP_PASS;
        }
        if (current_time - entry->last_update < SYN_FLOOD_TIME_WINDOW_NS) {
          entry->open_syn_count++;
          entry->last_update = current_time;
          if (entry->open_syn_count > OPEN_SYN_THRESHOLD) {
            bad_ips.update(&src_ip, &val_syn_ban);
            return XDP_DROP;
          }
        } else {
          bpf_trace_printk("Map reset, time window");
          entry->last_update = current_time;
          entry->open_syn_count = 1;
        }
      } else {
        //bpf_trace_printk("Ack received, incrementing source %d", src_ip);
        //bpf_trace_printk("Ack received, destination %d", iph->daddr);
        if(entry->open_syn_count>0) {
          entry->open_syn_count--;
        } else {
          syn_flood_counter.delete(&src_ip);
        }
        return XDP_PASS;
      }
    } else {
      struct syn_flood_entry new_entry;
      __builtin_memset(&new_entry, 0, sizeof(new_entry));
      new_entry.last_update = current_time;
      new_entry.start_time_window = current_time;
      new_entry.open_syn_count = 1;
      syn_flood_counter.update(&src_ip, &new_entry);
    }
  }
}
  

  return XDP_PASS;
}
