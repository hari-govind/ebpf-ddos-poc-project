#!/usr/bin/env python3

from bcc import BPF
from time import sleep

with open("defender.bpf.c", "r") as file:
    program = file.read()

b = BPF(text=program)
fn = b.load_func("process_packet", BPF.XDP)
b.attach_xdp("bridge1", fn, 0)

#syscall = b.get_syscall_fnname("execve")
#b.attach_kprobe(event=syscall, fn_name="hello")

while True:
    sleep(2)
    s = ""
    for k, v in b["bad_ips"].items():
        s += f"ID {k.value}: {v.value}\t"
    print("\n"+s)
    s = ""
    for k, v in b["syn_flood_counter"].items():
        s += f"IP:Count {k.value}: {v.open_syn_count}\t"
    print("\n"+s)