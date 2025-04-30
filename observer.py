#!/usr/bin/env python3

from bcc import BPF
from time import sleep
import ctypes as ct
import socket, struct
import ipaddress

with open("observer.bpf.c", "r") as file:
    program = file.read()

b = BPF(text=program)

def get_ip_from_int(int_ip):
    ip = ipaddress.ip_address(int_ip)
    return ".".join(str(ip).split(".")[::-1])

def display_ban_table():
    s = "\n===========\n"
    s += "IP \t\t Ban Reason\n"
    for k, v in b["bad_ips"].items():
        reason = "Ping Flood" if v.value == 1 else "SYN Flood Attack"
        ip = get_ip_from_int(k.value)
        s += f"{ip} \t {reason}\t\n"
    s += "\n===========\n"
    print(s)

while True:
    print("Options:\n1. Show Banned Ips\n2. Unban IP \n3. Unban all IPs")
    option = input("Enter choice: ")
    if option == "1":
        display_ban_table()
    elif option == "2":
        ip_list = [k.value for k,v in b["bad_ips"].items()]
        print("Select IP to remove:\n")
        for i in range(len(ip_list)):
            print(f"{i+1}. {get_ip_from_int(ip_list[i])}")
        ip_choice = int(input("Enter IP choice: "))-1
        b["bad_ips"].pop(ct.c_uint32(ip_list[ip_choice]))
        print("IP unbanned, current banned IPs:")
        display_ban_table()
    elif option == "3":
        for k, v in b["bad_ips"].items():
            b["bad_ips"].pop(ct.c_uint32(k.value))
            print(f"Removed ip: {get_ip_from_int(k.value)}\n")
        print("All entries removed")
    else:
        print("Invalid option, choose again")