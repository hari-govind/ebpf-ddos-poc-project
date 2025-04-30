# eBPF-DDoS-PoC-Project
A simple eBPF program using BCC Python that defends againist SYN flood and Ping flood attacks.
## Usage
- Make sure that bcc is installed([bcc/INSTALL.md](https://github.com/iovisor/bcc/blob/master/INSTALL.md)).
- Run the protector app: `./app.py`. By default it will attach to interface `bridge1`.
- Run the observer app: `./observer.py` to view and manage banned IPs.
## Testing
Use hping3 to test SYN flood and ping flood:
- `hping3 -i u1000 -S -c 100 -p 1234 10.0.0.7`
- `hping3 -1 -i u10000 -c 250 10.0.0.7`
## References
- [eBPF Maps](https://docs.ebpf.io/linux/concepts/maps/)
- [BCC reference guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)
- [Tailoring eBPF maps for DDoS Protection](https://netdevconf.info/0x18/sessions/talk/tailoring-ebpf-maps-for-ddos-protection.html)
- [SYN Flood Attack Detection and Defense Method Based on Extended Berkeley Packet Filter](https://link.springer.com/chapter/10.1007/978-3-030-89698-0_145)
- [Ping (ICMP) flood DDoS attack](https://www.cloudflare.com/learning/ddos/ping-icmp-flood-ddos-attack/)
