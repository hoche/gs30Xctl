# Reaching same-IP devices on separate VLANs (Linux)

How to put several devices that all use the **same IP address** on one switch,
each in its own VLAN, and reach each one individually from a single Linux host.

The examples use a GS305E, devices at `192.168.255.10` on ports 1–4, and the
host cabled to port 5. Everything on the host side needs root.

## 1. Switch layout

| Port | Role            | VLAN membership                         | PVID |
|------|-----------------|-----------------------------------------|------|
| 1    | device A        | VLAN 10 untagged                        | 10   |
| 2    | device B        | VLAN 20 untagged                        | 20   |
| 3    | device C        | VLAN 30 untagged                        | 30   |
| 4    | device D        | VLAN 40 untagged                        | 40   |
| 5    | trunk to host   | VLANs 10–40 tagged, VLAN 1 untagged     | 1    |

```bash
export NETGEAR_PASSWORD='...'
SW="gs30xctl --host 192.168.0.239"

$SW vlan enable
for v in 10 20 30 40; do $SW vlan add $v; done

# one letter per port (1..5): U=untagged, T=tagged, N=not a member
$SW vlan set-membership 10 U,N,N,N,T
$SW vlan set-membership 20 N,U,N,N,T
$SW vlan set-membership 30 N,N,U,N,T
$SW vlan set-membership 40 N,N,N,U,T

$SW pvid set 1 10
$SW pvid set 2 20
$SW pvid set 3 30
$SW pvid set 4 40

# last: take ports 1-4 out of VLAN 1, keep port 5 for management
$SW vlan set-membership 1 N,N,N,N,U
```

- Set PVIDs **before** removing ports from VLAN 1; the firmware may refuse to
  remove a port from the VLAN its PVID points at.
- The switch's web UI (and so `gs30xctl`) is only reachable on VLAN 1. Run
  these from a machine on port 5, and give the switch an IP distinct from the
  devices.
- The host's NIC must connect **directly** to port 5. A router in between
  drops the tagged frames, while untagged traffic to the switch still works,
  which makes the failure confusing.

## 2. One network namespace per VLAN

Because every device has the same IP, each VLAN interface goes in its own
network namespace; otherwise the host has several routes to the same address.

```bash
# port 1 = VLAN 10; NIC cabled to switch port 5 is enp12s0
ip netns add dev10
ip link add link enp12s0 name vlan10 type vlan id 10
ip link set vlan10 netns dev10
ip -n dev10 addr add 192.168.255.1/24 dev vlan10
ip -n dev10 link set lo up
ip -n dev10 link set vlan10 up

ip netns exec dev10 ping 192.168.255.10
```

`scripts/vlan-ns.sh` does this for any port (port N → VLAN N×10, namespace
`devN0`, interface `vlanN0`):

```bash
scripts/vlan-ns.sh up 2                          # PARENT=... HOST_IP=... to override
scripts/vlan-ns.sh exec 2 ping 192.168.255.10
scripts/vlan-ns.sh down 2
```

`scripts/move-to-enp12s0.sh` rebuilds existing namespaces on another NIC
(`FROM=... TO=...`).

Notes:

- Interface names are limited to 15 characters, so `enx803f5dd33402.10`
  won't fit; use short names like `vlan10`.
- Only one VLAN device per (parent NIC, VLAN ID) can exist. "VLAN device
  already exists" means a leftover is around; find it with
  `ip -d link show | grep -B1 'id 10 '`. If NetworkManager or netplan owns it,
  remove it there or it will come back.
- If the parent NIC disappears (e.g. a USB NIC is unplugged), its VLAN devices
  are deleted and the namespaces are left empty. Rerun `vlan-ns.sh up`.
- None of this survives a reboot; run the script from a systemd unit if needed.

### Troubleshooting

`Destination Host Unreachable` from `192.168.255.1` means ARP got no answer.

```bash
tcpdump -eni enp12s0 vlan 10                     # tagged who-has frames leaving?
gs30xctl --host 192.168.0.239 vlan show-membership 10
gs30xctl --host 192.168.0.239 pvid show
```

- Tagged ARPs leave but no reply: check cabling (host on port 5, device on
  port N), the switch membership/PVID, and the device's actual IP.
- Nothing appears: check the VLAN interface is `UP` in the namespace. On
  USB NICs using `r8152`, try `ethtool -K <nic> rxvlan off txvlan off`.

## 3. Running programs against a VLAN

Programs don't need to know about VLANs; run them inside the namespace.

```bash
ip netns exec dev10 iperf3 -c 192.168.255.10     # device on port 1
ip netns exec dev20 iperf3 -s                    # device on port 2 connects to 192.168.255.1
ip netns exec dev10 bash                         # shell where everything uses VLAN 10
```

Concurrent tests share the single host↔port 5 link, so their totals are capped
by that link.

## 4. Socket servers

**One process per VLAN** (simplest): write an ordinary server bound to
`0.0.0.0` and start one copy per namespace with `ip netns exec`.

**One process for all VLANs**: create each socket while switched into the
target namespace. A socket stays in the namespace it was created in. Needs
root (CAP_SYS_ADMIN). Python 3.12+:

```python
import os, socket, selectors

def socket_in_netns(ns, *args):
    """Create a socket inside network namespace `ns` (e.g. 'dev10')."""
    home = os.open("/proc/self/ns/net", os.O_RDONLY)
    target = os.open(f"/run/netns/{ns}", os.O_RDONLY)
    try:
        os.setns(target, os.CLONE_NEWNET)
        return socket.socket(*args)
    finally:
        os.setns(home, os.CLONE_NEWNET)
        os.close(target)
        os.close(home)

sel = selectors.DefaultSelector()
for port, ns in [(1, "dev10"), (2, "dev20"), (3, "dev30"), (4, "dev40")]:
    s = socket_in_netns(ns, socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("192.168.255.1", 5000))   # same address in each namespace, no conflict
    s.listen()
    sel.register(s, selectors.EVENT_READ, data=port)

while True:
    for key, _ in sel.select():
        conn, addr = key.fileobj.accept()
        print(f"switch port {key.data}: connection from {addr}")
        conn.sendall(b"hello\n")
        conn.close()
```

The listener that accepted a connection identifies the switch port. Client
sockets work the same way. In C use `setns()`; in Go, call
`runtime.LockOSThread()` first.

`SO_BINDTODEVICE` with all VLAN interfaces in one namespace is not recommended:
shared routing, ARP and neighbour tables for identical subnets need
`arp_ignore`/`arp_filter` and policy routing to behave.

## 5. Per-device alias IPs (no namespace awareness at all)

Link each namespace to the main namespace with a veth pair and NAT inside the
namespace, so each device gets a unique address in the main namespace:

```
main namespace                    namespace devN0                     switch port N
10.99.N.1 ── veth ── 10.99.N.2   [NAT]   vlanN0 192.168.255.1 ── VLAN N0 ── device 192.168.255.10
  device appears as 10.10.N.10
```

- Host → device: connect to `10.10.N.10`.
- Device → host: the device connects to `192.168.255.1`; a server in the main
  namespace sees the client as `10.10.N.10`, which identifies the port.

After `scripts/vlan-ns.sh up N`:

```bash
N=1; NS=dev$((N*10)); VL=vlan$((N*10))

ip link add v$N-host type veth peer name v$N-ns
ip link set v$N-ns netns $NS
ip addr add 10.99.$N.1/30 dev v$N-host && ip link set v$N-host up
ip -n $NS addr add 10.99.$N.2/30 dev v$N-ns && ip -n $NS link set v$N-ns up

ip route add 10.10.$N.0/24 via 10.99.$N.2

ip netns exec $NS sysctl -qw net.ipv4.ip_forward=1
ip netns exec $NS sh -c "
  # host -> device: 10.10.N.x becomes 192.168.255.x, sourced from 192.168.255.1
  iptables -t nat -A PREROUTING  -i v$N-ns -d 10.10.$N.0/24 -j NETMAP --to 192.168.255.0/24
  iptables -t nat -A POSTROUTING -o $VL -j MASQUERADE
  # device -> host: connections to 192.168.255.1 go to the host, source shown as 10.10.N.x
  iptables -t nat -A PREROUTING  -i $VL -d 192.168.255.1 -j DNAT --to-destination 10.99.$N.1
  iptables -t nat -A POSTROUTING -o v$N-ns -s 192.168.255.0/24 -j NETMAP --to 10.10.$N.0/24
"
```

Then, with no `ip netns exec`:

```bash
ping 10.10.1.10
iperf3 -c 10.10.2.10
python3 -m http.server 8080      # devices reach it at 192.168.255.1:8080
```

Caveats:

- Only unicast TCP/UDP/ICMP crosses the NAT; broadcast/multicast discovery
  (mDNS, SSDP, DHCP) does not.
- Protocols that embed IP addresses in their payload (FTP, SIP, some vendor
  discovery) may break.
- All traffic to `192.168.255.1` inside the namespace is sent to the host,
  including pings.
- Pick other ranges if `10.10.0.0/16` or `10.99.0.0/16` are already in use.
- Deleting the namespace (`vlan-ns.sh down N`) removes the NAT rules and the
  veth pair (both ends), and with it the main-namespace route.
