# gs30xctl

Python library + CLI for NETGEAR **GS305E, GS305EP, GS305EPP, GS308E, GS308EP
and GS308EPP** "Plus" switches: PoE control, 802.1Q VLANs and port PVIDs, driven
through the switch's web UI (these models have no SSH/REST API).

| Model    | Ports | PoE ports | PoE budget |
|----------|-------|-----------|------------|
| GS305E   | 5     | –         | –          |
| GS305EP  | 5     | 1–4       | 63 W       |
| GS305EPP | 5     | 1–4       | 120 W      |
| GS308E   | 8     | –         | –          |
| GS308EP  | 8     | 1–8       | 62 W       |
| GS308EPP | 8     | 1–8       | 123 W      |

The model is auto-detected from the login page; pass `model=` / `--model` to override.

## Install

    pip install .          # or: pip install -e '.[test]'

## Library

```python
from gs30xctl import Switch, UnsupportedFeatureError

with Switch("192.168.1.2", "mypassword") as sw:
    print(sw.model)                          # GS308EP (8 ports, PoE on ports 1-8 ...)

    sw.set_dot1q_enabled(True)
    sw.add_vlan(10)
    sw.set_vlan_membership(10, "U,U,N,N,N,N,N,T")   # one entry per port
    sw.set_port_pvid(1, 10)

    if sw.model.has_poe:
        for p in sw.get_poe_status():
            print(p)
        sw.poe_cycle([3, 4])
```

PoE methods raise `UnsupportedFeatureError` on GS305E/GS308E, and `ValueError`
for a port without PoE (e.g. port 5 on a GS305EP). Debug output goes through the
`gs30xctl` logger.

For long-lived processes, reuse sessions with `sw.session_id` / `sw.adopt_session(sid)`;
the switch allows only one web session at a time.

## CLI

    gs30xctl --host 192.168.1.2 login          # log in once; token cached in ~/.cache/gs30xctl/
    gs30xctl --host 192.168.1.2 info
    gs30xctl --host 192.168.1.2 poe status
    gs30xctl --host 192.168.1.2 poe off 3
    gs30xctl --host 192.168.1.2 vlan enable
    gs30xctl --host 192.168.1.2 vlan add 10
    gs30xctl --host 192.168.1.2 vlan set-membership 10 U,U,N,N,T
    gs30xctl --host 192.168.1.2 pvid set 1 10
    gs30xctl --host 192.168.1.2 logout

Password: `--password`, the `NETGEAR_PASSWORD` env var, or an interactive prompt.
`discover` and `dump <page.cgi>` help work out endpoint/field names on unfamiliar firmware.

## Tests

    pytest     # offline; uses a fake HTTP session
