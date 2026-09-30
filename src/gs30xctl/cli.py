"""
Command-line interface.

    gs30xctl --host 192.168.1.2 login      # log in once, cache the session
    gs30xctl --host 192.168.1.2 info
    gs30xctl --host 192.168.1.2 poe status
    gs30xctl --host 192.168.1.2 poe cycle 3 4
    gs30xctl --host 192.168.1.2 vlan add 10
    gs30xctl --host 192.168.1.2 vlan set-membership 10 U,U,N,N,T
    gs30xctl --host 192.168.1.2 pvid set 1 10
    gs30xctl --host 192.168.1.2 logout     # clear the cached session

Any command logs in automatically if there's no cached session; `login` is
just the most efficient way to start a batch. The password comes from
--password, the NETGEAR_PASSWORD env var, or an interactive prompt.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys

import requests

from . import cache
from .client import Switch
from .exceptions import SwitchError
from .models import MODELS, get_model
from .vlan import membership_to_labels


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gs30xctl",
        description="Control NETGEAR GS305E/GS305EP/GS305EPP/GS308E/GS308EP/GS308EPP switches.",
    )
    p.add_argument("--host", required=True, help="switch IP address or hostname")
    p.add_argument("--password", help="admin password (or set NETGEAR_PASSWORD env var)")
    p.add_argument("--model", type=str.upper, choices=sorted(MODELS),
                   help="switch model (default: auto-detect)")
    p.add_argument("--debug", action="store_true", help="log raw HTTP request/response details")
    p.add_argument("--no-cache", action="store_true",
                   help="don't reuse/save a cached session token; always log in fresh "
                        "(slower, and more likely to hit the switch's login throttle)")

    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("login", help="log in and cache the session token for later commands")
    sub.add_parser("logout", help="clear the cached session token for this host")
    sub.add_parser("info", help="show the detected model, port count and PoE ports")

    poe = sub.add_parser("poe", help="PoE port control (PoE models only)")
    poe_sub = poe.add_subparsers(dest="poe_command", required=True)
    poe_sub.add_parser("status", help="show PoE power/voltage/current per port")
    poe_sub.add_parser("settings", help="show PoE configuration per port")
    poe_sub.add_parser("on", help="turn PoE power on for a port").add_argument("port", type=int)
    poe_sub.add_parser("off", help="turn PoE power off for a port").add_argument("port", type=int)
    poe_sub.add_parser("cycle", help="power-cycle one or more PoE ports").add_argument(
        "ports", type=int, nargs="+")

    vlan = sub.add_parser("vlan", help="802.1Q VLAN control")
    vlan_sub = vlan.add_subparsers(dest="vlan_command", required=True)
    vlan_sub.add_parser("status", help="show whether 802.1Q is enabled + VLAN IDs")
    vlan_sub.add_parser("enable", help="enable 802.1Q VLAN mode")
    vlan_sub.add_parser("disable", help="disable 802.1Q VLAN mode")
    vlan_sub.add_parser("add", help="create a VLAN").add_argument("vid", type=int)
    vlan_sub.add_parser("delete", help="delete a VLAN").add_argument("vid", type=int)
    vlan_sub.add_parser("show-membership", help="show port membership for a VLAN").add_argument(
        "vid", type=int)
    set_p = vlan_sub.add_parser(
        "set-membership",
        help="set port membership for a VLAN, e.g. 'U,U,N,N,T' (one entry per port)")
    set_p.add_argument("vid", type=int)
    set_p.add_argument("membership", help="comma-separated: U=untagged T=tagged N=none")

    pvid = sub.add_parser("pvid", help="port default VLAN ID (PVID)")
    pvid_sub = pvid.add_subparsers(dest="pvid_command", required=True)
    pvid_sub.add_parser("show", help="show PVID for all ports")
    pvid_set = pvid_sub.add_parser("set", help="set PVID for a port")
    pvid_set.add_argument("port", type=int)
    pvid_set.add_argument("vid", type=int)

    sub.add_parser(
        "discover",
        help="diagnostic: scan the switch's menu pages for .cgi endpoint names "
             "(use this if 'vlan'/'pvid' commands 404 on your firmware)")

    dump_p = sub.add_parser(
        "dump", help="diagnostic: fetch a raw *.cgi page and print its forms/inputs/links")
    dump_p.add_argument("path", help="page to fetch, e.g. 8021qCf.cgi")
    dump_p.add_argument("--full-html", action="store_true",
                        help="also print the full raw HTML (can be long)")
    return p


def _dispatch(args, sw: Switch):
    if args.command == "login":
        sw.login()
        print(f"Logged in to {args.host} ({sw.model.name})")

    elif args.command == "info":
        print(sw.model)

    elif args.command == "poe":
        if args.poe_command == "status":
            for p in sw.get_poe_status():
                print(p)
        elif args.poe_command == "settings":
            for p in sw.get_poe_settings():
                print(p)
        elif args.poe_command in ("on", "off"):
            sw.set_poe_port(args.port, power=(args.poe_command == "on"))
            state = "enabled" if sw.get_poe_port_setting(args.port).power_enabled else "disabled"
            print(f"Port {args.port}: PoE {args.poe_command.upper()} requested -> now power={state}")
        elif args.poe_command == "cycle":
            sw.poe_cycle(args.ports)
            print(f"Cycled ports: {args.ports}")

    elif args.command == "vlan":
        if args.vlan_command == "status":
            print("802.1Q enabled:", sw.get_dot1q_enabled())
            print("VLAN IDs:", sw.get_vlan_ids())
        elif args.vlan_command in ("enable", "disable"):
            sw.set_dot1q_enabled(args.vlan_command == "enable")
            print(f"802.1Q VLAN mode {args.vlan_command}d")
        elif args.vlan_command == "add":
            sw.add_vlan(args.vid)
            print(f"VLAN {args.vid} added")
        elif args.vlan_command == "delete":
            sw.delete_vlan(args.vid)
            print(f"VLAN {args.vid} deleted")
        elif args.vlan_command == "show-membership":
            for i, lab in enumerate(membership_to_labels(sw.get_vlan_membership(args.vid)), start=1):
                print(f"Port {i}: {lab}")
        elif args.vlan_command == "set-membership":
            sw.set_vlan_membership(args.vid, args.membership)
            print(f"VLAN {args.vid} membership updated: {args.membership}")

    elif args.command == "pvid":
        if args.pvid_command == "show":
            for port, vid in sorted(sw.get_port_pvids().items()):
                print(f"Port {port}: PVID={vid}")
        elif args.pvid_command == "set":
            sw.set_port_pvid(args.port, args.vid)
            print(f"Port {args.port}: PVID set to {args.vid}")

    elif args.command == "discover":
        print(json.dumps(sw.discover_cgi_endpoints(), indent=2))

    elif args.command == "dump":
        result = sw.dump_page(args.path)
        if not args.full_html:
            result.pop("html")
        print(json.dumps(result, indent=2))


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="[%(name)s] %(message)s")

    if args.command == "logout":
        cache.clear_session(args.host)
        print(f"Cleared cached session for {args.host}")
        return 0

    def password_provider() -> str:
        return (args.password or os.environ.get("NETGEAR_PASSWORD")
                or getpass.getpass(f"Password for {args.host}: "))

    cached = {} if args.no_cache else cache.load_session(args.host)
    model = args.model or cached.get("model")
    sw = Switch(args.host, model=get_model(model) if model else None,
                password_provider=password_provider)
    if cached.get("sid") and args.command != "login":
        logging.getLogger(__name__).debug("reusing cached session token for %s", args.host)
        sw.adopt_session(cached["sid"])

    try:
        _dispatch(args, sw)
    except (SwitchError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except requests.RequestException as e:
        print(f"Network error: {e}", file=sys.stderr)
        return 1
    finally:
        # Persist whatever session is active so the next invocation can reuse it.
        if not args.no_cache and sw.session_id:
            cache.save_session(args.host, sw.session_id,
                               sw._model.name if sw._model else None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
