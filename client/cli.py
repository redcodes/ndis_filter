import argparse
import sys

from dns_spoof_driver import (
    DNS_SPOOF_DEFAULT_TTL,
    DnsSpoofDriverClient,
    DnsSpoofRule,
    flush_dns_cache,
)
from driver_manager import DriverManagerError, NdisLwfDriverManager
from redirect_driver import (
    DriverError,
    RedirectDriverClient,
    RedirectRule,
    RuleNameStore,
    protocol_from_text,
)


def cmd_list(args):
    client = RedirectDriverClient()
    store = RuleNameStore()
    rules = client.list_rules()
    store.prune([r.rule_id for r in rules])
    store.apply_names(rules)

    if not rules:
        print("no rules")
        return 0

    for rule in rules:
        extra = f" options={rule.options_text}" if rule.options_text != "-" else ""
        print(
            f"id={rule.rule_id} "
            f"name={rule.display_name} "
            f"family={rule.address_family_text} "
            f"protocol={rule.protocol_text} "
            f"orig={rule.orig_ip}:{rule.orig_port} "
            f"new={rule.new_ip}:{rule.new_port}"
            f"{extra}"
        )
    return 0


def cmd_add(args):
    client = RedirectDriverClient()
    store = RuleNameStore()
    rule = RedirectRule(
        rule_id=args.id,
        name=args.name or "",
        orig_ip=args.target_host,
        orig_port=args.target_port,
        new_ip=args.redirect_host,
        new_port=args.redirect_port,
        protocol=protocol_from_text(args.protocol),
        new_dst_mac=args.mac or "",
        local_loopback=args.local,
    )
    created = client.add_rule(rule)
    if args.name:
        store.set(created.rule_id, args.name)
    print(f"added rule id={created.rule_id}")
    return 0


def cmd_update(args):
    client = RedirectDriverClient()
    store = RuleNameStore()
    rule = RedirectRule(
        rule_id=args.rule_id,
        name=args.name or "",
        orig_ip=args.target_host,
        orig_port=args.target_port,
        new_ip=args.redirect_host,
        new_port=args.redirect_port,
        protocol=protocol_from_text(args.protocol),
        new_dst_mac=args.mac or "",
        local_loopback=args.local,
    )
    updated = client.update_rule(rule)
    if args.name is not None:
        store.set(updated.rule_id, args.name)
    print(f"updated rule id={updated.rule_id}")
    return 0


def cmd_delete(args):
    client = RedirectDriverClient()
    store = RuleNameStore()
    client.delete_rule(args.rule_id)
    store.delete(args.rule_id)
    print(f"deleted rule id={args.rule_id}")
    return 0


def cmd_clear(args):
    client = RedirectDriverClient()
    store = RuleNameStore()
    client.clear_rules()
    store.clear()
    print("cleared all redirect rules")
    return 0


def cmd_driver_status(args):
    mgr = NdisLwfDriverManager()
    st = mgr.query_status()
    print(
        f"state={st.state.value} "
        f"installed={st.installed} "
        f"running={st.running} "
        f"device_ready={st.device_ready} "
        f"is_admin={st.is_admin} "
        f"summary={st.summary}"
    )
    return 0


def cmd_driver_install(args):
    mgr = NdisLwfDriverManager()
    st = mgr.install(inf_path=args.inf, sys_path=args.sys, start_after_install=not args.no_start)
    print(f"installed state={st.state.value} running={st.running} reboot_required={st.reboot_required}")
    return 0


def cmd_driver_uninstall(args):
    mgr = NdisLwfDriverManager()
    st = mgr.uninstall()
    print(f"uninstalled state={st.state.value} reboot_required={st.reboot_required}")
    return 0


def cmd_driver_start(args):
    mgr = NdisLwfDriverManager()
    st = mgr.start()
    print(f"started state={st.state.value} running={st.running} device_ready={st.device_ready}")
    return 0


def cmd_driver_stop(args):
    mgr = NdisLwfDriverManager()
    st = mgr.stop()
    print(f"stopped state={st.state.value} running={st.running}")
    return 0


def cmd_dns_list(args):
    client = DnsSpoofDriverClient()
    rules = client.list_rules()
    if not rules:
        print("no dns spoof rules")
        return 0
    for rule in rules:
        print(
            f"id={rule.rule_id} "
            f"domain={rule.domain} "
            f"ipv4={rule.ipv4_text} "
            f"ipv6={rule.ipv6_text} "
            f"ttl={rule.ttl}"
        )
    return 0


def cmd_dns_add(args):
    client = DnsSpoofDriverClient()
    rule = DnsSpoofRule(
        rule_id=args.id,
        domain=args.domain,
        fake_ipv4=args.ipv4 or "",
        fake_ipv6=args.ipv6 or "",
        ttl=args.ttl,
        wildcard=args.wildcard,
    )
    created = client.add_rule(rule, flush_cache=not args.no_flush)
    print(
        f"added dns rule id={created.rule_id} domain={created.domain} "
        f"ipv4={created.ipv4_text} ipv6={created.ipv6_text} ttl={created.ttl}"
    )
    return 0


def cmd_dns_delete(args):
    client = DnsSpoofDriverClient()
    client.delete_rule(args.rule_id, flush_cache=not args.no_flush)
    print(f"deleted dns rule id={args.rule_id}")
    return 0


def cmd_dns_clear(args):
    client = DnsSpoofDriverClient()
    client.clear_rules(flush_cache=not args.no_flush)
    print("cleared all dns spoof rules")
    return 0


def cmd_dns_flush(args):
    ok = flush_dns_cache()
    print(f"dns cache flushed={ok}")
    return 0 if ok else 1


def build_parser():
    parser = argparse.ArgumentParser(description="NDISLWF port redirect & driver management CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="list rules")
    list_parser.set_defaults(func=cmd_list)

    add_parser = subparsers.add_parser("add", help="add a rule")
    add_parser.add_argument("--name", default="")
    add_parser.add_argument("--target-host", "--orig-ip", dest="target_host", required=True)
    add_parser.add_argument("--target-port", "--orig-port", dest="target_port", type=int, default=0)
    add_parser.add_argument("--redirect-host", "--new-ip", dest="redirect_host", required=True)
    add_parser.add_argument("--redirect-port", "--new-port", dest="redirect_port", type=int, default=0)
    add_parser.add_argument("--protocol", default="tcp", help="tcp | udp | any")
    add_parser.add_argument("--mac", default="", help="target next-hop MAC address")
    add_parser.add_argument("--local", action="store_true", help="force local loopback redirect")
    add_parser.add_argument("--id", type=int, default=0, help="explicit rule id (0=auto)")
    add_parser.set_defaults(func=cmd_add)

    update_parser = subparsers.add_parser("update", help="update an existing rule by ID")
    update_parser.add_argument("rule_id", type=int)
    update_parser.add_argument("--name", default=None)
    update_parser.add_argument("--target-host", "--orig-ip", dest="target_host", required=True)
    update_parser.add_argument("--target-port", "--orig-port", dest="target_port", type=int, default=0)
    update_parser.add_argument("--redirect-host", "--new-ip", dest="redirect_host", required=True)
    update_parser.add_argument("--redirect-port", "--new-port", dest="redirect_port", type=int, default=0)
    update_parser.add_argument("--protocol", default="tcp", help="tcp | udp | any")
    update_parser.add_argument("--mac", default="", help="target next-hop MAC address")
    update_parser.add_argument("--local", action="store_true", help="force local loopback redirect")
    update_parser.set_defaults(func=cmd_update)

    delete_parser = subparsers.add_parser("delete", help="delete a rule")
    delete_parser.add_argument("rule_id", type=int)
    delete_parser.set_defaults(func=cmd_delete)

    clear_parser = subparsers.add_parser("clear", help="clear all redirect rules")
    clear_parser.set_defaults(func=cmd_clear)

    status_parser = subparsers.add_parser("driver-status", help="query NDISLWF driver install/run status")
    status_parser.set_defaults(func=cmd_driver_status)

    install_parser = subparsers.add_parser("driver-install", help="install NDISLWF driver")
    install_parser.add_argument("--inf", default=None, help="path to netlwf.inf")
    install_parser.add_argument("--sys", default=None, help="path to ndislwf.sys")
    install_parser.add_argument("--no-start", action="store_true", help="do not start service after install")
    install_parser.set_defaults(func=cmd_driver_install)

    uninstall_parser = subparsers.add_parser("driver-uninstall", help="stop and uninstall NDISLWF driver")
    uninstall_parser.set_defaults(func=cmd_driver_uninstall)

    start_parser = subparsers.add_parser("driver-start", help="start installed NDISLWF driver")
    start_parser.set_defaults(func=cmd_driver_start)

    stop_parser = subparsers.add_parser("driver-stop", help="stop running NDISLWF driver")
    stop_parser.set_defaults(func=cmd_driver_stop)

    dns_list_parser = subparsers.add_parser("dns-list", help="list DNS spoof rules")
    dns_list_parser.set_defaults(func=cmd_dns_list)

    dns_add_parser = subparsers.add_parser("dns-add", help="add or update a DNS spoof rule")
    dns_add_parser.add_argument("--domain", required=True, help="exact or *.wildcard domain")
    dns_add_parser.add_argument("--ipv4", default="", help="forged IPv4 address (A record)")
    dns_add_parser.add_argument("--ipv6", default="", help="forged IPv6 address (AAAA record)")
    dns_add_parser.add_argument("--ttl", type=int, default=DNS_SPOOF_DEFAULT_TTL, help="answer TTL seconds")
    dns_add_parser.add_argument("--wildcard", action="store_true", help="match all subdomains (*.domain)")
    dns_add_parser.add_argument("--id", type=int, default=0, help="explicit rule id (0=auto)")
    dns_add_parser.add_argument("--no-flush", action="store_true", help="skip DnsFlushResolverCache")
    dns_add_parser.set_defaults(func=cmd_dns_add)

    dns_del_parser = subparsers.add_parser("dns-delete", help="delete a DNS spoof rule")
    dns_del_parser.add_argument("rule_id", type=int)
    dns_del_parser.add_argument("--no-flush", action="store_true", help="skip DnsFlushResolverCache")
    dns_del_parser.set_defaults(func=cmd_dns_delete)

    dns_clear_parser = subparsers.add_parser("dns-clear", help="clear all DNS spoof rules")
    dns_clear_parser.add_argument("--no-flush", action="store_true", help="skip DnsFlushResolverCache")
    dns_clear_parser.set_defaults(func=cmd_dns_clear)

    dns_flush_parser = subparsers.add_parser("dns-flush", help="flush Windows DNS resolver cache")
    dns_flush_parser.set_defaults(func=cmd_dns_flush)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except (DriverError, DriverManagerError, OSError) as error:
        print(f"driver call failed: {error}", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"argument error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
