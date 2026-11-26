import argparse
import sys

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


def build_parser():
    parser = argparse.ArgumentParser(description="NDISLWF port redirect command line tool")
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

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except (DriverError, OSError) as error:
        print(f"driver call failed: {error}", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"argument error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
