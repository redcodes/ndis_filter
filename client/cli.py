import argparse
import sys

from main import (
    FilterDriverClient,
    PORT_REDIRECT_PROCESS_MODE_EXCLUDE,
    PORT_REDIRECT_PROTOCOL_TCP,
    PORT_REDIRECT_PROTOCOL_UDP,
    PortRedirectRule,
)


def protocol_mask_from_text(text):
    value = (text or "tcp").strip().lower()
    if value == "tcp":
        return PORT_REDIRECT_PROTOCOL_TCP
    if value == "udp":
        return PORT_REDIRECT_PROTOCOL_UDP
    if value in ("both", "tcp,udp", "udp,tcp"):
        return PORT_REDIRECT_PROTOCOL_TCP | PORT_REDIRECT_PROTOCOL_UDP
    raise ValueError(f"unsupported protocol: {value}")


def cmd_list(args):
    client = FilterDriverClient()
    rules = client.query_rules()
    if not rules:
        print("no rules")
        return 0

    for rule in rules:
        print(
            f"id={rule.rule_id} "
            f"name={rule.name} "
            f"target={rule.target_host}:{rule.target_port} "
            f"redirect={rule.redirect_host}:{rule.redirect_port} "
            f"protocol={rule.protocols_text} "
            f"family={rule.address_family_text} "
            f"enabled={rule.enabled}"
        )
    return 0


def cmd_add(args):
    client = FilterDriverClient()
    rule = PortRedirectRule(
        name=args.name,
        target_host=args.target_host,
        target_port=args.target_port,
        redirect_host=args.redirect_host,
        redirect_port=args.redirect_port,
        protocol_mask=protocol_mask_from_text(args.protocol),
        enabled=True,
        process_mode=PORT_REDIRECT_PROCESS_MODE_EXCLUDE,
    )
    created = client.add_rule(rule)
    print(f"added rule id={created.rule_id}")
    return 0


def cmd_update(args):
    client = FilterDriverClient()
    rule = PortRedirectRule(
        rule_id=args.rule_id,
        name=args.name,
        target_host=args.target_host,
        target_port=args.target_port,
        redirect_host=args.redirect_host,
        redirect_port=args.redirect_port,
        protocol_mask=protocol_mask_from_text(args.protocol),
        enabled=not args.disabled,
        process_mode=PORT_REDIRECT_PROCESS_MODE_EXCLUDE,
    )
    updated = client.update_rule(rule)
    print(f"updated rule id={updated.rule_id}")
    return 0


def cmd_delete(args):
    client = FilterDriverClient()
    client.delete_rule(args.rule_id)
    print(f"deleted rule id={args.rule_id}")
    return 0


def cmd_stats(args):
    client = FilterDriverClient()
    stats = client.query_stats()
    values = [
        ("examined_nbls", stats.examined_nbls),
        ("redirected_nbls", stats.redirected_nbls),
        ("passed_nbls", stats.passed_nbls),
        ("clone_failures", stats.clone_failures),
        ("rewrite_failures", stats.rewrite_failures),
        ("skipped_multi_net_buffer", stats.skipped_multi_net_buffer),
        ("skipped_lso", stats.skipped_lso),
        ("skipped_ipsec", stats.skipped_ipsec),
        ("skipped_unsupported_protocol", stats.skipped_unsupported_protocol),
        ("skipped_fragmented_ipv4", stats.skipped_fragmented_ipv4),
        ("skipped_fragmented_ipv6", stats.skipped_fragmented_ipv6),
    ]
    for name, value in values:
        print(f"{name}={value}")
    return 0


def cmd_clear_stats(args):
    client = FilterDriverClient()
    client.clear_stats()
    print("cleared port redirect stats")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description="NDISLWF port redirect command line tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="list rules")
    list_parser.set_defaults(func=cmd_list)

    add_parser = subparsers.add_parser("add", help="add a rule")
    add_parser.add_argument("--name", default="test rule")
    add_parser.add_argument("--target-host", required=True)
    add_parser.add_argument("--target-port", type=int, required=True)
    add_parser.add_argument("--redirect-host", required=True)
    add_parser.add_argument("--redirect-port", type=int, required=True)
    add_parser.add_argument("--protocol", default="tcp")
    add_parser.set_defaults(func=cmd_add)

    update_parser = subparsers.add_parser("update", help="update an existing rule")
    update_parser.add_argument("rule_id", type=int)
    update_parser.add_argument("--name", default="test rule")
    update_parser.add_argument("--target-host", required=True)
    update_parser.add_argument("--target-port", type=int, required=True)
    update_parser.add_argument("--redirect-host", required=True)
    update_parser.add_argument("--redirect-port", type=int, required=True)
    update_parser.add_argument("--protocol", default="tcp")
    update_parser.add_argument("--disabled", action="store_true")
    update_parser.set_defaults(func=cmd_update)

    delete_parser = subparsers.add_parser("delete", help="delete a rule")
    delete_parser.add_argument("rule_id", type=int)
    delete_parser.set_defaults(func=cmd_delete)

    stats_parser = subparsers.add_parser("stats", help="query redirect stats")
    stats_parser.set_defaults(func=cmd_stats)

    clear_stats_parser = subparsers.add_parser("clear-stats", help="clear redirect stats")
    clear_stats_parser.set_defaults(func=cmd_clear_stats)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except OSError as error:
        print(f"driver call failed: {error}", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"argument error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
