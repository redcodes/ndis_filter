import argparse
import sys

from file_filter import FileFilterDriverClient, FileFilterRule


def cmd_list(args):
    client = FileFilterDriverClient()
    rules = client.query_rules()
    if not rules:
        print("no file filter rules")
        return 0

    for rule in rules:
        print(
            f"id={rule.rule_id} "
            f"name={rule.name} "
            f"path={rule.path_pattern} "
            f"actions={rule.action_text} "
            f"enabled={rule.enabled}"
        )
    return 0


def cmd_add(args):
    client = FileFilterDriverClient()
    rule = FileFilterRule(
        name=args.name,
        path_pattern=args.path,
        enabled=not args.disabled,
        deny_read=args.deny_read,
        deny_write=args.deny_write,
        deny_delete=args.deny_delete,
        deny_rename=args.deny_rename,
    )
    if not any([rule.deny_read, rule.deny_write, rule.deny_delete, rule.deny_rename]):
        rule.deny_write = True

    created = client.add_rule(rule)
    print(f"added file filter rule id={created.rule_id}")
    return 0


def cmd_delete(args):
    client = FileFilterDriverClient()
    client.delete_rule(args.rule_id)
    print(f"deleted file filter rule id={args.rule_id}")
    return 0


def cmd_stats(args):
    client = FileFilterDriverClient()
    stats = client.query_stats()
    values = [
        ("examined_creates", stats.examined_creates),
        ("blocked_creates", stats.blocked_creates),
        ("examined_set_information", stats.examined_set_information),
        ("blocked_set_information", stats.blocked_set_information),
    ]
    for name, value in values:
        print(f"{name}={value}")
    return 0


def cmd_clear_stats(args):
    client = FileFilterDriverClient()
    client.clear_stats()
    print("cleared file filter stats")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description="CnCrypt file filter command line tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="list file rules")
    list_parser.set_defaults(func=cmd_list)

    add_parser = subparsers.add_parser("add", help="add a file rule")
    add_parser.add_argument("--name", default="file rule")
    add_parser.add_argument("--path", required=True, help=r"NT path pattern, for example \Device\HarddiskVolume*\Secret\*")
    add_parser.add_argument("--disabled", action="store_true")
    add_parser.add_argument("--deny-read", action="store_true")
    add_parser.add_argument("--deny-write", action="store_true")
    add_parser.add_argument("--deny-delete", action="store_true")
    add_parser.add_argument("--deny-rename", action="store_true")
    add_parser.set_defaults(func=cmd_add)

    delete_parser = subparsers.add_parser("delete", help="delete a file rule")
    delete_parser.add_argument("rule_id", type=int)
    delete_parser.set_defaults(func=cmd_delete)

    stats_parser = subparsers.add_parser("stats", help="query file filter stats")
    stats_parser.set_defaults(func=cmd_stats)

    clear_stats_parser = subparsers.add_parser("clear-stats", help="clear file filter stats")
    clear_stats_parser.set_defaults(func=cmd_clear_stats)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except OSError as error:
        print(f"file filter driver call failed: {error}", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"argument error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
