import argparse
import socket
import sys
import threading
import time

from main import (
    FilterDriverClient,
    PORT_REDIRECT_PROCESS_MODE_EXCLUDE,
    PORT_REDIRECT_PROTOCOL_TCP,
    PortRedirectRule,
)


PAYLOAD = b"ndislwf-port-redirect-smoke"


class OneShotTcpServer:
    def __init__(self, bind_host, port, family):
        self.bind_host = bind_host
        self.port = port
        self.family = family
        self.received = b""
        self.error = None
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()
        if not self.ready.wait(5):
            raise TimeoutError(f"server did not start on {self.bind_host}:{self.port}")

    def join(self):
        self.thread.join(10)
        if self.thread.is_alive():
            raise TimeoutError(f"server did not finish on {self.bind_host}:{self.port}")
        if self.error:
            raise self.error
        return self.received

    def _run(self):
        try:
            with socket.socket(self.family, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((self.bind_host, self.port))
                listener.listen(1)
                self.ready.set()
                listener.settimeout(15)
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(5)
                    self.received = conn.recv(4096)
        except BaseException as error:
            self.error = error
            self.ready.set()


def _connect_and_send(host, port, family):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect((host, port))
        sock.sendall(PAYLOAD)


def _run_case(client, name, family, target_host, target_port, redirect_host, redirect_port, args):
    print(f"[{name}] add rule {target_host}:{target_port} -> {redirect_host}:{redirect_port}")
    before = client.query_stats()
    server = None

    if args.start_server:
        bind_host = args.bind_host or redirect_host
        server = OneShotTcpServer(bind_host, redirect_port, family)
        server.start()

    rule = PortRedirectRule(
        name=f"smoke-{name}",
        target_host=target_host,
        target_port=target_port,
        redirect_host=redirect_host,
        redirect_port=redirect_port,
        protocol_mask=PORT_REDIRECT_PROTOCOL_TCP,
        enabled=True,
        process_mode=PORT_REDIRECT_PROCESS_MODE_EXCLUDE,
    )

    created = client.add_rule(rule)
    try:
        print(f"[{name}] created rule id={created.rule_id}")
        if args.connect:
            time.sleep(0.2)
            _connect_and_send(target_host, target_port, family)
        if server is not None:
            received = server.join()
            if received != PAYLOAD:
                raise RuntimeError(f"{name} server received {received!r}, expected {PAYLOAD!r}")
        after = client.query_stats()
    finally:
        client.delete_rule(created.rule_id)
        print(f"[{name}] deleted rule id={created.rule_id}")

    examined_delta = after.examined_nbls - before.examined_nbls
    redirected_delta = after.redirected_nbls - before.redirected_nbls
    print(f"[{name}] stats examined_delta={examined_delta} redirected_delta={redirected_delta}")


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Add temporary IPv4/IPv6 TCP redirect rules and optionally perform a socket test. "
            "Use real NIC-reachable addresses for end-to-end NDIS verification; loopback traffic "
            "usually does not traverse an NDIS LWF."
        )
    )
    parser.add_argument("--ipv4-only", action="store_true", help="only run the IPv4 case")
    parser.add_argument("--ipv6-only", action="store_true", help="only run the IPv6 case")
    parser.add_argument("--connect", action="store_true", help="connect to each target host:port after adding the rule")
    parser.add_argument("--start-server", action="store_true", help="start a one-shot TCP server on each redirect port")
    parser.add_argument("--bind-host", help="server bind address; defaults to each redirect host")
    parser.add_argument("--ipv4-target-host", default="127.0.0.1")
    parser.add_argument("--ipv4-redirect-host", default="127.0.0.1")
    parser.add_argument("--ipv4-target-port", type=int, default=18081)
    parser.add_argument("--ipv4-redirect-port", type=int, default=18080)
    parser.add_argument("--ipv6-target-host", default="::1")
    parser.add_argument("--ipv6-redirect-host", default="::1")
    parser.add_argument("--ipv6-target-port", type=int, default=18083)
    parser.add_argument("--ipv6-redirect-port", type=int, default=18082)
    return parser


def main():
    args = build_parser().parse_args()
    if args.ipv4_only and args.ipv6_only:
        print("--ipv4-only and --ipv6-only are mutually exclusive", file=sys.stderr)
        return 2
    if args.start_server and not args.connect:
        print("--start-server requires --connect", file=sys.stderr)
        return 2

    client = FilterDriverClient()
    if not client.available:
        print("This smoke test requires Windows and the NDISLWF device.", file=sys.stderr)
        return 2

    try:
        if not args.ipv6_only:
            _run_case(
                client,
                "ipv4",
                socket.AF_INET,
                args.ipv4_target_host,
                args.ipv4_target_port,
                args.ipv4_redirect_host,
                args.ipv4_redirect_port,
                args,
            )
        if not args.ipv4_only:
            _run_case(
                client,
                "ipv6",
                socket.AF_INET6,
                args.ipv6_target_host,
                args.ipv6_target_port,
                args.ipv6_redirect_host,
                args.ipv6_redirect_port,
                args,
            )
    except OSError as error:
        print(f"driver or socket call failed: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        print(f"smoke test failed: {error}", file=sys.stderr)
        return 1

    print("port redirect smoke test completed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
