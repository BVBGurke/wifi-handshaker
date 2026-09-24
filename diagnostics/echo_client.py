#!/usr/bin/env python3
"""Tiny TCP reachability/echo client for the echo_host.py test host.

Connects to a host across a list of ports, sends a magic line and reports what
comes back, so a firewall drop (silent timeout), a closed port (refused), a
foreign service (wrong reply) and a working echo host (PONG/ECHO) can be told
apart. It is dependency-free and independent of ``wifi-handshake.py``.

    python diagnostics/echo_client.py --host 100.105.183.20
    python diagnostics/echo_client.py --host 100.105.183.20 --count 3
    python diagnostics/echo_client.py --host 100.105.183.20 --proxy 127.0.0.1:1056

For a userspace Tailscale setup the SOCKS5 proxy at ``127.0.0.1:1056`` is
detected automatically (override with ``--proxy``, disable with ``--no-proxy``).
No packets are injected and nothing is sent anywhere except to the given host.
"""

import argparse
import ipaddress
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.parse

MAGIC_PING = b"WIFI_HANDSHAKE_PING"
MAGIC_PONG = b"WIFI_HANDSHAKE_PONG"
DEFAULT_PORTS = (8443, 9443, 10443, 11443, 12443)
TAILNET_V4 = ipaddress.ip_network("100.64.0.0/10")
TAILNET_V6 = ipaddress.ip_network("fd7a:115c:a1e0::/48")
OK_STATUSES = ("pong", "both", "echo")


def parse_ports(value):
    ports = []
    for item in str(value).replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            port = int(item)
        except ValueError:
            continue
        if 0 < port < 65536:
            ports.append(port)
    return ports or list(DEFAULT_PORTS)


def is_tailnet_host(host):
    if host.rstrip(".").lower().endswith(".ts.net"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address in TAILNET_V4 or address in TAILNET_V6


def detect_proxy():
    """Return ``(host, port)`` of a local SOCKS5 proxy, or None."""
    host, port = "127.0.0.1", 1056
    env = os.environ.get("WIFI_HANDSHAKE_TAILSCALE_PROXY")
    if env:
        parsed = urllib.parse.urlsplit(env if "://" in env else "//" + env)
        host = parsed.hostname or host
        try:
            port = parsed.port or port
        except ValueError:
            pass
    try:
        sock = socket.create_connection((host, port), timeout=0.4)
        sock.close()
    except OSError:
        return None
    return host, port


def parse_proxy(value):
    parsed = urllib.parse.urlsplit(value if "://" in value else "//" + value)
    return parsed.hostname, parsed.port


def _socks5_recv_exact(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        data = sock.recv(size - len(chunks))
        if not data:
            raise OSError("SOCKS5 proxy closed the connection")
        chunks += data
    return bytes(chunks)


def _socks5_address(host):
    for family, atyp in ((socket.AF_INET, b"\x01"), (socket.AF_INET6, b"\x04")):
        try:
            return atyp + socket.inet_pton(family, host)
        except OSError:
            continue
    name = host.encode("idna")
    if not 0 < len(name) <= 255:
        raise OSError(f"invalid SOCKS5 target host: {host!r}")
    return b"\x03" + bytes([len(name)]) + name


SOCKS5_ERRORS = {
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused (nothing listens on the port)",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


def _socks5_connect(proxy, host, port, timeout):
    proxy_host, proxy_port = proxy
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        greeting = _socks5_recv_exact(sock, 2)
        if greeting != b"\x05\x00":
            raise OSError("SOCKS5 proxy rejected no-auth")
        sock.sendall(b"\x05\x01\x00" + _socks5_address(host) + struct.pack(">H", port))
        header = _socks5_recv_exact(sock, 4)
        if header[0] != 0x05 or header[1] != 0:
            code = header[1]
            raise OSError("SOCKS5 connect failed: "
                          + SOCKS5_ERRORS.get(code, f"unknown error 0x{code:02x}"))
        if header[3] == 1:
            _socks5_recv_exact(sock, 6)
        elif header[3] == 4:
            _socks5_recv_exact(sock, 18)
        else:
            _socks5_recv_exact(sock, _socks5_recv_exact(sock, 1)[0] + 2)
        return sock
    except BaseException:
        sock.close()
        raise


def connect(host, port, proxy, timeout, use_tls):
    """Connect and return ``(socket, path_label, connect_ms)``.

    For tailnet hosts the SOCKS5 proxy is tried first (userspace Tailscale has
    no direct route); otherwise a direct connection is preferred.
    """
    attempts = []
    if proxy and is_tailnet_host(host):
        # Userspace Tailscale has no direct route to tailnet hosts.
        attempts = [("SOCKS5", proxy), ("direct", None)]
    elif proxy:
        attempts = [("direct", None), ("SOCKS5", proxy)]
    else:
        attempts = [("direct", None)]
    errors = []
    for kind, forward in attempts:
        try:
            started = time.monotonic()
            if forward is None:
                sock = socket.create_connection((host, port), timeout=timeout)
            else:
                sock = _socks5_connect(forward, host, port, timeout)
            sock.settimeout(timeout)
            if use_tls:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            elapsed = (time.monotonic() - started) * 1000.0
            label = kind if forward is None else f"SOCKS5 {forward[0]}:{forward[1]}"
            return sock, label, elapsed
        except OSError as exc:
            if forward is None:
                errors.append(f"direct: {exc}")
            else:
                errors.append(f"SOCKS5 {forward[0]}:{forward[1]}: {exc}")
    raise OSError("; ".join(errors))


def classify(reply, message):
    """Map a reply line to ``(status, detail)``."""
    if reply is None:
        return "empty", "connection closed with no reply"
    text = reply.rstrip(b"\r\n")
    if text == MAGIC_PONG:
        return "pong", "magic pong"
    if text.startswith(MAGIC_PONG):
        return "both", "magic pong + echo"
    if text == message:
        return "echo", "echo"
    return "foreign", f"unexpected reply {text[:60]!r}"


def probe_port(host, port, proxy, timeout, count, message, use_tls):
    """Run ``count`` round trips on one port and return a result dict."""
    result = {"port": port, "status": "error", "detail": "", "path": None,
              "connect_ms": None, "rtt_ms": None, "loss": 0}
    try:
        sock, path, connect_ms = connect(host, port, proxy, timeout, use_tls)
    except OSError as exc:
        text = str(exc)
        lowered = text.lower()
        if "refused" in lowered and "socks5" not in lowered:
            result.update(status="refused", detail="connection refused (port closed)")
        elif "timed out" in lowered or "timeout" in lowered:
            result.update(status="timeout", detail="no answer (dropped or no route)")
        else:
            result.update(status="error", detail=text)
        return result
    result["path"] = path
    result["connect_ms"] = connect_ms
    rtts = []
    statuses = []
    with sock:
        stream = sock.makefile("rwb")
        for _ in range(max(1, count)):
            try:
                started = time.monotonic()
                stream.write(message + b"\n")
                stream.flush()
                reply = stream.readline()
                rtts.append((time.monotonic() - started) * 1000.0)
            except socket.timeout:
                result["status"] = "no-reply"
                result["detail"] = "connected, but no reply (silent host)"
                break
            except OSError as exc:
                result["detail"] = f"send/read failed: {exc}"
                break
            status, detail = classify(reply if reply else None, message)
            statuses.append(status)
            result["status"] = status
            result["detail"] = detail
            if status in ("foreign", "empty"):
                break
    result["loss"] = max(0, max(1, count) - len(rtts))
    if rtts:
        result["rtt_ms"] = (min(rtts), sum(rtts) / len(rtts), max(rtts))
    return result


def format_result(result):
    port = f"{result['port']}"
    status = result["status"]
    if status in OK_STATUSES:
        rtt = result["rtt_ms"]
        timing = f"rtt {rtt[1]:.1f} ms" if rtt else ""
        return f"  {port:<6} {status:<8} {result['detail']:<28} {timing}"
    if result["rtt_ms"]:
        return f"  {port:<6} {status:<8} {result['detail']:<28}"
    return f"  {port:<6} {status:<8} {result['detail']}"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="TCP reachability/echo client for echo_host.py.")
    parser.add_argument("--host", required=True,
                        help="target IP or MagicDNS name")
    parser.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)),
                        help="comma-separated TCP ports to try "
                             f"(default: {','.join(map(str, DEFAULT_PORTS))})")
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="connect/read timeout in seconds (default 3)")
    parser.add_argument("--count", type=int, default=1,
                        help="round trips per port (default 1)")
    parser.add_argument("--message", default=MAGIC_PING.decode(),
                        help=f"line to send (default: {MAGIC_PING.decode()})")
    parser.add_argument("--proxy", help="SOCKS5 proxy host:port "
                                       "(default: auto-detect 127.0.0.1:1056)")
    parser.add_argument("--no-proxy", action="store_true",
                        help="never use a SOCKS5 proxy")
    parser.add_argument("--tls", action="store_true",
                        help="wrap the connection in TLS (certificate not verified)")
    parser.add_argument("--json", action="store_true", help="print JSON")
    args = parser.parse_args(argv)

    ports = parse_ports(args.ports)
    message = args.message.encode()
    if args.no_proxy:
        proxy = None
    elif args.proxy:
        proxy = parse_proxy(args.proxy)
    else:
        proxy = detect_proxy()

    if not args.json:
        via = f" via SOCKS5 {proxy[0]}:{proxy[1]}" if proxy else " (direct)"
        tls = " TLS" if args.tls else ""
        print(f"Transport test -> {args.host}{via}{tls}")
        print(f"  {'port':<6} {'result':<8} {'detail':<28} timing")

    results = [probe_port(args.host, port, proxy, args.timeout, args.count,
                          message, args.tls) for port in ports]

    if args.json:
        print(json.dumps({"host": args.host, "proxy": proxy, "results": results},
                         indent=2))
    else:
        for result in results:
            print(format_result(result))
        good = [r for r in results if r["status"] in OK_STATUSES]
        print()
        if good:
            ports_ok = ", ".join(str(r["port"]) for r in good)
            print(f"Result: {len(good)}/{len(results)} port(s) answered "
                  f"as an echo host ({ports_ok}).")
        else:
            print(f"Result: 0/{len(results)} ports answered as an echo host.")
            statuses = {r["status"] for r in results}
            if "foreign" in statuses:
                print("  A port replied with something else: another service "
                      "uses it (see detail).")
            if "no-reply" in statuses:
                print("  'no-reply' means the TCP connection worked but nothing "
                      "was sent back (echo_host --mode silent, or a middlebox).")
            if statuses & {"timeout"}:
                print("  Timeouts mean the packet was dropped: firewall or no "
                      "route to the host.")
            if statuses & {"refused"}:
                print("  'refused' means the port is reachable but nothing "
                      "listens there.")
            print("  Is echo_host.py running on the target on one of these ports?")
    return 0 if any(r["status"] in OK_STATUSES for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
