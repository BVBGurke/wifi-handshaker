#!/usr/bin/env python3
"""Tiny TCP echo/feedback host for reachability testing.

Listens on one or more TCP ports and answers each line with a fixed magic
reply, the exact bytes it received, or both. It is deliberately dependency-free
and independent of ``wifi-handshake.py``, so it can tell "the network or the
firewall is broken" apart from "the real host has a bug".

Run this on the machine you want to reach (for example the Windows GPU box):

    python diagnostics/echo_host.py --ports 8443,9443,10443,11443,12443

Then run ``echo_client.py`` from the other machine. Every connection and every
message is logged here, so you can see whether packets arrive even when no
reply makes it back.

No packets are injected and nothing is sent anywhere except back to the caller.
"""

import argparse
import socket
import sys
import threading
import time

MAGIC_PING = b"WIFI_HANDSHAKE_PING"
MAGIC_PONG = b"WIFI_HANDSHAKE_PONG"
DEFAULT_PORTS = (8443, 9443, 10443, 11443, 12443)
MODES = ("pong", "echo", "both", "silent")
STOP = threading.Event()


def parse_ports(value):
    """Parse ``"8443,9443"`` (or ``;`` separated) into a list of ports."""
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


def log(message):
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def reply_for(line, mode):
    """Return the single response line for ``line``, or ``None`` for silence."""
    if mode == "pong":
        return MAGIC_PONG if line == MAGIC_PING else b"UNKNOWN"
    if mode == "echo":
        return line
    if mode == "both":
        return MAGIC_PONG + b" " + line if line == MAGIC_PING else line
    return None


def handle(conn, peer, port, mode, show_hex, once):
    with conn:
        conn.settimeout(60)
        stream = conn.makefile("rwb")
        while not STOP.is_set():
            try:
                line = stream.readline()
            except OSError as exc:
                log(f"{peer} -> :{port}  read error: {exc}")
                return
            if not line:
                return
            text = line.rstrip(b"\r\n")
            shown = text[:200]
            extra = " hex=" + text.hex() if show_hex else ""
            response = reply_for(text, mode)
            if response is None:
                log(f"{peer} -> :{port}  recv {len(text)}B {shown!r}{extra}  (no reply)")
            else:
                try:
                    stream.write(response + b"\n")
                    stream.flush()
                except OSError as exc:
                    log(f"{peer} -> :{port}  recv {len(text)}B {shown!r}  "
                        f"reply failed: {exc}")
                    return
                log(f"{peer} -> :{port}  recv {len(text)}B {shown!r}{extra}  "
                    f"send {response[:80]!r}")
            if once:
                STOP.set()
                return


def listen(port, bind, mode):
    """Open a listening socket on ``bind:port``, or return None on failure."""
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((bind, port))
        server.listen(16)
    except OSError as exc:
        log(f"port {port}: cannot listen ({exc})")
        return None
    log(f"listening on {bind}:{port} (mode={mode})")
    return server


def serve_port(server, port, mode, show_hex, once):
    server.settimeout(0.5)
    while not STOP.is_set():
        try:
            conn, addr = server.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        peer = f"{addr[0]}:{addr[1]}"
        log(f"connect from {peer} to :{port}")
        handle(conn, peer, port, mode, show_hex, once)
    server.close()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="TCP echo/feedback host for reachability testing.")
    parser.add_argument("--bind", default="0.0.0.0",
                        help="bind address, default 0.0.0.0")
    parser.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)),
                        help="comma-separated TCP ports to listen on "
                             f"(default: {','.join(map(str, DEFAULT_PORTS))})")
    parser.add_argument("--mode", choices=MODES, default="both",
                        help="pong: magic reply; echo: same bytes back; "
                             "both: magic reply + echo; silent: log only "
                             "(default: both)")
    parser.add_argument("--once", action="store_true",
                        help="exit after the first successful exchange")
    parser.add_argument("--hex", action="store_true",
                        help="also print received bytes as hex")
    args = parser.parse_args(argv)

    ports = parse_ports(args.ports)
    print(f"echo_host: bind={args.bind} ports={','.join(map(str, ports))} "
          f"mode={args.mode}")
    print("Protocol: send a line, get one line back "
          "(WIFI_HANDSHAKE_PING -> WIFI_HANDSHAKE_PONG).")
    if sys.platform == "win32":
        print("Windows Firewall drops inbound ports without a rule. If clients "
              "time out, allow them (admin PowerShell):")
        print('  New-NetFirewallRule -DisplayName "wifi-handshaker ports" '
              '-Direction Inbound -Action Allow -Protocol TCP -LocalPort '
              + ",".join(map(str, ports)) + " -Profile Any")
        print("Or skip the firewall with: python wifi-handshake.py --serve "
              "--tailscale-serve")
    print("Ctrl+C stops all listeners.")
    print()

    servers = []
    for port in ports:
        server = listen(port, args.bind, args.mode)
        if server is None:
            continue
        servers.append(server)
        threading.Thread(target=serve_port,
                         args=(server, port, args.mode, args.hex, args.once),
                         daemon=True).start()
    if not servers:
        print("No port could be opened.", file=sys.stderr)
        return 1
    try:
        while not STOP.is_set():
            time.sleep(0.2)
    except KeyboardInterrupt:
        print("\nstopping ...")
    finally:
        STOP.set()
        for server in servers:
            try:
                server.close()
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
