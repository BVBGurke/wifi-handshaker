#!/usr/bin/env python3
"""Passive Wi-Fi handshake capture and optional GPU cracking over Tailscale.

Run this file directly (`python wifi-handshake.py`) for the interactive menu,
or use `--help` / `--self-test` first. The module is importable as an engine.

Passive capture only: no deauthentication, injection or radio interference.
Monitor mode is a driver/firmware capability; the Adapter class tries several
setup paths so it works on as many chipsets as possible.

PROJECT RULE: all user-facing text is ENGLISH. Do not localize the interface
(no German, no other languages). See the rule block right below this docstring.
"""

# ===========================================================================
# PROJECT RULE - READ BEFORE EDITING (this also applies to AI assistants):
#
#   The ENTIRE user-facing interface MUST ALWAYS be in ENGLISH.
#
#   This covers every menu, prompt, question, message, warning, error, hint,
#   progress line and log line that a human can see. Do NOT translate the UI
#   into German or any other language, do NOT add localized variants, and do
#   NOT "improve" it by localizing. Code comments and identifiers stay English
#   too. Any new UI text must be written in English.
# ===========================================================================

import argparse
import base64
import collections
import contextlib
import csv
import getpass
import hashlib
import hmac
import http.client
import http.server
import io
import json
import mimetypes
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAC = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
DEFAULT_PORT = 8443
FIELDS = ["frame.number", "frame.time_epoch", "wlan.bssid", "wlan.sa", "wlan.da",
          "wlan_rsna_eapol.keydes.msgnr", "eapol.keydes.replay_counter",
          "wlan_rsna_eapol.keydes.nonce", "wlan_rsna_eapol.keydes.key_info.key_type",
          "eapol.type"]


def clean(value):
    # SSIDs are untrusted input. Never render terminal control sequences.
    return "".join(c if c.isprintable() else "?" for c in value)


# ANSI styling for the interactive UI. Disabled automatically when stdout is
# not a terminal or when NO_COLOR is set (https://no-color.org/).
STYLES = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
}


def use_color():
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def style(text, *names):
    if not use_color():
        return text
    return "".join(STYLES[name] for name in names) + str(text) + STYLES["reset"]


def heading(text):
    print("\n" + style(text, "bold", "cyan"))


def info(text):
    print(style(text, "dim"))


def warn(text):
    sys.stdout.flush()  # keep ordering when stdout is piped (block-buffered)
    print(style("Warning: ", "bold", "yellow") + style(text, "yellow"), file=sys.stderr)


def fail(text):
    sys.stdout.flush()
    print(style("Error: ", "bold", "red") + text, file=sys.stderr)


def ok(text):
    print(style("✓ ", "bold", "green") + style(text, "green"))


def run(*args, check=True, timeout=30):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} failed: {clean(result.stderr.strip())}")
    return result


def stop(proc):
    if proc is not None and proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


class SudoSession:
    """Keeps the sudo timestamp alive so the password is asked only once.

    ``sudo`` caches an authentication for a few minutes (15 by default). A
    long capture can easily exceed that, so a daemon thread refreshes the
    timestamp in the background while the capture runs.
    """

    def __init__(self):
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._refresh, daemon=True)

    def _refresh(self):
        while not self.stop_event.wait(45):
            subprocess.run(["sudo", "-n", "-v"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False)

    def start(self):
        self.thread.start()
        return self

    def close(self):
        self.stop_event.set()


def sudo_cached():
    return subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False).returncode == 0


def ensure_sudo(attempts=3):
    """Ask for the sudo password once and keep the timestamp alive.

    Returns a :class:`SudoSession` when authentication happened, or ``None``
    when already running as root. Raises on repeated failure.
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return None
    if not shutil.which("sudo"):
        raise RuntimeError("sudo is required. Run the script as root or install sudo.")
    if sudo_cached():
        return SudoSession().start()
    heading("Root privileges for monitor mode")
    info("The sudo password is asked once and is not stored.")
    for attempt in range(1, attempts + 1):
        try:
            password = getpass.getpass("sudo password: ")
        except EOFError as exc:
            raise RuntimeError("Cannot read input (no terminal).") from exc
        result = subprocess.run(["sudo", "-S", "-v", "-p", ""],
                                input=password + "\n", text=True,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=False)
        if result.returncode == 0:
            ok("Authentication successful.")
            return SudoSession().start()
        warn(f"Wrong password ({attempt}/{attempts}).")
    raise RuntimeError("sudo authentication failed.")


# ---------------------------------------------------------------------------
# Tailscale integration
#
# The laptop and the tower are expected to live in the same tailnet. These
# helpers wrap the `tailscale` CLI so the tool can show the tailnet, discover
# the tower by its MagicDNS name and print the address the tower is reachable
# at. Everything degrades gracefully: when Tailscale is missing or not logged
# in, the rest of the tool keeps working with an explicit --tower URL.
# ---------------------------------------------------------------------------

TAILSCALE_STATES = {
    "NoState": "not running",
    "NeedsLogin": "logged out",
    "NeedsMachineAuth": "awaiting approval",
    "Stopped": "stopped",
    "Starting": "starting",
    "Running": "running",
}


# Optional socket override for tailscaled. The default install uses
# /var/run/tailscale/tailscaled.sock; a userspace daemon
# (`tailscaled --tun=userspace-networking --socket ...`) listens elsewhere.
# Set WIFI_HANDSHAKE_TAILSCALE_SOCKET to talk to such a daemon.
TAILSCALE_SOCKET_ENV = "WIFI_HANDSHAKE_TAILSCALE_SOCKET"


def tailscale_binary():
    return shutil.which("tailscale")


def tailscale_available():
    return tailscale_binary() is not None


def tailscale_socket():
    return os.environ.get(TAILSCALE_SOCKET_ENV)


def tailscale_command(*args):
    """Build a `tailscale` command, honouring the socket override."""
    binary = tailscale_binary()
    if not binary:
        return None
    command = [binary]
    socket_path = tailscale_socket()
    if socket_path:
        command += ["--socket", socket_path]
    command += list(args)
    return command


def _tailscale(*args, timeout=10):
    command = tailscale_command(*args)
    if command is None:
        return None
    try:
        return subprocess.run(command, text=True, timeout=timeout,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (OSError, subprocess.TimeoutExpired):
        return None


def tailscale_status(timeout=10):
    """Parse `tailscale status --json` into a small summary, or ``None``.

    ``None`` means Tailscale is not installed, the daemon is not running or the
    output could not be parsed. The returned dict always carries ``state`` and a
    list of peers sorted with online peers first.
    """
    result = _tailscale("status", "--json", timeout=timeout)
    if result is None or result.returncode:
        return None
    try:
        data = json.loads(result.stdout)
    except ValueError:
        return None
    self_node = data.get("Self") or {}
    peers = []
    for node in (data.get("Peer") or {}).values():
        addresses = node.get("TailscaleIPs") or []
        peers.append({
            "hostname": node.get("HostName") or "",
            "dns_name": (node.get("DNSName") or "").rstrip("."),
            "ip": addresses[0] if addresses else "",
            "os": node.get("OS") or "",
            "online": bool(node.get("Online")),
            "active": bool(node.get("Active")),
        })
    peers.sort(key=lambda peer: (not peer["online"], peer["hostname"].lower()))
    self_addresses = self_node.get("TailscaleIPs") or []
    state = data.get("BackendState") or "NoState"
    return {
        "state": state,
        "state_label": TAILSCALE_STATES.get(state, state),
        "self_hostname": self_node.get("HostName") or "",
        "self_dns_name": (self_node.get("DNSName") or "").rstrip("."),
        "self_ip": self_addresses[0] if self_addresses else "",
        "peers": peers,
    }


def tailscale_ready(status=None):
    status = status or tailscale_status()
    return bool(status and status["state"] == "Running")


def tailscale_peer(name, status=None):
    """Find a tailnet peer by hostname or MagicDNS name (case-insensitive)."""
    status = status or tailscale_status()
    if not status:
        return None
    wanted = name.rstrip(".").lower()
    for peer in status["peers"]:
        candidates = {peer["hostname"].lower(), peer["dns_name"].lower(),
                      peer["dns_name"].split(".")[0].lower()}
        if wanted in candidates:
            return peer
    return None


def tailscale_tower_url(name="tower", port=DEFAULT_PORT, scheme="https"):
    """Build a tower URL from a tailnet peer's IP address, or None."""
    status = tailscale_status()
    if not tailscale_ready(status):
        return None
    peer = tailscale_peer(name, status)
    if not peer:
        return None
    host = peer["ip"] or peer["dns_name"]
    if not host:
        return None
    return f"{scheme}://{host}:{port}"


def print_tailscale_status(status=None):
    """Print a human-readable tailnet summary and return the status dict."""
    if not tailscale_available():
        warn("Tailscale is not installed. Install it to reach the tower over the tailnet.")
        return None
    status = status or tailscale_status()
    if not status:
        warn("Tailscale is not running. Start it with `sudo tailscale up`.")
        return None
    summary = f"Tailscale: {status['state_label']}"
    if status["self_hostname"]:
        summary += f" as {status['self_hostname']}"
    if status["self_ip"]:
        summary += f" ({status['self_ip']})"
    if status["state"] == "Running":
        ok(summary)
    else:
        warn(summary)
        info("Run `sudo tailscale up` (or menu item 7) to join the tailnet.")
        return status
    if not status["peers"]:
        info("No peers in the tailnet yet.")
        return status
    print(style(f"  {'#':>3}  {'Online':<7} {'Host':<24} {'OS':<9} IP", "bold"))
    for index, peer in enumerate(status["peers"], 1):
        mark = "yes" if peer["online"] else "no"
        print(f"  {index:>3}  {mark:<7} {peer['hostname'][:23]:<24} {peer['os'][:8]:<9} "
              f"{peer['ip'] or peer['dns_name']}")
    return status


def tailscale_login():
    """Bring this device into the tailnet (runs `tailscale up`)."""
    binary = tailscale_binary()
    if not binary:
        warn("Tailscale is not installed. See https://tailscale.com/download")
        return 1
    status = tailscale_status()
    if tailscale_ready(status):
        ok("Already connected to the tailnet as " + (status["self_hostname"] or "this device") + ".")
        print_tailscale_status(status)
        return 0
    command = tailscale_command("up", "--accept-routes")
    if command is None:
        warn("Tailscale is not installed. See https://tailscale.com/download")
        return 1
    if hasattr(os, "geteuid") and os.geteuid() != 0 and shutil.which("sudo"):
        command = ["sudo", *command]
    print("Starting: " + " ".join(command))
    try:
        subprocess.run(command, check=False)
    except OSError as exc:
        warn(f"Could not start Tailscale: {exc}")
        return 1
    return 0 if tailscale_ready() else 1


def choose_tailscale_tower(args):
    """Offer tailnet peers as the tower and remember the chosen URL."""
    status = print_tailscale_status()
    if not status or status["state"] != "Running" or not status["peers"]:
        return None
    answer = input("Use a peer as tower (number), or Enter to skip: ").strip()
    if not answer.isdecimal() or not 1 <= int(answer) <= len(status["peers"]):
        return None
    peer = status["peers"][int(answer) - 1]
    host = peer["ip"] or peer["dns_name"]
    if not host:
        return None
    args.tower = f"https://{host}:{getattr(args, 'port', DEFAULT_PORT)}"
    ok("Tower URL set to " + args.tower)
    return args.tower


def resolve_tower(args, name=None):
    """Fill in ``args.tower`` from the tailnet when it was not set explicitly.

    Discovery is only attempted when a tower name is known: either the
    ``--tower-name`` value or the default ``tower``. Returns the URL or None.
    """
    if getattr(args, "tower", None):
        return args.tower
    if not tailscale_available():
        return None
    wanted = name or getattr(args, "tower_name", None) or "tower"
    url = tailscale_tower_url(wanted, getattr(args, "port", DEFAULT_PORT))
    if url:
        ok(f"Found tailnet peer '{wanted}': {url}")
        args.tower = url
        return url
    return None


def prompt_tower(args):
    """Return a tower URL, trying tailnet discovery before manual input."""
    if getattr(args, "tower", None):
        return args.tower
    if resolve_tower(args):
        return args.tower
    args.tower = input("Tower URL (e.g. https://tower:8443): ").strip() or None
    return args.tower


def choose(prompt, size):
    while True:
        value = input(prompt).strip()
        if value.lower() == "q":
            raise KeyboardInterrupt
        if value.isdecimal() and 1 <= int(value) <= size:
            return int(value) - 1
        print(f"Enter a number from 1 to {size}, or q to quit.")


def adapters():
    """List (interface, phy) pairs, skipping P2P helper interfaces.

    ``p2p-dev-*`` virtual interfaces share a radio but cannot capture; listing
    them only confuses the adapter choice, so they are filtered out. Monitor
    interfaces that already exist are kept and can be reused directly.
    """
    result = []
    phy = None
    for line in run("iw", "dev").stdout.splitlines():
        line = line.strip()
        if line.startswith("phy#"):
            phy = "phy" + line[4:]
        elif line.startswith("Interface "):
            name = line.split(maxsplit=1)[1]
            if name.startswith("p2p-dev-"):
                continue
            result.append((name, phy))
    return result


class Adapter:
    """A wireless interface prepared for monitor-mode capture.

    Compatibility: monitor mode is a driver/firmware capability, so different
    cards need different setup. Three paths are tried, in order, to cover as
    many chipsets as possible:

      1. An interface that is already in monitor mode is reused unchanged.
      2. The managed interface is switched to monitor directly (works on
         mac80211 drivers such as rtw88, ath9k, mt76, ...).
      3. A dedicated monitor virtual interface is created with
         ``iw phy <phy> interface add <name> type monitor`` (needed on drivers
         that cannot switch the primary interface, e.g. some brcmfmac builds).

    Drivers that support neither path (many Broadcom/Intel parts) genuinely
    cannot capture; that is hardware, not software.
    """

    def __init__(self, name, phy):
        self.name, self.phy = name, phy
        self.changed = False
        self.nm_changed = False
        self.nm_managed = False
        self.connection = None
        self.created_vif = None
        self.monitor_name = name
        info = run("iw", "dev", name, "info").stdout
        match = re.search(r"^\s*type (\S+)", info, re.M)
        self.original_type = match.group(1) if match else "unknown"
        if self.original_type not in ("managed", "monitor", "unknown"):
            raise RuntimeError(
                f"{name} is in '{self.original_type}' mode. Choose a dedicated "
                "managed or monitor adapter; AP/IBSS interfaces are left alone.")
        link = json.loads(run("ip", "-j", "link", "show", "dev", name).stdout)[0]
        self.was_up = "UP" in link.get("flags", [])
        if shutil.which("nmcli"):
            nm = run("nmcli", "-g", "GENERAL.NM-MANAGED,GENERAL.CON-UUID",
                     "device", "show", name, check=False)
            if nm.returncode == 0:
                lines = nm.stdout.splitlines()
                self.nm_managed = bool(lines and lines[0] == "yes")
                if len(lines) > 1 and re.fullmatch(r"[0-9a-fA-F-]{36}", lines[1]):
                    self.connection = lines[1]
        self.capabilities = run("iw", "phy", phy, "info").stdout
        if not re.search(r"^\s*\* monitor\s*$", self.capabilities, re.M):
            # Some out-of-tree drivers capture fine without advertising it, so
            # this is a warning rather than a hard stop. enable() still fails
            # with a clear message if the radio really cannot do monitor mode.
            warn(f"{name} does not advertise monitor-mode support. Trying "
                 "anyway; if setup fails, use a monitor-capable adapter.")

    @property
    def iface(self):
        """Interface actually used for capture (may be a created monitor vif)."""
        return self.monitor_name

    def enable(self):
        if self.original_type == "monitor":
            self.monitor_name = self.name
            run("ip", "link", "set", "dev", self.name, "up", check=False)
            print(f"{self.name} is already in monitor mode; reusing it.")
            return
        if self.nm_managed:
            self.nm_changed = True
            run("nmcli", "device", "set", self.name, "managed", "no")
        self.changed = True
        try:
            run("ip", "link", "set", "dev", self.name, "down")
            run("iw", "dev", self.name, "set", "type", "monitor")
            run("ip", "link", "set", "dev", self.name, "up")
            self.monitor_name = self.name
            return
        except (RuntimeError, OSError) as exc:
            print(f"Switching {self.name} to monitor mode failed ({exc}). "
                  "Trying a dedicated monitor interface instead ...")
        self._add_monitor_vif()

    def _add_monitor_vif(self):
        vif = self.name + "mon"
        if len(vif) > 15:  # IFNAMSIZ limit
            vif = "mon" + vif[-12:]
        run("iw", "dev", vif, "del", check=False)
        try:
            run("iw", "phy", self.phy, "interface", "add", vif, "type", "monitor")
            run("ip", "link", "set", "dev", vif, "up")
        except (RuntimeError, OSError) as exc:
            raise RuntimeError(
                f"Could not put {self.name} into monitor mode ({exc}). "
                "Common causes: the driver does not support monitor mode, the "
                "radio is blocked (check `rfkill list`), or another Wi-Fi "
                "manager is holding it. Use a monitor-capable adapter.") from exc
        self.created_vif = vif
        self.monitor_name = vif
        print(f"Created dedicated monitor interface {vif} on {self.phy}.")

    def restore(self):
        if not self.changed and not self.nm_changed and not self.created_vif:
            return
        print("\nRestoring adapter settings ...")
        commands = []
        if self.created_vif:
            commands.append(("iw", "dev", self.created_vif, "del"))
        if self.changed:
            commands += [("ip", "link", "set", "dev", self.name, "down"),
                         ("iw", "dev", self.name, "set", "type", self.original_type)]
            if self.was_up:
                commands.append(("ip", "link", "set", "dev", self.name, "up"))
        if self.nm_changed:
            commands.append(("nmcli", "device", "set", self.name, "managed", "yes"))
            if self.connection:
                commands.append(("nmcli", "--wait", "20", "connection", "up", "uuid",
                                 self.connection, "ifname", self.name))
        for command in commands:
            try:
                run(*command)
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
                warn(f"Restore failed: {exc}")
                print("  Retry manually: " + " ".join(command), file=sys.stderr)


def parse_networks(text, frequency_by_channel=None):
    """Parse an airodump-ng CSV export into network dicts.

    ``frequency_by_channel`` maps an airodump channel number to the list of
    frequencies we hopped. It is used to resolve the exact frequency for the
    capture step, which matters on 5/6 GHz where the channel number alone is
    ambiguous (e.g. channel 1 exists on 2.4 GHz and on 6 GHz).
    """
    frequency_by_channel = frequency_by_channel or {}
    networks = {}
    clients = {}
    station_section = False
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        if row[0].strip() == "Station MAC":
            station_section = True
            continue
        if station_section:
            # Station rows: Station MAC, ..., # packets, BSSID, Probed ESSIDs.
            if len(row) >= 6:
                station, ap = row[0].strip().lower(), row[5].strip().lower()
                if MAC.fullmatch(station) and MAC.fullmatch(ap):
                    clients.setdefault(ap, set()).add(station)
            continue
        if len(row) < 14:
            continue
        bssid = row[0].strip().lower()
        if not MAC.fullmatch(bssid):
            continue
        try:
            channel, power = int(row[3]), int(row[8])
        except ValueError:
            continue
        if channel <= 0:
            continue
        candidates = frequency_by_channel.get(channel) or []
        frequency = min(candidates) if candidates else None
        networks[bssid] = dict(bssid=bssid, channel=channel, frequency=frequency, power=power,
                               security=clean(" / ".join(v.strip() for v in row[5:8] if v.strip())),
                               ssid=clean(row[13].strip()) or "<hidden>")
    # The station section follows the AP section, so attach clients afterwards.
    for network in networks.values():
        network["clients"] = sorted(clients.get(network["bssid"], ()))
    return sorted(networks.values(), key=lambda n: n["power"] if n["power"] < -1 else -999,
                  reverse=True)


def signal_label(dbm):
    if dbm >= -1:
        return "unknown"
    if dbm >= -50:
        return "excellent"
    if dbm >= -60:
        return "good"
    if dbm >= -70:
        return "fair"
    return "weak"


def signal_bar(dbm):
    """Four-block signal bar for the network list (weak -> strong)."""
    levels = 0
    if dbm < -1:
        for threshold in (-80, -70, -60, -50):
            if dbm >= threshold:
                levels += 1
    return "█" * levels + "░" * (4 - levels)


# Frequency ranges per band selector. "b"/"g" are both 2.4 GHz, "a" is 5 GHz
# and "6" is the 6 GHz band used by Wi-Fi 6E/7. Frequencies are the unit of
# truth internally: airodump-ng can hop by frequency (-C) and `iw dev set freq`
# takes MHz, which avoids the 2.4/6 GHz channel-number clash. (`iw dev set
# channel` takes a channel *number*, not a frequency.)
BAND_RANGES = {
    "b": (2400, 2500),
    "g": (2400, 2500),
    "a": (5000, 5900),
    "6": (5925, 7125),
}


def radio_channels(capabilities):
    """Map enabled frequency (MHz) -> channel number from `iw phy ... info`."""
    channels = {}
    for line in capabilities.splitlines():
        match = re.search(r"\*\s+(\d+(?:\.\d+)?) MHz \[(\d+)\]", line)
        if not match or "disabled" in line:
            continue
        channels[float(match.group(1))] = int(match.group(2))
    return channels


def frequency_bands(frequency):
    """All band selectors that apply to a frequency (2.4 GHz is both b and g)."""
    return {band for band, (low, high) in BAND_RANGES.items() if low <= frequency < high}


def band_for_frequency(frequency):
    bands = frequency_bands(frequency)
    return sorted(bands)[0] if bands else None


def scan_channels(capabilities, band, requested=None):
    """Return the sorted frequencies to hop for the selected band(s).

    ``band`` is a string of band selectors (e.g. "abg", "6", "abg6").
    ``requested`` entries may be channel numbers or frequencies in MHz; a
    channel number is resolved to every matching frequency in the band set.
    """
    available = radio_channels(capabilities)
    wanted = set(band)
    selected = {freq: channel for freq, channel in available.items()
                if frequency_bands(freq) & wanted}
    if requested:
        chosen, missing = {}, []
        for value in requested:
            if value > 1000:  # explicit frequency in MHz
                matches = {value: selected[value]} if value in selected else {}
            else:  # channel number, possibly present in several bands
                matches = {freq: channel for freq, channel in selected.items()
                           if channel == value}
            if matches:
                chosen.update(matches)
            else:
                missing.append(value)
        if missing:
            raise RuntimeError(f"Channels not enabled for the selected band/radio: {sorted(missing)}")
        if not chosen:
            raise RuntimeError("No usable channels for this radio and band.")
        return sorted(chosen)
    if not selected:
        raise RuntimeError("No enabled 2.4/5/6 GHz channels found for this radio and band.")
    return sorted(selected)


def parse_channel_list(value):
    if not re.fullmatch(r"\d+(?:,\d+)*", value):
        raise argparse.ArgumentTypeError(
            "Use comma-separated channels/frequencies, e.g. 1,6,11 or 5180 or 2412")
    channels = [int(item) for item in value.split(",")]
    for channel in channels:
        if channel > 1000:
            if not 2400 <= channel <= 7125:
                raise argparse.ArgumentTypeError("Frequencies must be between 2400 and 7125 MHz")
        elif not 1 <= channel <= 233:
            raise argparse.ArgumentTypeError("Channel numbers must be between 1 and 233")
    return channels


def scan(adapter, directory, seconds, band, requested=None):
    capabilities = run("iw", "phy", adapter.phy, "info").stdout
    frequencies = scan_channels(capabilities, band, requested)
    available = radio_channels(capabilities)
    frequency_by_channel = {}
    for frequency in frequencies:
        frequency_by_channel.setdefault(available[frequency], []).append(frequency)
    ambiguous = sorted(ch for ch, freqs in frequency_by_channel.items() if len(freqs) > 1)
    if ambiguous:
        print("Note: channel numbers " + ",".join(map(str, ambiguous))
              + " exist on more than one band. Scan 6 GHz separately with --band 6 "
                "so those access points are identified on the right frequency.")
    # Give every channel several beacon intervals, with time for two sweeps.
    seconds = max(seconds, len(frequencies))
    # Discard old scan snapshots before rescanning.
    for old in directory.glob("scan-*.csv"):
        old.unlink()
    prefix = directory / "scan"
    log_path = directory / "scan.log"
    print(f"\nListening for nearby networks for {seconds} seconds...")
    print("Requested scan frequencies: " + ",".join(str(int(f)) for f in frequencies) + " MHz")
    observed = set()
    with log_path.open("wb") as log:
        # -C hops by frequency in MHz, which works for 2.4/5/6 GHz alike and
        # avoids the channel-number overlap between 2.4 GHz and 6 GHz.
        proc = subprocess.Popen(["airodump-ng", "-C", ",".join(str(int(f)) for f in frequencies),
                                 "-f", "500", "--write", str(prefix),
                                 "--output-format", "csv", "--write-interval", "1",
                                 adapter.iface], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + seconds
            next_sample = time.monotonic()
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError("Scan stopped: " + clean(log_path.read_text(errors="replace")[-2000:]))
                if time.monotonic() >= next_sample:
                    info = run("iw", "dev", adapter.iface, "info").stdout
                    mode = re.search(r"^\s*type (\S+)", info, re.M)
                    frequency = re.search(r"\((\d+) MHz\)", info)
                    if not mode or mode.group(1) != "monitor":
                        raise RuntimeError("Adapter left monitor mode during scan. Another Wi-Fi manager may be interfering.")
                    if frequency:
                        observed.add(int(frequency.group(1)))
                    next_sample = time.monotonic() + 0.7
                time.sleep(0.2)
        finally:
            stop(proc)
    print("Observed scan frequencies, sampled: "
          + (",".join(str(f) for f in sorted(observed)) + " MHz" if observed else "none"))
    if len(frequencies) > 1 and len(observed) < 2:
        print("WARNING: channel hopping was not observed. The driver or another Wi-Fi process may be holding the radio.")
    errors = log_path.read_text(errors="replace")
    for line in errors.splitlines():
        if re.search(r"(failed|error|busy|not supported|cannot|could not|couldn't|permission)", line, re.I):
            print("Scanner diagnostic: " + clean(line)[:500])
    files = sorted(directory.glob("scan-*.csv"))
    return parse_networks(files[-1].read_text(errors="replace"), frequency_by_channel) if files else []


class Handshake:
    """Match an ordered EAPOL exchange for one client with paired replay counters.

    Two modes are supported:
      * ``(1, 2, 3, 4)`` requires the full four-way exchange and an ANonce that
        ties M1 to M3.
      * ``(1, 2)`` accepts the common real-world case where only M1 (ANonce) and
        M2 (SNonce + MIC) were captured. hashcat -m 22000 needs no more.

    This checks packet structure, not the MIC or password. A complete exchange
    must fit in 30 seconds. Retransmissions are allowed.
    """
    def __init__(self, bssid, messages=(1, 2, 3, 4)):
        self.bssid = bssid.lower()
        self.messages = tuple(sorted(messages))
        self.complete_on = self.messages[-1]
        self.frames = collections.deque(maxlen=4096)
        self.last_frame = None

    def feed(self, line):
        self.last_frame = None
        fields = line.rstrip("\r\n").split("\t")
        if len(fields) != len(FIELDS):
            return None
        number, timestamp, bssid, source, dest, message, replay, nonce, pairwise, eapol_type = fields
        bssid, source, dest = bssid.lower(), source.lower(), dest.lower()
        if bssid != self.bssid or eapol_type != "3" or pairwise.lower() not in ("1", "true"):
            return None
        try:
            number, timestamp, message, replay = int(number), float(timestamp), int(message), int(replay)
        except ValueError:
            return None
        if message not in (1, 2, 3, 4) or message not in self.messages:
            return None
        if message in (1, 3):
            if source != bssid:
                return None
            client = dest
        else:
            if dest != bssid:
                return None
            client = source
        if not MAC.fullmatch(client) or int(client[:2], 16) & 1 or client == bssid:
            return None
        nonce = nonce.replace(":", "").lower()
        if message != 4 and (not re.fullmatch(r"[0-9a-f]{64}", nonce) or int(nonce, 16) == 0):
            return None
        frame = dict(number=number, time=timestamp, message=message, replay=replay,
                     nonce=nonce, client=client)
        self.last_frame = frame
        while self.frames and timestamp - self.frames[0]["time"] > 30:
            self.frames.popleft()
        self.frames.append(frame)
        if message != self.complete_on:
            return None
        previous = list(self.frames)[:-1]
        if self.complete_on == 2:
            for j in range(len(previous) - 1, -1, -1):
                m1 = previous[j]
                if (m1["message"] == 1 and m1["client"] == client
                        and m1["replay"] == replay and m1["nonce"] != "00" * 32
                        and m1["time"] <= timestamp):
                    return [m1, frame]
            return None
        for i in range(len(previous) - 1, -1, -1):
            m3 = previous[i]
            if m3["message"] != 3 or m3["client"] != client or m3["replay"] != replay:
                continue
            for j in range(i - 1, -1, -1):
                m2 = previous[j]
                if m2["message"] != 2 or m2["client"] != client or m2["replay"] >= replay:
                    continue
                for m1 in reversed(previous[:j]):
                    if (m1["message"] == 1 and m1["client"] == client
                            and m1["replay"] == m2["replay"] and m1["nonce"] == m3["nonce"]
                            and m1["time"] <= m2["time"] <= m3["time"] <= timestamp):
                        return [m1, m2, m3, frame]
        return None


# Actionable tips printed while a capture produces no usable EAPOL traffic.
# Keyed by seconds of listening; each threshold prints once per capture.
ACTION_TIPS = [
    (30, "No EAPOL-Key: toggle the test device's Wi-Fi off and on so it reconnects."),
    (60, "Verify the test device joins exactly this SSID and the same band "
         "(dual-band APs often broadcast 2.4 and 5 GHz separately)."),
    (120, "Reconnect while staying close to the access point. When idle, the AP "
          "renews the PMK only rarely (sometimes only after an hour)."),
    (240, "Try another device: some clients make the passive capture hard "
          "(association in a different channel width / beacon-interval gap)."),
]


class CaptureStats:
    def __init__(self, bssid, messages=(1, 2, 3, 4), siblings=()):
        self.bssid = bssid
        self.messages = tuple(sorted(messages))
        self.siblings = list(siblings)
        self.total = self.target = self.target_keys = self.other_keys = 0
        self.messages_seen = collections.Counter()
        self.accepted = collections.Counter()
        self.last_hint = None
        self._tips_done = set()

    def feed(self, line, accepted):
        fields = line.rstrip("\r\n").split("\t")
        if len(fields) != len(FIELDS):
            return
        self.total += 1
        target = fields[2].lower() == self.bssid
        self.target += int(target)
        if fields[9] != "3":
            return
        if not target:
            self.other_keys += 1
            if self.other_keys <= 3:
                print(f"EAPOL-Key on another BSSID: {clean(fields[2])}. Not the selected AP.", flush=True)
            return
        self.target_keys += 1
        message = fields[5] or "unclassified"
        self.messages_seen[message] += 1
        if accepted:
            self.accepted[message] += 1
        if self.target_keys <= 20 or self.target_keys % 50 == 0:
            direction = f"{clean(fields[3])} -> {clean(fields[4])}"
            verdict = "accepted" if accepted else "not usable by four-way matcher"
            print(f"Target EAPOL-Key M{clean(message)}: {direction}, "
                  f"replay={clean(fields[6]) or '?'}, {verdict}", flush=True)

    def report(self, elapsed, complete=False):
        counts = " ".join(f"M{i}={self.messages_seen[str(i)]}" for i in self.messages)
        print(f"Listening {elapsed}s: packets={self.total}, target={self.target}, "
              f"target EAPOL-Key={self.target_keys}, other AP EAPOL-Key={self.other_keys}; {counts}", flush=True)
        if complete:
            return
        if not self.total:
            hint = "No decoded packets. The radio/driver or capture pipeline is not delivering traffic."
        elif not self.target:
            hint = "Packets are arriving, but none match the selected BSSID. Check the AP and channel."
        elif not self.target_keys:
            hint = ("Target traffic is arriving, but no EAPOL-Key. Check which SSID and which band "
                    "the test device joins.")
        elif not all(self.accepted[str(i)] for i in self.messages):
            hint = ("Only part of the exchange arrived. Get closer to both AP and client; "
                    "M3/M4 in particular are often lost when a client moves or the channel is busy.")
        else:
            hint = ("The required messages were seen, but no usable exchange for one client "
                    "(nonce/replay order does not match).")
        if hint != self.last_hint:
            print(hint, flush=True)
            self.last_hint = hint
        self._actions(elapsed)

    def _actions(self, elapsed):
        if not self.target_keys:
            if self.siblings and 45 not in self._tips_done:
                names = ", ".join(f"'{s['ssid']}' ({s['bssid']})" for s in self.siblings)
                print(f"This AP also broadcasts as: {names}. If the test device joins one of "
                      f"those, select that SSID in the network list instead.", flush=True)
                self._tips_done.add(45)
            for threshold, text in ACTION_TIPS:
                if elapsed >= threshold and threshold not in self._tips_done:
                    print(text, flush=True)
                    self._tips_done.add(threshold)


def check_radio(adapter, frequency):
    info = run("iw", "dev", adapter.iface, "info").stdout
    mode = re.search(r"^\s*type (\S+)", info, re.M)
    if not mode or mode.group(1) != "monitor":
        raise RuntimeError("Adapter left monitor mode. Another Wi-Fi manager may be controlling it.")
    if not frequency:
        return
    # Not every driver reports the current channel; only fail on a real mismatch.
    actual = re.search(r"\((\d+) MHz\)", info)
    if actual and int(actual.group(1)) != int(frequency):
        raise RuntimeError(f"Adapter is no longer on selected frequency {int(frequency)} MHz. "
                           "Another process may be controlling the radio.")


def field_options():
    return ["-T", "fields", "-E", "occurrence=f"] + [part for f in FIELDS for part in ("-e", f)]


def capture_command(interface, raw, timeout, max_mb):
    # Live capture cannot combine -Y with -w. Handshake.feed filters the fields.
    command = ["tshark", "-n", "-l", "-i", interface, "-s", "0", "-B", "16",
               "-a", f"filesize:{max_mb * 1024}", "-w", str(raw), "-P"] + field_options()
    if timeout:
        command += ["-a", f"duration:{timeout}"]
    return command


def ap_base(bssid):
    """Grouping key for multi-SSID / dual-band APs sharing one radio MAC."""
    return ":".join(bssid.lower().split(":")[-4:])


def same_ap_networks(networks, chosen):
    """Other listed networks broadcast by the same physical AP as `chosen`."""
    base = ap_base(chosen["bssid"])
    return [n for n in networks if n["bssid"] != chosen["bssid"] and ap_base(n["bssid"]) == base]


def choose_handshake_mode():
    """Ask which EAPOL set to capture. M1+M2 is enough for hashcat -m 22000."""
    heading("EAPOL set selection")
    print("  " + style("1", "bold") + ". M1+M2       "
          + style("(quick; enough for hashcat -m 22000) [default]", "dim"))
    print("  " + style("2", "bold") + ". M1+M2+M3+M4 "
          + style("(full four-way; in practice rarely captured completely)", "dim"))
    choice = input(style("Choice [1]: ", "bold")).strip()
    return "m1m2m3m4" if choice == "2" else "m1m2"


def tune_channel(adapter, network):
    """Tune the monitor interface to the target network's frequency.

    Frequencies (MHz) are used rather than channel numbers because channel
    numbers overlap between 2.4 GHz and 6 GHz. ``iw dev set freq`` is the
    command that takes MHz; ``iw dev set channel`` expects a channel number and
    is only used as a fallback for older drivers, and only when that channel
    number is unambiguous across the enabled bands. Returns the frequency used.
    """
    frequency = network.get("frequency")
    channel = network["channel"]
    if frequency and frequency > 1000:
        try:
            run("iw", "dev", adapter.iface, "set", "freq", str(int(frequency)))
            return frequency
        except (RuntimeError, OSError) as exc:
            warn(f"Could not tune {int(frequency)} MHz directly ({exc}).")
    # Fallback for drivers without `set freq`: only safe when this channel
    # number maps to exactly one enabled frequency.
    matching = sorted(freq for freq, number
                      in radio_channels(adapter.capabilities).items() if number == channel)
    if len(matching) == 1:
        run("iw", "dev", adapter.iface, "set", "channel", str(channel))
        return matching[0]
    if len(matching) > 1:
        raise RuntimeError(
            f"Channel {channel} exists in several bands ({matching}) and this driver "
            "did not accept an explicit frequency. Use a driver that supports "
            "`iw dev set freq`.")
    run("iw", "dev", adapter.iface, "set", "channel", str(channel))
    return frequency


def capture(adapter, network, directory, timeout, max_mb, messages=(1, 2), siblings=()):
    frequency = tune_channel(adapter, network)
    check_radio(adapter, frequency)
    raw = directory / "traffic.pcapng"
    log_path = directory / "capture.log"
    bssid = network["bssid"]
    command = capture_command(adapter.iface, raw, timeout, max_mb)
    tracker = Handshake(bssid, messages)
    stats = CaptureStats(bssid, messages, siblings=siblings)
    wanted = "+".join(f"M{i}" for i in messages)
    heading("Capturing handshake")
    print("Target:  " + style(network["ssid"], "bold") + f"  [{bssid}]")
    mhz = f" ({int(frequency)} MHz)" if frequency else ""
    print(f"Channel: {network['channel']}{mhz}")
    print(f"Waiting for EAPOL exchange: {style(wanted, 'bold')}   (Ctrl+C cancels)")
    if set(messages) == {1, 2}:
        info("M1+M2 are enough for hashcat -m 22000; the full four-way handshake is not required.")
    info("No packets are injected. A device must naturally connect or reconnect.")
    info("Detection is for this exact BSSID, not every AP with the same network name.")
    info(f"Temporary capture limit: {max_mb} MiB. Unrelated traffic is deleted on exit.")
    started = last_status = time.monotonic()
    found = None
    buffer = b""
    with log_path.open("wb") as log, selectors.DefaultSelector() as selector:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log)
        try:
            selector.register(proc.stdout, selectors.EVENT_READ)
            eof = False
            while not eof and found is None:
                for key, _ in selector.select(timeout=1):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        eof = True
                        break
                    buffer += chunk
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        decoded = line.decode("utf-8", errors="replace")
                        found = tracker.feed(decoded)
                        stats.feed(decoded, tracker.last_frame)
                        if found:
                            break
                now = time.monotonic()
                if now - last_status >= 10:
                    stats.report(int(now - started))
                    check_radio(adapter, frequency)
                    last_status = now
            if not found:
                stop(proc)
                detail = clean(log_path.read_text(errors="replace")[-1500:])
                if proc.returncode:
                    raise RuntimeError("Capture failed: " + detail)
                warn("Capture limit reached without a complete handshake. No capture saved.")
                return None
        finally:
            stop(proc)
            proc.stdout.close()
            stats.report(int(time.monotonic() - started), complete=bool(found))
    return raw, found


def save_capture(raw, frames, network, output):
    # Only the matched exchange and this AP's beacons leave the temporary directory.
    numbers = ",".join(str(f["number"]) for f in frames)
    filt = (f"frame.number in {{{numbers}}} || "
            f"(wlan.bssid == {network['bssid']} && wlan.fc.type_subtype == 0x08)")
    run("tshark", "-n", "-r", str(raw), "-Y", filt, "-w", str(output))
    os.chmod(output, 0o600)
    if os.environ.get("SUDO_UID") and os.environ.get("SUDO_GID"):
        os.chown(output, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))


# ---------------------------------------------------------------------------
# Offline capture inspection (no radio, no root).
#
# Finds WPA/WPA2 four-way handshakes in an existing capture with the same field
# parser the live capture uses, and, for WPA2-PSK, verifies the MIC with PBKDF2
# and the 802.11 PRF. This is what turns the public example captures
# (vanhoefm/wifi-example-captures) into a real regression test, and it lets you
# check a capture before uploading it to the tower.
# ---------------------------------------------------------------------------

# LLC/SNAP header that precedes an EAPOL frame inside an 802.11 data frame.
EAPOL_SNAP = bytes.fromhex("aaaa03000000888e")


def parse_eapol_key(eapol):
    """Parse an EAPOL-Key frame into message number, replay counter, nonce, MIC."""
    if len(eapol) < 99 or eapol[1] != 3:
        return None
    key_info = int.from_bytes(eapol[5:7], "big")
    ack, mic = key_info & 0x0080, key_info & 0x0100
    install, secure = key_info & 0x0040, key_info & 0x0200
    if ack and not mic:
        message = 1
    elif not ack and mic and not secure:
        message = 2
    elif ack and mic and install and secure:
        message = 3
    elif not ack and mic and secure:
        message = 4
    else:
        return None
    return dict(message=message, replay=int.from_bytes(eapol[9:17], "big"),
                nonce=eapol[17:49], mic=eapol[81:97], key_info=key_info)


def eapol_key_frames(path):
    """Yield (frame, bssid, client, eapol_bytes, parsed) for EAPOL-Key frames.

    The raw bytes come from tshark's ``jsonraw`` output. If that is unavailable
    (older tshark) nothing is yielded and callers keep the structural result.
    """
    listing = run("tshark", "-n", "-r", str(path), "-Y", "eapol", "-T", "fields",
                  "-e", "frame.number", "-e", "wlan.bssid", "-e", "wlan.sa",
                  "-e", "wlan.da").stdout
    rows = [line.split("\t") for line in listing.splitlines() if line.strip()]
    result = run("tshark", "-n", "-r", str(path), "-Y", "eapol", "-T", "jsonraw",
                 check=False)
    if result.returncode:
        return
    try:
        packets = json.loads(result.stdout or "[]")
    except ValueError:
        return
    raws = []
    for packet in packets:
        try:
            raws.append(bytes.fromhex(packet["_source"]["layers"]["frame_raw"][0]))
        except (KeyError, IndexError, ValueError):
            raws.append(b"")
    for row, data in zip(rows, raws):
        if len(row) < 4 or not data:
            continue
        frame, bssid, sa, da = row[0], row[1].lower(), row[2].lower(), row[3].lower()
        if not (MAC.fullmatch(bssid) and MAC.fullmatch(sa) and MAC.fullmatch(da)):
            continue
        index = data.find(EAPOL_SNAP)
        if index < 0:
            continue
        eapol = data[index + len(EAPOL_SNAP):]
        parsed = parse_eapol_key(eapol)
        if not parsed:
            continue
        client = da if parsed["message"] in (1, 3) else sa
        yield frame, bssid, client, eapol, parsed


def derive_ptk(pmk, aa, spa, anonce, snonce):
    """802.11 PRF: derive the 48-byte CCMP PTK (KCK || KEK || TK)."""
    def pair(first, second):
        return min(first, second) + max(first, second)
    data = pair(aa, spa) + pair(anonce, snonce)
    output, counter = b"", 0
    while len(output) < 48:
        output += hmac.new(pmk, b"Pairwise key expansion\x00" + data
                           + bytes([counter]), hashlib.sha1).digest()
        counter += 1
    return output[:48]


def verify_mic(eapol, parsed, pmk, aa, spa, anonce, snonce):
    """True/False whether an M2/M4 MIC matches the derived key (None if not M2/M4)."""
    if parsed["message"] not in (2, 4) or parsed["mic"] == b"\x00" * 16:
        return None
    kck = derive_ptk(pmk, aa, spa, anonce, snonce)[:16]
    body = bytearray(eapol)
    body[81:97] = b"\x00" * 16
    return hmac.new(kck, bytes(body), hashlib.sha1).digest()[:16] == parsed["mic"]


def inspect_capture(path, ssid=None, password=None):
    """Report (and optionally verify) the four-way handshakes in a capture.

    Returns a summary dict: handshakes found, MICs verified and MICs mismatched.
    """
    path = Path(path)
    if not path.is_file():
        raise RuntimeError(f"Capture file not found: {path}")
    text = run("tshark", "-n", "-r", str(path), *field_options()).stdout
    trackers, found = {}, []
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != len(FIELDS) or not MAC.fullmatch(fields[2].lower()):
            continue
        bssid = fields[2].lower()
        tracker = trackers.setdefault(bssid, Handshake(bssid, (1, 2)))
        match = tracker.feed(line)
        if match:
            found.append((bssid, match[0]["client"]))
    heading("Capture: " + clean(path.name))
    unique = sorted(set(found))
    for bssid, client in unique:
        ok(f"Handshake found: AP {bssid}, client {client}")
    if not unique:
        warn("No complete M1+M2 (or full four-way) handshake found.")
    if bool(ssid) != bool(password):
        warn("MIC verification needs both --essid and --password; skipping verification.")
        ssid = password = None
    summary = {"handshakes": len(unique), "verified": 0, "mismatched": 0}
    if not (ssid and password):
        if unique:
            info("Pass --essid and --password to verify the MIC with a known passphrase.")
        return summary
    pmk = hashlib.pbkdf2_hmac("sha1", password.encode(), ssid.encode(), 4096, 32)
    frames = list(eapol_key_frames(path))
    if not frames:
        warn("Raw EAPOL bytes unavailable (need tshark with -T jsonraw); cannot verify.")
        return summary
    groups = {}
    for frame, bssid, client, eapol, parsed in frames:
        groups.setdefault((bssid, client), []).append((frame, eapol, parsed))
    for (bssid, client), entries in sorted(groups.items()):
        anonce = next((p["nonce"] for _, _, p in entries if p["message"] in (1, 3)), None)
        snonce = next((p["nonce"] for _, _, p in entries if p["message"] == 2), None)
        if not anonce or not snonce:
            continue
        aa = bytes.fromhex(bssid.replace(":", ""))
        spa = bytes.fromhex(client.replace(":", ""))
        for frame, eapol, parsed in entries:
            verified = verify_mic(eapol, parsed, pmk, aa, spa, anonce, snonce)
            if verified is None:
                continue
            label = f"M{parsed['message']} MIC"
            if verified:
                summary["verified"] += 1
                ok(f"  {label} verified for AP {bssid}, client {client}.")
            else:
                summary["mismatched"] += 1
                fail(f"  {label} MISMATCH for AP {bssid}, client {client}.")
    return summary


# ---------------------------------------------------------------------------
# Example captures: download public test data (vanhoefm/wifi-example-captures).
# ---------------------------------------------------------------------------

EXAMPLE_CAPTURES_REPO = "vanhoefm/wifi-example-captures"
# file name -> (SSID, passphrase) for captures whose secret is documented.
KNOWN_EXAMPLE_PASSWORDS = {
    "wnm_sleep_test-wpa2-psk:12345678.pcapng": ("test-wnm-rsn", "12345678"),
}


def download_example_captures(directory, repo=EXAMPLE_CAPTURES_REPO):
    """Download .pcap/.pcapng files from a GitHub repository into a directory."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/contents/",
        headers={"User-Agent": "wifi-handshake"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            items = json.load(response)
    except (urllib.error.URLError, ValueError, OSError) as exc:
        raise RuntimeError(f"Could not list {repo}: {exc}") from exc
    if not isinstance(items, list):
        raise RuntimeError(f"Unexpected response from {repo}: expected a directory listing.")
    saved = []
    for item in items:
        name = item.get("name", "")
        url = item.get("download_url")
        if not url or not name.lower().endswith((".pcap", ".pcapng", ".cap")):
            continue
        target = directory / name
        print("Downloading " + clean(name) + " ...")
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                target.write_bytes(response.read())
        except (urllib.error.URLError, OSError) as exc:
            warn(f"Failed to download {name}: {exc}")
            continue
        saved.append(target)
    heading("Example captures in " + clean(str(directory)))
    for target in saved:
        print("  " + clean(target.name))
    if not saved:
        warn("No capture files found in the repository.")
    return saved


# ---------------------------------------------------------------------------
# Tower integration: handshake transfer + GPU cracking over Tailscale.
#
# Roles:
#   * Linux laptop  -> capture (above) plus a client that uploads a handshake.
#   * Windows tower -> HTTP/JSON + WebSocket server that runs hashcat on a GPU.
#
# The transport is TLS with a self-signed certificate and fingerprint pinning,
# layered on top of Tailscale. There is intentionally no application-level
# authentication: the Tailscale network is the trust boundary. Anyone able to
# reach the tower port can start jobs and use the GPU. Restrict access with
# Tailscale ACLs if that is too broad.
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = 1
HASHCAT_MODE = "22000"
HASHCAT_VERSION = "7.1.2"
HASHCAT_URL = ("https://github.com/hashcat/hashcat/releases/download/"
               f"v{HASHCAT_VERSION}/hashcat-{HASHCAT_VERSION}.7z")
HASHCAT_SHA256 = "80db0316387794ce9d14ed376da75b8a7742972485b45db790f5f8260307ff98"
HCXTOOLS_VERSION = "7.1.2"
HCXTOOLS_URL = ("https://github.com/ZerBea/hcxtools/releases/download/"
                f"{HCXTOOLS_VERSION}/hcxtools-{HCXTOOLS_VERSION}.zip")
HCXTOOLS_SHA256 = "cf6d363c162854b4e052ebabb529e29ff22cf320c52a68df130c6b06e3ed0f14"
WORDLIST_SUFFIXES = (".txt", ".dict", ".lst", ".wordlist")
RULE_SUFFIXES = (".rule",)
EXTRA_HASHCAT_FLAGS = {
    "-w": 1, "-O": 0, "--force": 0, "--optimized-kernel": 0, "-d": 1,
    "--backend-devices": 1, "--backend-ignore-cuda": 0, "--backend-ignore-opencl": 0,
    "--increment": 0, "--increment-min": 1, "--increment-max": 1,
    "--hwmon-disable": 0, "--hwmon-temp-abort": 1, "--workload-profile": 1,
}


def app_dir():
    override = os.environ.get("WIFI_HANDSHAKE_DIR")
    return Path(override) if override else Path.home() / ".wifi-handshake"


def default_tools_dir():
    # Keep the GPU toolchain next to the script so hashcat's ./OpenCL kernels and
    # session logs stay inside the project instead of a shared installation.
    return Path(__file__).resolve().parent / "tools"


def exe_names(stem):
    return [stem + ".exe", stem] if os.name == "nt" else [stem]


def find_tool(stem, extra_dirs=()):
    for directory in extra_dirs:
        if not directory:
            continue
        directory = Path(directory)
        for name in exe_names(stem):
            direct = directory / name
            if direct.is_file():
                return direct
            nested = sorted(directory.glob("**/" + name))
            if nested:
                return nested[0]
    for name in exe_names(stem):
        found = shutil.which(name)
        # Skip .cmd/.bat shims: subprocess cannot execute them without a shell.
        if found and Path(found).suffix.lower() not in (".cmd", ".bat", ".ps1"):
            return Path(found)
    return None


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_verified(url, expected_sha256, dest):
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as response, dest.open("wb") as handle:
        shutil.copyfileobj(response, handle)
    digest = sha256_file(dest)
    print(f"SHA256: {digest}")
    if digest.lower() != expected_sha256.lower():
        dest.unlink(missing_ok=True)
        raise RuntimeError("Checksum mismatch. The download was discarded. Expected "
                           f"{expected_sha256}, got {digest}.")
    print("Checksum verified against the pinned value.")
    return dest


def extract_archive(archive, dest):
    archive, dest = Path(archive), Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    if archive.suffix == ".7z":
        seven = shutil.which("7z") or shutil.which("7za") or shutil.which("7z.exe")
        if seven:
            run(seven, "x", "-y", f"-o{dest}", str(archive))
            return dest
        try:
            import py7zr
            with py7zr.SevenZipFile(archive, mode="r") as handle:
                handle.extractall(path=dest)
            return dest
        except ImportError:
            pass
        if shutil.which("tar"):
            result = subprocess.run(["tar", "-xf", str(archive), "-C", str(dest)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                return dest
        raise RuntimeError("No 7z extractor found. Install 7-Zip or `pip install py7zr`.")
    shutil.unpack_archive(str(archive), str(dest))
    return dest


def install_tools(tools_dir):
    """Fetch the pinned hashcat build and explain the hcxtools situation.

    hashcat publishes a Windows binary, so it is downloaded, checksum-verified
    and unpacked automatically. hcxtools publishes source only, so there is no
    official Windows binary to install: convert captures on the Linux laptop, or
    build hcxpcapngtool yourself and point --tools-dir at it.
    """
    tools_dir = Path(tools_dir or default_tools_dir())
    tools_dir.mkdir(parents=True, exist_ok=True)
    archive = tools_dir / f"hashcat-{HASHCAT_VERSION}.7z"
    if not archive.is_file() or sha256_file(archive) != HASHCAT_SHA256:
        download_verified(HASHCAT_URL, HASHCAT_SHA256, archive)
    print(f"Extracting {archive} ...")
    extract_archive(archive, tools_dir)
    found = find_tool("hashcat", [tools_dir])
    print("hashcat: " + (str(found) if found else "NOT FOUND after extraction"))
    print("hcxtools: no official Windows binary is published. Either")
    print("  * run the conversion on the Linux laptop (pacman -S hcxtools), or")
    print("  * build hcxpcapngtool yourself and place hcxpcapngtool.exe in " + str(tools_dir))
    return 0


class TowerConfig:
    def __init__(self, host, port, jobs_dir, tools_dir, wordlist_dirs, rule_dirs,
                 cert_path=None, key_path=None, tls=True, max_upload_mb=64, job_timeout=0):
        self.host = host
        self.port = port
        self.jobs_dir = Path(jobs_dir).resolve()
        self.tools_dir = Path(tools_dir).resolve() if tools_dir else None
        self.wordlist_dirs = [Path(d).resolve() for d in wordlist_dirs]
        self.rule_dirs = [Path(d).resolve() for d in rule_dirs]
        self.cert_path = Path(cert_path).resolve() if cert_path else None
        self.key_path = Path(key_path).resolve() if key_path else None
        self.tls = tls
        # serve() passes argparse defaults (None when the flag is absent).
        # Never let a None leak in, or every upload would crash do_POST.
        self.max_upload_mb = max_upload_mb or 64
        self.job_timeout = job_timeout or 0

    @property
    def potfile(self):
        return app_dir() / "tower.potfile"

    def tool_dirs(self):
        dirs = [self.tools_dir, default_tools_dir(), app_dir() / "tools"]
        seen, unique = set(), []
        for directory in dirs:
            if directory and directory not in seen:
                seen.add(directory)
                unique.append(directory)
        return unique


def discover_tools(config):
    dirs = config.tool_dirs()
    hashcat = find_tool("hashcat", dirs)
    hcxpcapngtool = find_tool("hcxpcapngtool", dirs)
    tools = {"hashcat": hashcat, "hcxpcapngtool": hcxpcapngtool, "backend": None, "backends": {}}
    if hashcat:
        try:
            version = run(str(hashcat), "--version").stdout.strip().splitlines()
            tools["hashcat_version"] = version[0] if version else "unknown"
        except (RuntimeError, OSError, subprocess.TimeoutExpired):
            tools["hashcat_version"] = "unknown"
        tools["backends"] = detect_backends(hashcat)
        tools["backend"] = preferred_backend(tools["backends"])
    if hashcat and not config.rule_dirs:
        shipped = Path(hashcat).resolve().parent / "rules"
        if shipped.is_dir():
            config.rule_dirs.append(shipped)
    return tools


BACKEND_IGNORE_FLAGS = {
    "cuda": "--backend-ignore-cuda",
    "hip": "--backend-ignore-hip",
    "opencl": "--backend-ignore-opencl",
    "metal": "--backend-ignore-metal",
}
BACKEND_ORDER = ("cuda", "hip", "metal", "opencl")


def detect_backends(hashcat):
    """Parse `hashcat -I` into {backend: [{id, type, name}]}.

    hashcat must run from its own directory so it can load the ./OpenCL kernels.
    """
    if hashcat is None:
        return {}
    try:
        result = subprocess.run([str(hashcat), "-I"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace", timeout=90,
                                cwd=str(Path(hashcat).resolve().parent))
    except (OSError, subprocess.TimeoutExpired):
        return {}
    backends, current, device = {}, None, None
    for line in result.stdout.splitlines():
        header = re.match(r"^\s*(CUDA|HIP|OpenCL|Metal|oneAPI) Info:", line)
        if header:
            current = header.group(1).lower()
            backends.setdefault(current, [])
            device = None
            continue
        start = re.match(r"^\s*Backend Device ID #(\d+)", line)
        if start and current is not None:
            device = {"id": int(start.group(1))}
            backends[current].append(device)
            continue
        if device is not None:
            field = re.match(r"^\s*([A-Za-z][A-Za-z ]*?)\s*\.+\s*:\s*(.+?)\s*$", line)
            if field:
                device[field.group(1).strip().lower()] = field.group(2)
    return backends


def preferred_backend(backends):
    """Pick the GPU backend: CUDA for NVIDIA, HIP/OpenCL for AMD, OpenCL for Intel."""
    for name in BACKEND_ORDER:
        if any(_is_gpu(name, device) for device in backends.get(name, [])):
            return name
    return None


def _is_gpu(backend, device):
    kind = (device.get("type") or "").lower()
    if kind:
        return "gpu" in kind
    # CUDA/HIP/Metal sections omit Type; their devices are always GPUs.
    return backend in ("cuda", "hip", "metal")


def backend_flags(chosen, available=None):
    """Ignore every detected backend except the chosen one.

    Only backends that hashcat actually reported are ignored, so we never pass
    an --backend-ignore-* flag for a backend this build does not support.
    """
    if not chosen:
        return []
    names = list(BACKEND_IGNORE_FLAGS) if available is None else list(available)
    return [BACKEND_IGNORE_FLAGS[name] for name in names
            if name in BACKEND_IGNORE_FLAGS and name != chosen]


def backend_summary(backends):
    lines = []
    for name in BACKEND_ORDER:
        for device in backends.get(name, []):
            lines.append(f"{name.upper()} {device.get('type', 'GPU')}: {device.get('name', 'unknown')}")
    return lines


def resolve_named(name, directories, suffixes):
    """Resolve a client-supplied wordlist/rule name against configured folders."""
    if not name or not isinstance(name, str):
        raise RuntimeError("Empty name in attack parameters.")
    if "/" in name or "\\" in name or name.startswith(".") or ".." in name:
        raise RuntimeError(f"Refusing suspicious name: {name}")
    for directory in directories:
        candidate = Path(directory) / name
        if candidate.is_file() and candidate.suffix.lower() in suffixes:
            return candidate.resolve()
    raise RuntimeError(f"Unknown or disallowed file: {name}")


def inventory(directories, suffixes):
    items = []
    for directory in directories:
        if not directory or not Path(directory).is_dir():
            continue
        for path in sorted(Path(directory).rglob("*")):
            if path.is_file() and path.suffix.lower() in suffixes:
                items.append({"name": path.name, "size": path.stat().st_size})
    seen, unique = set(), []
    for item in items:
        if item["name"] not in seen:
            seen.add(item["name"])
            unique.append(item)
    return unique


def sanitize_extra_args(args):
    if not args:
        return []
    if not isinstance(args, list):
        raise RuntimeError("extra_args must be a list.")
    clean_args, index = [], 0
    while index < len(args):
        token = args[index]
        if token not in EXTRA_HASHCAT_FLAGS:
            raise RuntimeError(f"hashcat flag not allowed: {token}")
        clean_args.append(token)
        arity = EXTRA_HASHCAT_FLAGS[token]
        if arity:
            if index + 1 >= len(args):
                raise RuntimeError(f"Missing value for {token}")
            clean_args.append(str(args[index + 1]))
            index += 2
        else:
            index += 1
    return clean_args


def build_hashcat_command(hashcat, hash_file, attack, out_file, potfile, config,
                          backend=None, available_backends=None):
    attack = attack or {}
    kind = attack.get("type", "dictionary")
    command = [str(hashcat), "-m", HASHCAT_MODE, str(hash_file),
               "-o", str(out_file), "--outfile-format", "2",
               "--potfile-path", str(potfile),
               "--restore-file-path", str(Path(out_file).parent / "hashcat.restore"),
               "--status", "--status-timer", "2", "--session", "tower"]
    rules = attack.get("rules") or []
    if kind == "dictionary":
        command.append(str(resolve_named(attack.get("wordlist"), config.wordlist_dirs, WORDLIST_SUFFIXES)))
        for rule in rules:
            command += ["-r", str(resolve_named(rule, config.rule_dirs, RULE_SUFFIXES))]
    elif kind == "mask":
        command += ["-a", "3", str(attack.get("mask") or "")]
    elif kind == "hybrid":
        wordlist = resolve_named(attack.get("wordlist"), config.wordlist_dirs, WORDLIST_SUFFIXES)
        mask = str(attack.get("mask") or "")
        order = attack.get("order", "wordlist-first")
        command += ["-a", "7", mask, str(wordlist)] if order == "mask-first" else \
                   ["-a", "6", str(wordlist), mask]
    elif kind == "combination":
        command += ["-a", "1",
                    str(resolve_named(attack.get("wordlist"), config.wordlist_dirs, WORDLIST_SUFFIXES)),
                    str(resolve_named(attack.get("wordlist2"), config.wordlist_dirs, WORDLIST_SUFFIXES))]
    else:
        raise RuntimeError(f"Unknown attack type: {kind}")
    chosen = str(attack.get("backend") or backend or "").lower()
    if chosen not in BACKEND_IGNORE_FLAGS:
        chosen = backend if backend in BACKEND_IGNORE_FLAGS else None
    command += backend_flags(chosen, available_backends)
    # Enforce the server's job runtime limit. hashcat --runtime stops the
    # session gracefully after N seconds instead of us having to kill it.
    if getattr(config, "job_timeout", 0):
        command += ["--runtime", str(int(config.job_timeout))]
    command += sanitize_extra_args(attack.get("extra_args"))
    return command


STATUS_PATTERNS = {
    "hash_rate": re.compile(r"^Speed\.#\d+\.*:\s+(.+?)\s*$"),
    "eta": re.compile(r"^Time\.Estimated\.*:\s+(.+?)\s*$"),
    "guess_base": re.compile(r"^Guess\.Base\.*:\s+(.+?)\s*$"),
    "guess_mod": re.compile(r"^Guess\.Mod\.*:\s+(.+?)\s*$"),
    "candidates": re.compile(r"^Candidates\.#\d+\.*:\s+(.+?)\s*$"),
    "monitor": re.compile(r"^Hardware\.Mon\.#\d+\.*:\s+(.+?)\s*$"),
}
PROGRESS_RE = re.compile(r"^Progress\.*:\s+(\d+)/(\d+)\s+\(([\d.]+)%\)")
RECOVERED_RE = re.compile(r"^Recovered\.*:\s+(\d+)/(\d+)")


def parse_hashcat_status(line):
    line = line.rstrip("\r\n")
    update = {}
    match = PROGRESS_RE.match(line)
    if match:
        update["progress"] = float(match.group(3))
    match = RECOVERED_RE.match(line)
    if match:
        update["recovered"] = f"{match.group(1)}/{match.group(2)}"
    for field, pattern in STATUS_PATTERNS.items():
        match = pattern.match(line)
        if not match:
            continue
        value = match.group(1)
        if field == "hash_rate":
            update["hash_rate"] = value
        elif field == "eta":
            update["eta"] = value
        elif field == "monitor":
            gpu = {}
            temp = re.search(r"Temp:\s*(\d+)c", value)
            util = re.search(r"Util:\s*(\d+)%", value)
            if temp:
                gpu["temp"] = int(temp.group(1))
            if util:
                gpu["util"] = int(util.group(1))
            if gpu:
                update["gpu"] = gpu
        else:
            update.setdefault("candidate_parts", {})[field] = value
    parts = update.pop("candidate_parts", None)
    if parts:
        labels = {"guess_base": "base", "guess_mod": "rules", "candidates": "candidates"}
        update["candidate"] = " | ".join(f"{labels[k]}: {v}" for k, v in parts.items())
    return update


class JobStore:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.condition = threading.Condition(self.lock)
        self.jobs = {}
        self.queue = collections.deque()
        self.cancel_requested = set()
        self._load()

    def _status_path(self, job_id):
        return self.root / job_id / "status.json"

    def _save(self, job):
        path = self._status_path(job["id"])
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"status.{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps(job, indent=2), encoding="utf-8")
        for attempt in range(5):
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.05)

    def _load(self):
        for path in sorted(self.root.glob("*/status.json")):
            try:
                job = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not job.get("id"):
                continue
            if job.get("state") in ("queued", "converting", "running"):
                job["state"] = "queued"
                with self.lock:
                    self.jobs[job["id"]] = job
                    self.queue.append(job["id"])
                    self._save(job)
            else:
                with self.lock:
                    self.jobs[job["id"]] = job

    def create(self, attack, filename, data=None):
        job_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
        job = {"id": job_id, "created": time.time(), "state": "queued",
               "filename": filename, "attack": attack, "progress": 0.0,
               "hash_rate": None, "gpu": {}, "eta": None, "candidate": None,
               "recovered": None, "result": None, "error": None, "updated": time.time()}
        job_dir = self.root / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        if data is not None:
            (job_dir / filename).write_bytes(data)
        with self.lock:
            self.jobs[job_id] = job
            self.queue.append(job_id)
            self._save(job)
            self.condition.notify_all()
        return job

    def get(self, job_id):
        with self.lock:
            job = self.jobs.get(job_id)
            return dict(job) if job else None

    def update(self, job_id, **fields):
        with self.lock:
            job = self.jobs.get(job_id)
            if job is None:
                return None
            job.update(fields)
            job["updated"] = time.time()
            self._save(job)
            snapshot = dict(job)
            self.condition.notify_all()
        return snapshot

    def listing(self):
        with self.lock:
            return [dict(j) for j in sorted(self.jobs.values(),
                                            key=lambda item: item["created"], reverse=True)]

    def take_next(self, timeout):
        with self.lock:
            if not self.queue:
                self.condition.wait(timeout)
            if not self.queue:
                return None
            job_id = self.queue.popleft()
            self.jobs[job_id]["state"] = "running"
            self._save(self.jobs[job_id])
            return dict(self.jobs[job_id])

    def cancel(self, job_id):
        with self.lock:
            job = self.jobs.get(job_id)
            if job is None:
                return False
            if job["state"] in ("done", "failed", "cancelled"):
                return False
            self.cancel_requested.add(job_id)
            self.condition.notify_all()
        return True

    def is_cancelled(self, job_id):
        with self.lock:
            return job_id in self.cancel_requested

    def job_dir(self, job_id):
        return self.root / job_id


def read_cracked(out_file):
    out_file = Path(out_file)
    if not out_file.is_file():
        return None
    lines = [line.rstrip("\r\n") for line in out_file.read_text(encoding="utf-8", errors="replace").splitlines()]
    lines = [line for line in lines if line]
    return lines[-1] if lines else None


def is_capture_like(body):
    if len(body) < 4:
        return False
    magic = body[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",
                 b"\x0a\x0d\x0d\x0a"):
        return True
    head = body[:16].decode("ascii", errors="ignore")
    return head.startswith("WPA*") or head.startswith("22000*")


WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ws_accept_key(key):
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()


def ws_frame(payload, opcode=0x1):
    payload = payload if isinstance(payload, bytes) else payload.encode()
    header = bytearray([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header.append(length)
    elif length < 65536:
        header.append(126)
        header += struct.pack("!H", length)
    else:
        header.append(127)
        header += struct.pack("!Q", length)
    return bytes(header) + payload


def recv_exact(sock, count):
    chunks = bytearray()
    while len(chunks) < count:
        chunk = sock.recv(count - len(chunks))
        if not chunk:
            raise ConnectionError("peer closed")
        chunks += chunk
    return bytes(chunks)


def ws_read(sock, timeout):
    sock.settimeout(timeout)
    try:
        header = recv_exact(sock, 2)
    except socket.timeout:
        return "timeout", b""
    except (ConnectionError, OSError):
        return "error", b""
    opcode = header[0] & 0x0F
    masked = bool(header[1] & 0x80)
    length = header[1] & 0x7F
    try:
        if length == 126:
            length = struct.unpack("!H", recv_exact(sock, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", recv_exact(sock, 8))[0]
        mask = recv_exact(sock, 4) if masked else None
        payload = recv_exact(sock, length) if length else b""
    except (socket.timeout, ConnectionError, OSError):
        return "error", b""
    if mask:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return {0x8: "close", 0x9: "ping", 0xA: "pong", 0x1: "text", 0x2: "binary"}.get(opcode, "binary"), payload


def read_http_headers(sock):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode("iso-8859-1", errors="replace")


def _openssl_self_signed(cert_path, key_path):
    openssl = shutil.which("openssl")
    if not openssl:
        return False
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                             "-keyout", str(key_path), "-out", str(cert_path), "-days", "3650",
                             "-subj", "/CN=wifi-handshake-tower"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        print(clean(result.stderr[-400:]))
        return False
    print(f"Generated self-signed certificate via openssl: {cert_path}")
    return True


def generate_self_signed(cert_path, key_path, host):
    try:
        import datetime
        import ipaddress
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        return _openssl_self_signed(cert_path, key_path)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wifi-handshake-tower")])
    alt = [x509.DNSName("localhost")]
    for candidate in {host, socket.gethostname()}:
        if not candidate or candidate in ("0.0.0.0", "::"):
            continue
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(candidate)))
        except ValueError:
            alt.append(x509.DNSName(candidate))
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .sign(key, hashes.SHA256()))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    print(f"Generated self-signed certificate: {cert_path}")
    return True


def ensure_server_context(config):
    if not config.tls:
        print("WARNING: TLS disabled. Capture and password travel unencrypted; "
              "Tailscale still encrypts the tunnel between devices.")
        return None
    if config.cert_path and config.key_path and config.cert_path.is_file() and config.key_path.is_file():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(config.cert_path), str(config.key_path))
        return context
    cert_path = config.cert_path or (app_dir() / "tower-cert.pem")
    key_path = config.key_path or (app_dir() / "tower-key.pem")
    if not (cert_path.is_file() and key_path.is_file()) and not generate_self_signed(cert_path, key_path, config.host):
        print("WARNING: no certificate available; serving plain HTTP.")
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))
    config.cert_path, config.key_path = cert_path, key_path
    return context


class TowerWorker(threading.Thread):
    def __init__(self, store, config, tools):
        super().__init__(daemon=True, name="tower-worker")
        self.store = store
        self.config = config
        self.tools = tools
        self.stop_event = threading.Event()
        self.procs = {}
        self.proc_lock = threading.Lock()

    def stop(self):
        self.stop_event.set()
        with self.proc_lock:
            procs = list(self.procs.values())
        for proc in procs:
            try:
                proc.terminate()
            except OSError:
                pass

    def run(self):
        while not self.stop_event.is_set():
            job = self.store.take_next(timeout=1.0)
            if job is None:
                continue
            job_id = job["id"]
            if self.store.is_cancelled(job_id):
                self.store.update(job_id, state="cancelled")
                continue
            try:
                self.process(job)
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
                self.store.update(job_id, state="failed", error=clean(str(exc)))
            except Exception as exc:  # keep the worker alive on unexpected errors
                self.store.update(job_id, state="failed",
                                  error=f"{type(exc).__name__}: {clean(str(exc))}")

    def process(self, job):
        job_id = job["id"]
        job_dir = self.store.job_dir(job_id)
        upload = job_dir / job["filename"]
        hashcat = self.tools.get("hashcat")
        if hashcat is None:
            raise RuntimeError("hashcat was not found on the tower. Run --install-tools.")
        if not upload.is_file():
            raise RuntimeError("Uploaded capture is missing.")
        hash_file = upload
        if upload.suffix.lower() != ".hc22000":
            converter = self.tools.get("hcxpcapngtool")
            if converter is None:
                raise RuntimeError("Upload is a raw capture but hcxpcapngtool is not available on the "
                                   "tower. Convert on the laptop or install hcxtools.")
            self.store.update(job_id, state="converting")
            hash_file = job_dir / "capture.hc22000"
            result = subprocess.run([str(converter), "-o", str(hash_file), str(upload)],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding="utf-8", errors="replace", timeout=300)
            (job_dir / "convert.log").write_text(result.stdout or "", encoding="utf-8")
            if not hash_file.is_file() or hash_file.stat().st_size == 0:
                raise RuntimeError("hcxpcapngtool produced no usable hashes: " +
                                   clean((result.stdout or "")[-400:]))
        out_file = job_dir / "cracked.txt"
        command = build_hashcat_command(hashcat, hash_file, job["attack"], out_file,
                                        self.config.potfile, self.config,
                                        self.tools.get("backend"),
                                        list(self.tools.get("backends") or {}))
        self.store.update(job_id, state="running", command=[str(part) for part in command])
        last_save = 0.0
        with (job_dir / "hashcat.log").open("w", encoding="utf-8") as log:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding="utf-8", errors="replace",
                                    cwd=str(Path(hashcat).resolve().parent))
            with self.proc_lock:
                self.procs[job_id] = proc
            try:
                for line in proc.stdout:
                    log.write(line)
                    update = parse_hashcat_status(line)
                    now = time.monotonic()
                    if update and now - last_save >= 1.0:
                        self.store.update(job_id, **update)
                        last_save = now
                    if self.store.is_cancelled(job_id):
                        proc.terminate()
                        break
            finally:
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                # hashcat writes <session>.log next to its executable; we keep
                # our own copy in the job folder, so drop the stray one.
                (Path(hashcat).resolve().parent / "tower.log").unlink(missing_ok=True)
                with self.proc_lock:
                    self.procs.pop(job_id, None)
        if self.store.is_cancelled(job_id):
            self.store.update(job_id, state="cancelled")
            return
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"hashcat exited with code {proc.returncode}. See hashcat.log.")
        password = read_cracked(out_file)
        self.store.update(job_id, state="done", progress=100.0,
                          result={"found": password is not None, "password": password})


class TowerServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class TowerHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "wifi-handshake-tower"

    def log_message(self, fmt, *args):
        print(f"[tower] {self.address_string()} {fmt % args}", flush=True)

    @property
    def store(self):
        return self.server.store

    @property
    def config(self):
        return self.server.config

    @property
    def tools(self):
        return self.server.tools

    def send_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def health(self):
        hashcat = self.tools.get("hashcat")
        return {"ok": True, "protocol": PROTOCOL_VERSION, "os": os.name,
                "hashcat": str(hashcat) if hashcat else None,
                "hashcat_version": self.tools.get("hashcat_version"),
                "hcxpcapngtool": str(self.tools["hcxpcapngtool"]) if self.tools.get("hcxpcapngtool") else None,
                "backend": self.tools.get("backend"),
                "devices": backend_summary(self.tools.get("backends") or {}),
                "queue": len(self.store.queue)}

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/v1/health":
            return self.send_json(200, self.health())
        if path == "/api/v1/wordlists":
            return self.send_json(200, {
                "wordlists": inventory(self.config.wordlist_dirs, WORDLIST_SUFFIXES),
                "rules": inventory(self.config.rule_dirs, RULE_SUFFIXES)})
        if path == "/api/v1/jobs":
            return self.send_json(200, {"jobs": self.store.listing()})
        match = re.fullmatch(r"/api/v1/jobs/([0-9A-Za-z._-]+)(/events|/result)?", path)
        if match:
            job_id, suffix = match.group(1), match.group(2)
            job = self.store.get(job_id)
            if job is None:
                return self.send_json(404, {"error": "unknown job"})
            if suffix == "/events":
                if self.headers.get("Upgrade", "").lower() == "websocket":
                    return self.stream_events(job_id)
                return self.send_json(200, {"job": job})
            if suffix == "/result":
                return self.send_json(200, {"id": job_id, "state": job["state"],
                                            "result": job.get("result"), "error": job.get("error")})
            return self.send_json(200, {"job": job})
        return self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path != "/api/v1/jobs":
            return self.send_json(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.send_json(400, {"error": "invalid Content-Length"})
        if length <= 0 or length > self.config.max_upload_mb * 1024 * 1024:
            return self.send_json(413, {"error": f"upload must be 1..{self.config.max_upload_mb} MiB"})
        try:
            attack = json.loads(base64.b64decode(self.headers.get("X-Attack", "")).decode())
        except (ValueError, UnicodeDecodeError):
            return self.send_json(400, {"error": "missing or invalid X-Attack header"})
        filename = Path(self.headers.get("X-Filename", "capture.bin")).name
        if filename in ("", ".", ".."):
            filename = "capture.bin"
        body = self.rfile.read(length)
        if not is_capture_like(body):
            return self.send_json(400, {"error": "body does not look like a capture"})
        job = self.store.create(attack, filename, body)
        return self.send_json(201, {"job_id": job["id"]})

    def do_DELETE(self):
        match = re.fullmatch(r"/api/v1/jobs/([0-9A-Za-z._-]+)", urllib.parse.urlparse(self.path).path)
        if not match:
            return self.send_json(404, {"error": "not found"})
        if self.store.cancel(match.group(1)):
            return self.send_json(202, {"cancelled": match.group(1)})
        return self.send_json(409, {"error": "job not cancellable"})

    def stream_events(self, job_id):
        key = self.headers.get("Sec-WebSocket-Key", "")
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", ws_accept_key(key))
        self.end_headers()
        sock = self.connection
        self.close_connection = True
        try:
            while True:
                job = self.store.get(job_id)
                if job is None:
                    break
                sock.sendall(ws_frame(json.dumps({"type": "status", "job": job})))
                if job["state"] in ("done", "failed", "cancelled"):
                    break
                op, _ = ws_read(sock, 1.0)
                if op in ("close", "error"):
                    break
                if op == "ping":
                    sock.sendall(ws_frame(b"", opcode=0xA))
        except OSError:
            pass


def serve(args):
    host = getattr(args, "host", None) or args.bind
    config = TowerConfig(
        host=host, port=args.port,
        jobs_dir=args.jobs_dir or (app_dir() / "jobs"),
        tools_dir=args.tools_dir or (app_dir() / "tools"),
        wordlist_dirs=args.wordlist_dirs or [app_dir() / "wordlists"],
        rule_dirs=list(args.rule_dirs or []),
        cert_path=args.cert, key_path=args.key, tls=not args.no_tls,
        max_upload_mb=args.max_upload_mb, job_timeout=args.job_timeout)
    config.jobs_dir.mkdir(parents=True, exist_ok=True)
    config.potfile.parent.mkdir(parents=True, exist_ok=True)
    for directory in config.wordlist_dirs:
        directory.mkdir(parents=True, exist_ok=True)
    tools = discover_tools(config)
    print(f"Tower tools: hashcat={tools.get('hashcat')} hcxpcapngtool={tools.get('hcxpcapngtool')}")
    devices = backend_summary(tools.get("backends") or {})
    print(f"GPU backend: {tools.get('backend') or 'auto (none detected)'}")
    for line in devices:
        print("  " + line)
    if not tools.get("hashcat"):
        print("WARNING: hashcat not found. Jobs will fail until it is installed (--install-tools).")
    store = JobStore(config.jobs_dir)
    worker = TowerWorker(store, config, tools)
    worker.start()
    server = TowerServer((config.host, config.port), TowerHandler)
    server.store, server.config, server.tools = store, config, tools
    context = ensure_server_context(config)
    if context:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    scheme = "https" if context else "http"
    print(f"Tower listening on {scheme}://{config.host}:{config.port}")
    print(f"Jobs: {config.jobs_dir}  Wordlists: {[str(d) for d in config.wordlist_dirs]}")
    tailnet = tailscale_status()
    if tailnet and tailnet["state"] == "Running" and tailnet["self_ip"]:
        print(f"Reachable in the tailnet as {tailnet['self_ip']} "
              f"(use: --tower https://{tailnet['self_ip']}:{config.port})")
    print("No authentication: anyone on the Tailscale network can submit jobs.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down tower...")
    finally:
        worker.stop()
        server.shutdown()
        server.server_close()
    return 0


def known_hosts_path():
    return app_dir() / "known_hosts.json"


def known_fingerprint(host, port):
    path = known_hosts_path()
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8")).get(f"{host}:{port}")
    except (OSError, ValueError):
        return None


def remember_fingerprint(host, port, fingerprint):
    path = known_hosts_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {}
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
    data[f"{host}:{port}"] = fingerprint
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


class TowerClient:
    def __init__(self, url, fingerprint=None, insecure=False, timeout=60, confirm=None):
        parsed = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
        self.scheme = parsed.scheme or "https"
        self.host = parsed.hostname or "localhost"
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.timeout = timeout
        self.fingerprint = fingerprint
        self.insecure = insecure
        self.confirm = confirm or (lambda digest: input(
            f"Tower certificate fingerprint (sha256): {digest}\n"
            "Trust this tower and remember it? Type YES: ").strip() == "YES")
        self.last_fingerprint = None

    def base(self):
        return f"{self.host}:{self.port}"

    def _context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def _verify_peer(self, sock):
        if self.scheme != "https" or self.insecure:
            return
        der = sock.getpeercert(binary_form=True)
        if not der:
            raise RuntimeError("Tower presented no certificate.")
        digest = hashlib.sha256(der).hexdigest()
        self.last_fingerprint = digest
        expected = (self.fingerprint or known_fingerprint(self.host, self.port) or "").replace(":", "").lower()
        if not expected:
            if not self.confirm(digest):
                raise RuntimeError("Tower certificate not trusted.")
            remember_fingerprint(self.host, self.port, digest)
            return
        if digest.lower() != expected:
            raise RuntimeError(f"Certificate fingerprint mismatch. Expected {expected}, got {digest}.")

    def _open_socket(self):
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.scheme == "https":
            sock = self._context().wrap_socket(raw, server_hostname=self.host)
            self._verify_peer(sock)
            return sock
        return raw

    def request(self, method, path, body=None, headers=None):
        if self.scheme == "https":
            conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout,
                                               context=self._context())
            conn.connect()
            self._verify_peer(conn.sock)
        else:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            data = response.read()
            if response.status >= 400:
                raise RuntimeError(f"Tower error {response.status}: {clean(data.decode(errors='replace')[:400])}")
            return json.loads(data.decode()) if data else {}
        finally:
            conn.close()

    def health(self):
        return self.request("GET", "/api/v1/health")

    def wordlists(self):
        return self.request("GET", "/api/v1/wordlists")

    def create_job(self, capture_path, attack):
        body = Path(capture_path).read_bytes()
        headers = {"Content-Type": "application/octet-stream",
                   "X-Attack": base64.b64encode(json.dumps(attack).encode()).decode(),
                   "X-Filename": Path(capture_path).name}
        return self.request("POST", "/api/v1/jobs", body=body, headers=headers)

    def job(self, job_id):
        return self.request("GET", f"/api/v1/jobs/{job_id}")["job"]

    def stream_events(self, job_id, on_status):
        try:
            sock = self._open_socket()
        except (OSError, RuntimeError):
            return False
        try:
            key = base64.b64encode(os.urandom(16)).decode()
            request = (f"GET /api/v1/jobs/{job_id}/events HTTP/1.1\r\nHost: {self.base()}\r\n"
                       f"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                       f"Sec-WebSocket-Version: 13\r\n\r\n")
            sock.sendall(request.encode())
            if " 101 " not in read_http_headers(sock).split("\r\n", 1)[0]:
                return False
            while True:
                op, payload = ws_read(sock, 10.0)
                if op == "timeout":
                    return True
                if op in ("close", "error"):
                    return op == "close"
                if op == "ping":
                    sock.sendall(ws_frame(b"", opcode=0xA))
                    continue
                if op in ("text", "binary") and payload:
                    job = json.loads(payload.decode()).get("job")
                    if job:
                        on_status(job)
                        if job.get("state") in ("done", "failed", "cancelled"):
                            return True
        except (OSError, ValueError, RuntimeError):
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass


def print_job_line(job):
    gpu = job.get("gpu") or {}
    parts = [job.get("state", "?")]
    if job.get("progress") is not None:
        parts.append(f"{job['progress']:.1f}%")
    if job.get("hash_rate"):
        parts.append(job["hash_rate"])
    if gpu.get("temp") is not None:
        parts.append(f"{gpu['temp']}C")
    if gpu.get("util") is not None:
        parts.append(f"util {gpu['util']}%")
    if job.get("eta"):
        parts.append(f"ETA {job['eta']}")
    if job.get("candidate"):
        parts.append(job["candidate"])
    if job.get("recovered"):
        parts.append(f"recovered {job['recovered']}")
    print("  " + " | ".join(parts), flush=True)


def choose_attack(client, attack_file=None):
    if attack_file:
        return json.loads(Path(attack_file).read_text(encoding="utf-8"))
    listing = client.wordlists()
    wordlists = listing.get("wordlists", [])
    rules = listing.get("rules", [])
    print("\nAttack type:")
    print("  1. Dictionary (wordlist, optional rules)")
    print("  2. Mask / brute force (e.g. ?d?d?d?d?d?d?d?d)")
    print("  3. Hybrid (wordlist + mask)")
    print("  4. Combination (two wordlists)")
    kind = choose("Attack type, or q: ", 4)
    attack = {}
    if kind in (0, 2, 3):
        if not wordlists:
            raise RuntimeError("The tower lists no wordlists. Add .txt files to its wordlist folder.")
        print("\nWordlists:")
        for index, item in enumerate(wordlists, 1):
            print(f"  {index}. {item['name']} ({item['size']} bytes)")
        attack["wordlist"] = wordlists[choose("Wordlist, or q: ", len(wordlists))]["name"]
    if kind == 0:
        attack["type"] = "dictionary"
        if rules and input("Add rules? Type y to choose: ").strip().lower() == "y":
            print("\nRule sets:")
            for index, item in enumerate(rules, 1):
                print(f"  {index}. {item['name']}")
            attack["rules"] = [rules[choose("Rule set, or q: ", len(rules))]["name"]]
    elif kind == 1:
        attack["type"] = "mask"
        attack["mask"] = input("Mask (e.g. ?d?d?d?d?d?d?d?d): ").strip()
    elif kind == 2:
        attack["type"] = "hybrid"
        attack["mask"] = input("Mask: ").strip()
        attack["order"] = "wordlist-first"
    elif kind == 3:
        attack["type"] = "combination"
        print("\nSecond wordlist:")
        for index, item in enumerate(wordlists, 1):
            print(f"  {index}. {item['name']}")
        attack["wordlist2"] = wordlists[choose("Second wordlist, or q: ", len(wordlists))]["name"]
    return attack


def watch_job(client, job_id, tower_url):
    seen = {"line": None}

    def on_status(job):
        line = json.dumps([job.get("state"), job.get("progress"), job.get("hash_rate")])
        if line != seen["line"]:
            seen["line"] = line
            print_job_line(job)

    streamed = client.stream_events(job_id, on_status)
    job = client.job(job_id)
    deadline = time.monotonic() + 1800
    while job.get("state") not in ("done", "failed", "cancelled") and time.monotonic() < deadline:
        if not streamed:
            print_job_line(job)
        time.sleep(3)
        job = client.job(job_id)
    if job.get("state") not in ("done", "failed", "cancelled"):
        print(f"Still running. Reattach with: --tower {tower_url} --watch {job_id}")
        return 0
    result = job.get("result") or {}
    if job["state"] == "failed":
        print(f"Tower error: {job.get('error')}")
    elif result.get("found"):
        print(f"Password found: {result['password']}")
    else:
        print("Password not found with this attack.")
    return 0


def prepare_capture(path):
    """Convert .pcapng to .hc22000 on the laptop when hcxtools is available.

    hcxtools publishes no official Windows binary, so conversion normally
    happens here. The tower still converts as a fallback if it has the tool.
    """
    path = Path(path)
    if path.suffix.lower() == ".hc22000":
        return path
    converter = find_tool("hcxpcapngtool")
    if converter is None:
        print("hcxpcapngtool not found locally; sending the raw capture for the tower to convert.")
        return path
    out = path.with_suffix(".hc22000")
    result = subprocess.run([str(converter), "-o", str(out), str(path)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if result.returncode or not out.is_file() or out.stat().st_size == 0:
        print("Local conversion produced no hashes; sending the raw capture instead.")
        out.unlink(missing_ok=True)
        return path
    print(f"Converted locally: {out}")
    return out


def send_capture(args):
    client = TowerClient(args.tower, fingerprint=args.fingerprint, insecure=args.insecure)
    health = client.health()
    print(f"Tower: hashcat={health.get('hashcat_version')} hcxpcapngtool={health.get('hcxpcapngtool')}")
    capture_path = prepare_capture(args.send)
    attack = choose_attack(client, args.attack)
    print("Attack: " + json.dumps(attack))
    job_id = client.create_job(capture_path, attack)["job_id"]
    print(f"Job queued: {job_id}")
    return watch_job(client, job_id, args.tower)


def reattach(args):
    client = TowerClient(args.tower, fingerprint=args.fingerprint, insecure=args.insecure)
    return watch_job(client, args.watch, args.tower)


def self_test():
    """Use synthetic offline packets to test the actual tshark field names and export."""
    ap, client = "02:11:22:33:44:55", "02:aa:bb:cc:dd:ee"
    nonce_a, nonce_s = "11" * 32, "22" * 32
    def row(n, msg, counter, nonce, sta=client, timestamp=None, pairwise="1"):
        source, dest = (ap, sta) if msg in (1, 3) else (sta, ap)
        return "\t".join(map(str, [n, timestamp if timestamp is not None else n,
                                    ap, source, dest, msg, counter, nonce, pairwise, "3"]))
    good = [row(1, 1, 5, nonce_a), row(2, 2, 5, nonce_s),
            row(3, 3, 6, nonce_a), row(4, 4, 6, "00" * 32)]
    def test_rows(rows):
        tracker = Handshake(ap)
        result = None
        for line in rows:
            result = tracker.feed(line)
        return result
    assert len(test_rows(good)) == 4
    assert test_rows(good[1:]) is None
    assert test_rows([good[0], row(2, 2, 4, nonce_s), *good[2:]]) is None
    assert test_rows([*good[:2], row(3, 3, 6, "33" * 32), good[3]]) is None
    assert test_rows([*good[:3], row(4, 4, 6, "00" * 32, sta="02:00:00:00:00:01")]) is None
    assert test_rows([*good[:3], row(4, 4, 6, "00" * 32, timestamp=40)]) is None
    assert test_rows([*good[:3], row(4, 4, 6, "00" * 32, pairwise="0")]) is None
    assert test_rows([good[0], good[0], *good[1:]]) is not None
    tracker = Handshake(ap)
    assert tracker.feed("\t".join(["1", "1.0", ap, ap, client, "", "", "", "", ""])) is None
    assert tracker.feed(good[0].replace(ap, "02:00:00:00:00:01")) is None
    # Check that ordinary traffic and another AP's handshake are distinguished.
    stats = CaptureStats(ap)
    tracker = Handshake(ap)
    with contextlib.redirect_stdout(io.StringIO()):
        ordinary = "\t".join(["1", "1.0", ap, ap, client, "", "", "", "", ""])
        stats.feed(ordinary, None)
        stats.feed(good[0].replace(ap, "02:00:00:00:00:01"), None)
        for line in good:
            tracker.feed(line)
            stats.feed(line, tracker.last_frame)
        stats.report(10)
    assert stats.total == 6 and stats.target == 5 and stats.other_keys == 1
    assert stats.target_keys == 4 and all(stats.accepted[str(i)] == 1 for i in range(1, 5))
    sample = f"{ap}, first, last, 6, 54, WPA2, CCMP, PSK, -48, 2, 0, 0, 4, Test,\n"
    network = parse_networks(sample)[0]
    assert network["channel"] == 6 and network["security"] == "WPA2 / CCMP / PSK"
    assert network["frequency"] is None
    # A channel number can be resolved to its frequency for the capture step.
    resolved = parse_networks(sample, {6: [2437.0]})[0]
    assert resolved["frequency"] == 2437.0
    assert resolved["clients"] == []
    # Associated clients are parsed from the station section of the airodump CSV.
    with_clients = parse_networks(sample
        + "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
        + f"02:aa:bb:cc:dd:ee, 0, 0, -40, 10, {ap}, Test\n")[0]
    assert with_clients["clients"] == ["02:aa:bb:cc:dd:ee"]
    assert clean("bad\x1b\nssid") == "bad??ssid"
    assert signal_label(-1) == "unknown"
    capabilities = "\n".join(["* 2412.0 MHz [1] (20 dBm)", "* 2462 MHz [11] (20 dBm)",
                               "* 5500.0 MHz [100] (no IR, radar detection)",
                               "* 5845.0 MHz [169] (disabled)", "* 5955 MHz [1] (20 dBm)"])
    assert radio_channels(capabilities) == {2412.0: 1, 2462.0: 11, 5500.0: 100, 5955.0: 1}
    assert band_for_frequency(2437) == "b" and band_for_frequency(5180) == "a"
    assert band_for_frequency(5955) == "6" and band_for_frequency(900) is None
    assert frequency_bands(2437) == {"b", "g"} and frequency_bands(5955) == {"6"}
    assert scan_channels(capabilities, "abg") == [2412.0, 2462.0, 5500.0]
    assert scan_channels(capabilities, "bg") == [2412.0, 2462.0]
    assert scan_channels(capabilities, "g") == [2412.0, 2462.0]
    assert scan_channels(capabilities, "a") == [5500.0]
    assert scan_channels(capabilities, "6") == [5955.0]
    assert scan_channels(capabilities, "abg6") == [2412.0, 2462.0, 5500.0, 5955.0]
    assert scan_channels(capabilities, "a", [100]) == [5500.0]
    assert scan_channels(capabilities, "abg6", [5955]) == [5955.0]
    assert scan_channels(capabilities, "abg", [2412]) == [2412.0]
    try:
        scan_channels(capabilities, "abg", [169])
    except RuntimeError:
        pass
    else:
        raise AssertionError("Disabled channel accepted")
    assert parse_channel_list("1,6,11") == [1, 6, 11]
    assert parse_channel_list("2412,5180") == [2412, 5180]
    try:
        parse_channel_list("9999")
    except argparse.ArgumentTypeError:
        pass
    else:
        raise AssertionError("out-of-range frequency accepted")
    # Channel tuning: `set freq <MHz>` is preferred, `set channel <n>` is only a
    # fallback and must refuse ambiguous channel numbers (2.4 GHz vs 6 GHz).
    class FakeAdapter:
        iface = "wlan0"
    FakeAdapter.capabilities = capabilities
    calls = []
    real_run = run
    class FakeResult:
        stdout = stderr = ""
        returncode = 0
    def recording_run(*args, **kwargs):
        calls.append(args)
        return FakeResult()
    def failing_freq_run(*args, **kwargs):
        calls.append(args)
        if "freq" in args:
            raise RuntimeError("simulated iw failure")
        return FakeResult()
    try:
        globals()["run"] = recording_run
        assert tune_channel(FakeAdapter(), {"channel": 11, "frequency": 2462.0}) == 2462.0
        assert calls[-1] == ("iw", "dev", "wlan0", "set", "freq", "2462")
        assert tune_channel(FakeAdapter(), {"channel": 11, "frequency": None}) == 2462.0
        assert calls[-1] == ("iw", "dev", "wlan0", "set", "channel", "11")
        globals()["run"] = failing_freq_run
        with contextlib.redirect_stderr(io.StringIO()):
            assert tune_channel(FakeAdapter(), {"channel": 11, "frequency": 2462.0}) == 2462.0
            assert calls[-1] == ("iw", "dev", "wlan0", "set", "channel", "11")
            try:
                tune_channel(FakeAdapter(), {"channel": 1, "frequency": 5955.0})
            except RuntimeError:
                pass
            else:
                raise AssertionError("ambiguous channel fallback accepted")
    finally:
        globals()["run"] = real_run
    # Tower: M1+M2 capture mode accepts the common short exchange.
    m12 = Handshake(ap, (1, 2))
    assert m12.feed(row(1, 1, 5, nonce_a)) is None
    found12 = m12.feed(row(2, 2, 5, nonce_s))
    assert found12 and [f["message"] for f in found12] == [1, 2]
    m12b = Handshake(ap, (1, 2))
    assert m12b.feed(row(2, 2, 5, nonce_s)) is None
    assert CaptureStats(ap, (1, 2)).messages == (1, 2)
    # Tower: hashcat status parsing.
    assert parse_hashcat_status("Speed.#1.........:  1234.5 kH/s (12.34ms) @ Accel:64")["hash_rate"].startswith("1234.5")
    assert parse_hashcat_status("Progress.........: 1000/2000 (50.00%)")["progress"] == 50.0
    assert parse_hashcat_status("Hardware.Mon.#1..: Temp: 65c Fan: 40% Util: 98%")["gpu"] == {"temp": 65, "util": 98}
    assert parse_hashcat_status("Recovered........: 1/1 (100.00%) Digests")["recovered"] == "1/1"
    assert parse_hashcat_status("Time.Estimated...: Fri Sep 25 10:00:00 2026 (2 hours, 3 mins)")["eta"].startswith("Fri")
    assert parse_hashcat_status("nothing here") == {}
    # Tower: extra hashcat flags are whitelisted.
    assert sanitize_extra_args(["-w", "3", "--force"]) == ["-w", "3", "--force"]
    for bad in (["--outfile", "x"], ["-o"], ["rm"], ["--potfile-path"], ["-w"]):
        try:
            sanitize_extra_args(bad)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"extra args accepted: {bad}")
    try:
        resolve_named("../secret.txt", [Path(".")], WORDLIST_SUFFIXES)
    except RuntimeError:
        pass
    else:
        raise AssertionError("path traversal accepted")
    assert is_capture_like(b"\x0a\x0d\x0d\x0a\x00\x00\x00\x00")
    assert is_capture_like(b"WPA*01*deadbeef")
    assert not is_capture_like(b"GET / HTTP/1.1")
    # Tower: websocket framing.
    assert ws_frame(b"hi") == b"\x81\x02hi"
    assert ws_frame(b"x" * 200)[:2] == b"\x81\x7e"
    assert ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    # Tower: GPU backend selection.
    assert preferred_backend({"cuda": [{"id": 1, "name": "NVIDIA GeForce RTX 4070 SUPER"}],
                              "opencl": [{"id": 2, "type": "GPU", "name": "NVIDIA GeForce RTX 4070 SUPER"}]}) == "cuda"
    assert preferred_backend({"opencl": [{"id": 1, "type": "GPU", "name": "AMD Radeon RX 7900"}]}) == "opencl"
    assert preferred_backend({"hip": [{"id": 1, "type": "GPU", "name": "AMD Radeon"}]}) == "hip"
    assert preferred_backend({"opencl": [{"id": 1, "type": "CPU", "name": "Intel CPU"}]}) is None
    assert preferred_backend({}) is None
    assert "--backend-ignore-opencl" in backend_flags("cuda")
    assert "--backend-ignore-cuda" not in backend_flags("cuda")
    assert backend_flags("cuda", ["cuda", "opencl"]) == ["--backend-ignore-opencl"]
    assert backend_flags("cuda", ["cuda"]) == []
    assert backend_flags(None) == []
    assert detect_backends(None) == {}
    # Tower: job store round-trip and attack command building.
    with tempfile.TemporaryDirectory(prefix="tower-store-") as tmp:
        store = JobStore(tmp)
        job = store.create({"type": "mask", "mask": "?d?d"}, "x.pcapng")
        assert store.get(job["id"])["state"] == "queued"
        taken = store.take_next(timeout=0)
        assert taken["id"] == job["id"] and taken["state"] == "running"
        store.update(job["id"], state="done", result={"found": True, "password": "abc"})
        assert JobStore(tmp).get(job["id"])["result"]["password"] == "abc"
        assert store.cancel("missing") is False
    with tempfile.TemporaryDirectory(prefix="tower-attack-") as tmp:
        wl_dir, rule_dir = Path(tmp) / "wl", Path(tmp) / "rules"
        wl_dir.mkdir(); rule_dir.mkdir()
        (wl_dir / "test.txt").write_text("password\n")
        (rule_dir / "test.rule").write_text(":\n")
        config = TowerConfig("127.0.0.1", 8443, Path(tmp) / "jobs", None, [wl_dir], [rule_dir])
        command = build_hashcat_command("hashcat", Path(tmp) / "h.hc22000",
                                        {"type": "dictionary", "wordlist": "test.txt", "rules": ["test.rule"]},
                                        Path(tmp) / "out.txt", Path(tmp) / "pot", config)
        assert str(wl_dir / "test.txt") in command and "-r" in command
        mask_command = build_hashcat_command("hashcat", Path(tmp) / "h.hc22000",
                                             {"type": "mask", "mask": "?d?d?d?d"},
                                             Path(tmp) / "out.txt", Path(tmp) / "pot", config)
        assert "-a" in mask_command and "3" in mask_command
        assert "--runtime" not in mask_command  # no limit configured
        config_limited = TowerConfig("127.0.0.1", 8443, Path(tmp) / "jobs", None,
                                     [wl_dir], [rule_dir], job_timeout=600)
        limited = build_hashcat_command("hashcat", Path(tmp) / "h.hc22000",
                                        {"type": "mask", "mask": "?d?d?d?d"},
                                        Path(tmp) / "out.txt", Path(tmp) / "pot", config_limited)
        assert limited[limited.index("--runtime") + 1] == "600"
        # serve() forwards argparse defaults; a None here used to crash every
        # upload (do_POST: None * 1024 * 1024). Defaults must survive.
        config_none = TowerConfig("127.0.0.1", 8443, Path(tmp) / "jobs", None,
                                  [wl_dir], [rule_dir], max_upload_mb=None, job_timeout=None)
        assert config_none.max_upload_mb == 64 and config_none.job_timeout == 0
        parsed = build_parser().parse_args([])
        assert parsed.max_upload_mb == 64 and parsed.job_timeout == 0
    if not shutil.which("tshark"):
        print("Self-test passed (pure logic, tower protocol, attack building). "
              "tshark not found; skipping the offline packet test.")
        return
    with tempfile.TemporaryDirectory(prefix="wifi-handshake-test-") as tmp:
        raw = Path(tmp) / "synthetic.pcap"
        mac = lambda value: bytes.fromhex(value.replace(":", ""))
        with raw.open("wb") as file:
            # Classic pcap, link type IEEE 802.11; no real radio traffic.
            file.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 105))
            for i, (info, replay, nonce) in enumerate([
                    (0x008a, 5, nonce_a), (0x010a, 5, nonce_s),
                    (0x03ca, 6, nonce_a), (0x030a, 6, "00" * 32)], 1):
                from_ap = i in (1, 3)
                header = struct.pack("<HH", 0x0208 if from_ap else 0x0108, 0)
                header += mac(client if from_ap else ap) + mac(ap if from_ap else client)
                header += mac(ap) + struct.pack("<H", i << 4)
                key = struct.pack("!BHHQ", 2, info, 16, replay) + bytes.fromhex(nonce)
                key += bytes(16 + 8 + 8) + (bytes([0x55]) * 16 if i != 1 else bytes(16))
                key += struct.pack("!H", 0)
                packet = header + bytes.fromhex("aaaa03000000888e")
                packet += struct.pack("!BBH", 2, 3, len(key)) + key
                file.write(struct.pack("<IIII", i, 0, len(packet), len(packet)) + packet)
        # Feed synthetic packets through capture stdin, not offline -r mode.
        # This exercises live-capture option validation without using a radio.
        copy = Path(tmp) / "copy.pcapng"
        command = capture_command("-", copy, 10, 1)
        assert "-Y" not in command
        dumpcap = shutil.which("dumpcap")
        if dumpcap and os.access(dumpcap, os.X_OK):
            result = subprocess.run(command, input=raw.read_bytes(), stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=20)
            if result.returncode:
                raise RuntimeError("Synthetic capture test failed: " + result.stderr.decode(errors="replace"))
            decoded = result.stdout.decode(errors="replace")
            print("Synthetic stdin capture passed using the production capture options.")
        else:
            print("SKIPPED synthetic stdin capture: no permission to execute dumpcap.")
            print("Run sudo ./wifi-handshake.py --self-test to include that check. No radio is used.")
            decoded = run("tshark", "-n", "-l", "-r", str(raw), "-w", str(copy), "-P",
                          *field_options()).stdout
        found = test_rows(decoded.splitlines())
        assert found and [f["message"] for f in found] == [1, 2, 3, 4], decoded
        exported = Path(tmp) / "handshake.pcapng"
        save_capture(raw, found, network, exported)
        assert exported.stat().st_size > 0
        decoded_again = run("tshark", "-n", "-r", str(exported), *field_options()).stdout
        assert test_rows(decoded_again.splitlines())
    # Optional real-world regression: run against a downloaded example capture
    # (see --download-captures). Skipped silently when the file is absent.
    example_dir = Path(__file__).resolve().parent / "test-captures"
    for name, (essid, password) in KNOWN_EXAMPLE_PASSWORDS.items():
        example = example_dir / name
        if not example.is_file():
            continue
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = inspect_capture(example, essid, password)
        assert result["handshakes"] >= 1, f"{name}: no handshake found"
        assert result["mismatched"] == 0 and result["verified"] >= 1, \
            f"{name}: MIC verification failed"
        print(f"Self-test: verified example capture {name} (WPA2 MIC).")
    print("Self-test passed: parsing, signal labels, channel tuning, client detection, "
          "handshake matching (M1+M2 and M1-M4), offline MIC verification, tower protocol, "
          "hashcat status parsing, attack building, tshark decoding and export.")
    print("No adapter changes, network access or radio capture performed.")



# ---------------------------------------------------------------------------
# Platform support and interactive menu.
#
# Terminal modes: the default start runs an interactive menu (capture / tower /
# client upload). Capture itself is Linux-only (iw/airodump-ng/tshark); macOS
# and Windows have no usable monitor-mode capture here. Everything else runs on
# every platform.
# ---------------------------------------------------------------------------

def platform_name():
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "macos"
    if os.name == "nt":
        return "windows"
    return sys.platform


def capture_supported():
    return platform_name() == "linux"


def default_bind():
    return "0.0.0.0"


def last_capture_marker():
    """Path where a (possibly sudo-elevated) capture records its output file."""
    uid = os.environ.get("SUDO_UID")
    if uid:
        try:
            import pwd
            return Path(pwd.getpwuid(int(uid)).pw_dir) / ".wifi-handshake" / "last_capture"
        except (KeyError, ValueError, ImportError):
            pass
    return app_dir() / "last_capture"


def menu_capture(args):
    """Run the capture flow, elevating through sudo as a child process.

    Using ``os.execvp`` (as the direct ``--run-capture`` path does) would
    replace the whole process and drop the user back to the shell, so the menu
    would never see the result. Running sudo as a child keeps the menu alive;
    the child records the saved file in a marker the parent can read.
    """
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        session = ensure_sudo()
        forwarded = [item for item in sys.argv[1:] if item != "--run-capture"]
        marker = last_capture_marker()
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.unlink(missing_ok=True)
        try:
            code = subprocess.run(["sudo", "--", sys.executable, str(Path(__file__).resolve()),
                                   "--run-capture", *forwarded]).returncode
            captured = marker.read_text(encoding="utf-8").strip() if marker.is_file() else None
        finally:
            if session is not None:
                session.close()
        marker.unlink(missing_ok=True)
        return code, captured
    return run_capture_cli(args), getattr(args, "last_capture", None)


def run_interactive(args):
    while True:
        heading("wifi-handshake - Terminal Menu")
        print("  " + style("1", "bold") + ". Capture handshake  "
              + style("(Linux, monitor mode, root)", "dim"))
        print("  " + style("2", "bold") + ". Start tower        "
              + style("(server + hashcat, for the GPU box)", "dim"))
        print("  " + style("3", "bold") + ". Send capture       "
              + style("(client, to --tower URL)", "dim"))
        print("  " + style("4", "bold") + ". Help / Install     "
              + style("(--help, download hashcat)", "dim"))
        print("  " + style("5", "bold") + ". Inspect capture    "
              + style("(offline: find/verify a handshake in a file)", "dim"))
        print("  " + style("6", "bold") + ". Example captures   "
              + style("(download public test data)", "dim"))
        print("  " + style("7", "bold") + ". Tailscale          "
              + style("(status, log in, pick the tower in your tailnet)", "dim"))
        print("  " + style("q", "bold") + "  Quit")
        choice = input(style("Choice: ", "bold")).strip().lower()
        if choice == "1":
            code, captured = menu_capture(args)
            if code == 0 and captured:
                if input("Send this capture to a tower now? [y/N] ").strip().lower() == "y":
                    if prompt_tower(args):
                        args.send = Path(captured)
                        run_headless(args)
                    else:
                        print("No tower URL set. Capture kept at " + captured)
            continue
        if choice == "2":
            serve(args)
            continue
        if choice == "3":
            if not prompt_tower(args):
                warn("No tower URL set. Aborting.")
                continue
            if not args.send:
                cap = input("Path to capture file (.pcapng/.hc22000): ").strip()
                args.send = Path(cap) if cap else None
            if not args.send or not Path(args.send).exists():
                warn("No valid capture file. Aborting.")
                continue
            print("Sending capture to " + style(args.tower, "cyan"))
            run_headless(args)
            continue
        if choice == "4":
            print("Installing hashcat ...")
            install_tools(args.tools_dir)
            continue
        if choice == "5":
            cap = input("Capture file (.pcap/.pcapng): ").strip()
            if not cap:
                continue
            essid = input("SSID (optional, enables MIC verification): ").strip() or None
            password = None
            if essid:
                password = getpass.getpass("Passphrase (optional): ") or None
            inspect_capture(Path(cap), essid, password)
            continue
        if choice == "6":
            target = input("Target directory [test-captures]: ").strip() or "test-captures"
            download_example_captures(Path(target), args.captures_repo)
            continue
        if choice == "7":
            print_tailscale_status()
            answer = input("Action: [Enter] back, l to log in, t to pick a tower: ").strip().lower()
            if answer == "l":
                tailscale_login()
            elif answer == "t":
                choose_tailscale_tower(args)
            continue
        if choice in ("q", ""):
            return 0
        warn("Invalid choice.")






def build_parser():
    parser = argparse.ArgumentParser(
        prog="wifi-handshake",
        description="Passive Wi-Fi handshake capture and tower GPU cracking. "
                    "Run without arguments for the interactive terminal menu.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python wifi-handshake.py                  # interactive menu
  python wifi-handshake.py --tower URL     # client: upload a capture
  python wifi-handshake.py --serve --port 8443   # tower: GPU box
  python wifi-handshake.py --run-capture   # capture directly (Linux, sudo)
  python wifi-handshake.py --self-test     # offline tests
  python wifi-handshake.py --install-tools # download hashcat for the tower
  python wifi-handshake.py --inspect cap.pcapng  # find a handshake offline
  python wifi-handshake.py --inspect cap.pcapng --essid SSID --password PW  # verify MIC
  python wifi-handshake.py --download-captures   # fetch example captures
  python wifi-handshake.py --tailscale-status    # show the tailnet and peers
  python wifi-handshake.py --send cap.pcapng --tower-name tower  # find tower via Tailscale

Runs on Linux, macOS and Windows. Capture (monitor mode) needs Linux; the tower
and client roles work on every platform. Capture dependencies on Arch:
  sudo pacman -S --needed iw aircrack-ng wireshark-cli hcxtools python iproute2 sudo

No deauthentication, injection or radio interference anywhere in this tool.
Only test networks you own or have permission to test.
""")
    parser.add_argument("--tower", help="tower base URL, e.g. https://tower:8443")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"tower port, default {DEFAULT_PORT}")
    parser.add_argument("--bind", default="0.0.0.0", help="server bind address, default 0.0.0.0")
    parser.add_argument("--tools-dir", type=Path, help="folder holding hashcat")
    parser.add_argument("--output-dir", type=Path, help="where captures are saved")
    parser.add_argument("--insecure", action="store_true", help="skip certificate pinning")
    parser.add_argument("--serve", action="store_true", help="start the tower server (alternative to menu choice 2)")
    parser.add_argument("--install-tools", action="store_true", help="download, verify and unpack hashcat")
    parser.add_argument("--self-test", action="store_true", help="run offline tests and exit")

    server = parser.add_argument_group("tower server (--serve)")
    server.add_argument("--jobs-dir", type=Path, help="where jobs and results are stored")
    server.add_argument("--wordlist-dirs", type=Path, action="append", help="wordlist folders")
    server.add_argument("--rule-dirs", type=Path, action="append", help="hashcat rule folders")
    server.add_argument("--cert", type=Path, help="existing TLS certificate (PEM)")
    server.add_argument("--key", type=Path, help="existing TLS private key (PEM)")
    server.add_argument("--no-tls", action="store_true", help="serve plain HTTP")
    server.add_argument("--max-upload-mb", type=int, default=64, help="upload size limit in MiB, default 64")
    server.add_argument("--job-timeout", type=int, default=0, help="job runtime limit in seconds (0 = unlimited)")

    capture = parser.add_argument_group("non-interactive capture (Linux, no TUI)")
    capture.add_argument("--run-capture", action="store_true", help="capture directly, without the menu")
    capture.add_argument("--handshake", choices=("m1m2", "m1m2m3m4"),
                         help="required EAPOL messages (default: m1m2; "
                              "m1m2 is enough for hashcat -m 22000)")
    capture.add_argument("--scan-seconds", type=int, default=20)
    capture.add_argument("--band", choices=("bg", "a", "6", "abg", "ab6", "abg6"), default="abg",
                         help="bands to scan: b/g=2.4 GHz, a=5 GHz, 6=6 GHz (default: abg)")
    capture.add_argument("--channels", type=parse_channel_list,
                         help="channels or frequencies, e.g. 1,6,11 or 5180 or 2412")
    capture.add_argument("--timeout", type=int, default=0, help="capture seconds; 0 waits indefinitely")
    capture.add_argument("--max-mb", type=int, default=256, help="temporary capture size limit")

    offline = parser.add_argument_group("offline inspection (no radio, no root)")
    offline.add_argument("--inspect", type=Path,
                         help="analyse an existing .pcap/.pcapng and find handshakes")
    offline.add_argument("--essid", help="SSID for --inspect MIC verification")
    offline.add_argument("--password", help="passphrase for --inspect MIC verification")
    offline.add_argument("--download-captures", nargs="?", const=Path("test-captures"),
                         type=Path, help="download example captures into DIR "
                                         "(default: ./test-captures)")
    offline.add_argument("--captures-repo", default=EXAMPLE_CAPTURES_REPO,
                         help="GitHub owner/repo to download captures from "
                              f"(default: {EXAMPLE_CAPTURES_REPO})")

    headless = parser.add_argument_group("non-interactive client (no TUI)")
    headless.add_argument("--send", type=Path, help="send this capture instead of capturing")
    headless.add_argument("--watch", help="reattach to an existing job id")
    headless.add_argument("--attack", type=Path, help="JSON file with attack parameters")
    headless.add_argument("--fingerprint", help="pinned tower certificate sha256 fingerprint")

    tailscale = parser.add_argument_group("tailscale (tower discovery over the tailnet)")
    tailscale.add_argument("--tower-name", help="tailnet hostname of the tower "
                                                "(default when discovering: tower)")
    tailscale.add_argument("--tailscale-status", action="store_true",
                           help="print tailnet status and peers, then exit")
    tailscale.add_argument("--tailscale-login", action="store_true",
                           help="join the tailnet (`tailscale up`), then exit")
    return parser


def run_capture_cli(args):
    if not capture_supported():
        raise RuntimeError("Live capture needs Linux (iw/airodump-ng/tshark). "
                           "On other systems use --serve for the tower or --send/--watch.")
    if args.scan_seconds < 3 or args.timeout < 0 or args.max_mb < 1:
        raise RuntimeError("scan-seconds must be >= 3, timeout >= 0, max-mb >= 1")
    if not sys.stdin.isatty():
        raise RuntimeError("Run in an interactive terminal for sudo and the menus.")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        # Ask for the sudo password once, then re-exec as root. The cached
        # authentication means sudo does not prompt a second time, so the
        # capture flow starts seamlessly.
        ensure_sudo()
        forwarded = list(sys.argv[1:])
        if "--run-capture" not in forwarded:
            forwarded.append("--run-capture")
        os.execvp("sudo", ["sudo", "--", sys.executable, str(Path(__file__).resolve()), *forwarded])
    # Keep the user's PATH (hashcat/tshark may live in /usr/local/bin) while
    # ensuring the sbin directories that hold iw/ip are reachable.
    os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin:" + os.environ.get("PATH", "")
    os.environ["LC_ALL"] = "C"
    os.umask(0o077)
    missing = [c for c in ("iw", "ip", "airodump-ng", "tshark") if not shutil.which(c)]
    if missing:
        raise RuntimeError("Missing local tools: " + ", ".join(missing) + ". Nothing was installed.")
    if shutil.which("rfkill"):
        listing = run("rfkill", "list", check=False).stdout
        for block in re.split(r"\n\s*\n", listing):
            if "Wireless LAN" in block and re.search(r"blocked:\s*yes", block, re.I):
                warn("rfkill reports a blocked Wi-Fi radio. "
                     "Run `sudo rfkill unblock wifi` if capture fails.")
                break
    fields = run("tshark", "-G", "fields").stdout
    if any("\t" + field + "\t" not in fields for field in FIELDS):
        raise RuntimeError("This tshark build is missing required Wi-Fi/EAPOL fields.")
    output_dir = (args.output_dir or Path(__file__).resolve().parent).resolve()
    if not output_dir.is_dir():
        raise RuntimeError(f"Output directory does not exist: {output_dir}")
    available = adapters()
    if not available:
        raise RuntimeError("No wireless interfaces found.")
    heading("Wireless adapters")
    for i, (name, phy) in enumerate(available, 1):
        print(f"  {style(i, 'bold')}. {name} " + style(f"[{phy}]", "dim"))
    name, phy = available[choose("Adapter number, or q: ", len(available))]
    adapter = Adapter(name, phy)
    siblings = [other for other, p in available if p == phy and other != name]
    if siblings and adapter.original_type != "monitor":
        # Switching a managed interface to monitor takes over the whole radio,
        # so a sibling would lose its connection. An already-monitor interface
        # is only brought up, which is harmless to siblings.
        raise RuntimeError("Other interfaces share this radio: " + ", ".join(siblings)
                           + ". Use a dedicated radio, or select an existing monitor interface.")
    if siblings:
        print("Note: " + ", ".join(siblings) + " share this radio; reusing the existing "
              "monitor interface does not reconfigure them.")
    print(f"\n{style(name, 'bold')} will disconnect from Wi-Fi while monitoring.")
    warn("Only use this on a network you own or have explicit permission to test.")
    if input(style("Type YES to proceed: ", "bold")).strip() != "YES":
        print("Cancelled. No adapter changes made.")
        return 0
    if not adapter.nm_managed:
        info("NetworkManager does not manage this interface. Other Wi-Fi managers may interfere.")
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        with tempfile.TemporaryDirectory(prefix="wifi-handshake-") as tmp:
            directory = Path(tmp)
            adapter.enable()
            while True:
                networks = scan(adapter, directory, args.scan_seconds, args.band, args.channels)
                if not networks:
                    if input("No networks found. Enter r to rescan, anything else to quit: ").strip().lower() == "r":
                        continue
                    return 1
                heading(f"Networks found: {len(networks)}")
                print(style(f"{'#':>3}  {'Signal':<24} {'Ch':>3}  {'Cl':>2}  {'Security':<28} "
                            f"{'BSSID':<17} Network", "bold"))
                for i, net in enumerate(networks, 1):
                    if net["power"] < -1:
                        strength = (f"{signal_bar(net['power'])} {net['power']} dBm "
                                    f"{signal_label(net['power'])}")
                    else:
                        strength = "unknown"
                    print(f"{i:3}  {strength:<24} {net['channel']:>3}  {len(net['clients']):>2}  "
                          f"{net['security']:<28} {net['bssid']}  {net['ssid']}")
                info("Signal is received power, not a speed test. Security labels may be incomplete.")
                info("Cl = clients seen on that AP. Networks with clients are the best passive "
                     "targets: they rekey when they reconnect on their own.")
                with_clients = [n for n in networks if n["clients"]]
                if with_clients:
                    print("With clients: " + ", ".join(
                        f"{n['ssid']} ({len(n['clients'])})" for n in with_clients[:8]))
                groups = {}
                for net in networks:
                    groups.setdefault(ap_base(net["bssid"]), []).append(net)
                for base, members in sorted(groups.items(), key=lambda kv: -len(kv[1])):
                    if len(members) > 1:
                        names = ", ".join(f"'{m['ssid']}' ({m['bssid']})" for m in members)
                        print(f"Note: {len(members)} networks belong to the same AP [...{base}]: "
                              f"{names}. Connect the test device to exactly the SSID you pick below.")
                answer = input("Network number, r to rescan, or q to quit: ").strip().lower()
                if answer == "r":
                    continue
                if answer == "q":
                    return 0
                if not answer.isdecimal() or not 1 <= int(answer) <= len(networks):
                    warn("Invalid selection.")
                    continue
                network = networks[int(answer) - 1]
                if not any(wpa in network["security"].upper() for wpa in ("WPA", "RSN")):
                    warn("This network does not advertise WPA/RSN. "
                         "It has no WPA four-way handshake to capture.")
                    continue
                mode = getattr(args, "handshake", None)
                if mode is None:
                    mode = choose_handshake_mode()
                messages = (1, 2) if mode == "m1m2" else (1, 2, 3, 4)
                break
            siblings = same_ap_networks(networks, network)
            result = capture(adapter, network, directory, args.timeout, args.max_mb,
                             messages=messages, siblings=siblings)
            if result is None:
                return 1
            raw, frames = result
            prefix = time.strftime("handshake-%Y%m%d-%H%M%S-") + network["bssid"].replace(":", "") + "-"
            fd, path = tempfile.mkstemp(prefix=prefix, suffix=".pcapng", dir=output_dir)
            os.close(fd)
            output = Path(path)
            try:
                save_capture(raw, frames, network, output)
            except BaseException:
                output.unlink(missing_ok=True)
                raise
            wanted = "+".join(f"M{i}" for i in messages)
            ok(f"Captured a matching EAPOL exchange ({wanted}) for client {frames[0]['client']}.")
            print("Saved: " + style(output, "bold", "cyan"))
            info("Contains the exchange and target AP beacons. "
                 "No password/MIC verification or cracking.")
            args.last_capture = str(output)
            marker = last_capture_marker()
            try:
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.write_text(str(output), encoding="utf-8")
                if os.environ.get("SUDO_UID") and os.environ.get("SUDO_GID"):
                    os.chown(marker, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
            except OSError as exc:
                print(f"Could not record the capture marker: {exc}", file=sys.stderr)
            return 0
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        adapter.restore()


def run_headless(args):
    if args.watch:
        resolve_tower(args)
        if not args.tower:
            raise RuntimeError("--watch requires --tower URL or --tower-name")
        client = TowerClient(args.tower, fingerprint=args.fingerprint, insecure=args.insecure)
        return watch_job(client, args.watch, args.tower)
    if args.send:
        resolve_tower(args)
        if not args.tower:
            raise RuntimeError("--send requires --tower URL or --tower-name")
        client = TowerClient(args.tower, fingerprint=args.fingerprint, insecure=args.insecure)
        health = client.health()
        print(f"Tower: hashcat={health.get('hashcat_version')} hcxpcapngtool={health.get('hcxpcapngtool')}")
        attack = choose_attack(client, args.attack)
        print("Attack: " + json.dumps(attack))
        job_id = client.create_job(prepare_capture(args.send), attack)["job_id"]
        print(f"Job queued: {job_id}")
        return watch_job(client, job_id, args.tower)
    return None


def main(argv=None):
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.self_test:
            self_test()
            return 0
        if args.install_tools:
            return install_tools(args.tools_dir)
        if args.download_captures is not None:
            download_example_captures(args.download_captures, args.captures_repo)
            return 0
        if args.inspect:
            summary = inspect_capture(args.inspect, args.essid, args.password)
            return 1 if summary["mismatched"] else 0
        if args.tailscale_login:
            return tailscale_login()
        if args.tailscale_status:
            print_tailscale_status()
            return 0
        headless = run_headless(args)
        if headless is not None:
            return headless
        if args.run_capture:
            result = run_capture_cli(args)
            return 0 if result is None else result
        if args.serve:
            return serve(args)
        return run_interactive(args)
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        return 130
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        fail(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
