#!/usr/bin/env python3
"""Offline, passive Wi-Fi handshake capture. Run --help or --self-test first."""

import argparse
import base64
import collections
import csv
import hashlib
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
FIELDS = ["frame.number", "frame.time_epoch", "wlan.bssid", "wlan.sa", "wlan.da",
          "wlan_rsna_eapol.keydes.msgnr", "eapol.keydes.replay_counter",
          "wlan_rsna_eapol.keydes.nonce", "wlan_rsna_eapol.keydes.key_info.key_type",
          "eapol.type"]


def clean(value):
    # SSIDs are untrusted input. Never render terminal control sequences.
    return "".join(c if c.isprintable() else "?" for c in value)


def run(*args, check=True):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30)
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


def choose(prompt, size):
    while True:
        value = input(prompt).strip()
        if value.lower() == "q":
            raise KeyboardInterrupt
        if value.isdecimal() and 1 <= int(value) <= size:
            return int(value) - 1
        print(f"Enter a number from 1 to {size}, or q to quit.")


def adapters():
    result = []
    phy = None
    for line in run("iw", "dev").stdout.splitlines():
        line = line.strip()
        if line.startswith("phy#"):
            phy = "phy" + line[4:]
        elif line.startswith("Interface "):
            result.append((line.split(maxsplit=1)[1], phy))
    return result


class Adapter:
    def __init__(self, name, phy):
        self.name, self.phy = name, phy
        self.changed = False
        self.nm_changed = False
        self.nm_managed = False
        self.connection = None
        info = run("iw", "dev", name, "info").stdout
        match = re.search(r"^\s*type (\S+)", info, re.M)
        self.original_type = match.group(1) if match else "unknown"
        if self.original_type != "managed":
            raise RuntimeError("Choose a managed-mode adapter; existing monitor/AP interfaces are left alone.")
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
        capabilities = run("iw", "phy", phy, "info").stdout
        if not re.search(r"^\s*\* monitor\s*$", capabilities, re.M):
            raise RuntimeError(f"{name} does not advertise monitor-mode support.")

    def enable(self):
        if self.nm_managed:
            self.nm_changed = True
            run("nmcli", "device", "set", self.name, "managed", "no")
        self.changed = True
        run("ip", "link", "set", "dev", self.name, "down")
        run("iw", "dev", self.name, "set", "type", "monitor")
        run("ip", "link", "set", "dev", self.name, "up")

    def restore(self):
        if not self.changed and not self.nm_changed:
            return
        print("\nRestoring adapter settings...")
        commands = []
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
                print(f"Restore warning: {exc}", file=sys.stderr)
                print("Retry: " + " ".join(command), file=sys.stderr)


def parse_networks(text):
    networks = {}
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        if row[0].strip() == "Station MAC":
            break
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
        networks[bssid] = dict(bssid=bssid, channel=channel, power=power,
                               security=clean(" / ".join(v.strip() for v in row[5:8] if v.strip())),
                               ssid=clean(row[13].strip()) or "<hidden>")
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


def scan_channels(capabilities, band, requested=None):
    available = []
    for line in capabilities.splitlines():
        match = re.search(r"\*\s+(\d+(?:\.\d+)?) MHz \[(\d+)\]", line)
        if not match or "disabled" in line:
            continue
        frequency, channel = float(match.group(1)), int(match.group(2))
        if (2400 <= frequency < 2500 and "b" in band) or (5000 <= frequency < 5900 and "a" in band):
            available.append(channel)
    available = sorted(set(available))
    if requested:
        missing = set(requested) - set(available)
        if missing:
            raise RuntimeError(f"Channels not enabled for the selected band/radio: {sorted(missing)}")
        return sorted(set(requested))
    if not available:
        raise RuntimeError("No enabled 2.4/5 GHz channels found for this radio and band.")
    return available


def parse_channel_list(value):
    if not re.fullmatch(r"\d+(?:,\d+)*", value):
        raise argparse.ArgumentTypeError("Use comma-separated channel numbers, e.g. 1,6,11 or 100")
    channels = [int(item) for item in value.split(",")]
    if any(c < 1 or c > 196 for c in channels):
        raise argparse.ArgumentTypeError("Channel numbers must be between 1 and 196")
    return channels


def scan(adapter, directory, seconds, band, requested=None):
    channels = scan_channels(run("iw", "phy", adapter.phy, "info").stdout, band, requested)
    # Give every channel several beacon intervals, with time for two sweeps.
    seconds = max(seconds, len(channels))
    # Discard old scan snapshots before rescanning.
    for old in directory.glob("scan-*.csv"):
        old.unlink()
    prefix = directory / "scan"
    log_path = directory / "scan.log"
    print(f"\nListening for nearby networks for {seconds} seconds...")
    print("Requested scan channels: " + ",".join(map(str, channels)))
    observed = set()
    with log_path.open("wb") as log:
        proc = subprocess.Popen(["airodump-ng", "--channel", ",".join(map(str, channels)),
                                 "-f", "500", "--write", str(prefix),
                                 "--output-format", "csv", "--write-interval", "1",
                                 adapter.name], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + seconds
            next_sample = time.monotonic()
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError("Scan stopped: " + clean(log_path.read_text(errors="replace")[-2000:]))
                if time.monotonic() >= next_sample:
                    info = run("iw", "dev", adapter.name, "info").stdout
                    mode = re.search(r"^\s*type (\S+)", info, re.M)
                    channel = re.search(r"^\s*channel (\d+)", info, re.M)
                    if not mode or mode.group(1) != "monitor":
                        raise RuntimeError("Adapter left monitor mode during scan. Another Wi-Fi manager may be interfering.")
                    if channel:
                        observed.add(int(channel.group(1)))
                    next_sample = time.monotonic() + 0.7
                time.sleep(0.2)
        finally:
            stop(proc)
    print("Observed scan channels, sampled: " + (",".join(map(str, sorted(observed))) or "none"))
    if len(channels) > 1 and len(observed) < 2:
        print("WARNING: channel hopping was not observed. The driver or another Wi-Fi process may be holding the radio.")
    errors = log_path.read_text(errors="replace")
    for line in errors.splitlines():
        if re.search(r"(failed|error|busy|not supported|cannot|could not|couldn't|permission)", line, re.I):
            print("Scanner diagnostic: " + clean(line)[:500])
    files = sorted(directory.glob("scan-*.csv"))
    return parse_networks(files[-1].read_text(errors="replace")) if files else []


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


class CaptureStats:
    def __init__(self, bssid, messages=(1, 2, 3, 4)):
        self.bssid = bssid
        self.messages = tuple(sorted(messages))
        self.total = self.target = self.target_keys = self.other_keys = 0
        self.messages_seen = collections.Counter()
        self.accepted = collections.Counter()
        self.last_hint = None

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
            hint = "Target traffic is arriving, but no EAPOL-Key. Check which BSSID/band your test device joins."
        elif not all(self.accepted[str(i)] for i in self.messages):
            hint = ("Only part of a usable exchange has arrived. Move closer to both AP and client.")
        else:
            hint = "The required messages have been seen, but not a matching exchange for one client, nonce and replay sequence."
        if hint != self.last_hint:
            print(hint, flush=True)
            self.last_hint = hint


def check_radio(adapter, channel):
    info = run("iw", "dev", adapter.name, "info").stdout
    mode = re.search(r"^\s*type (\S+)", info, re.M)
    actual = re.search(r"^\s*channel (\d+)", info, re.M)
    if not mode or mode.group(1) != "monitor":
        raise RuntimeError("Adapter left monitor mode. Another Wi-Fi manager may be controlling it.")
    if not actual or int(actual.group(1)) != channel:
        raise RuntimeError(f"Adapter is no longer on selected channel {channel}. "
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


def capture(adapter, network, directory, timeout, max_mb, messages=(1, 2, 3, 4)):
    run("iw", "dev", adapter.name, "set", "channel", str(network["channel"]))
    check_radio(adapter, network["channel"])
    raw = directory / "traffic.pcapng"
    log_path = directory / "capture.log"
    bssid = network["bssid"]
    command = capture_command(adapter.name, raw, timeout, max_mb)
    tracker = Handshake(bssid, messages)
    stats = CaptureStats(bssid, messages)
    wanted = "+".join(f"M{i}" for i in messages)
    print(f"\nListening on channel {network['channel']} for {network['ssid']} [{bssid}].")
    print(f"Waiting for a matching EAPOL exchange ({wanted}). Ctrl+C cancels.")
    print("No packets are injected. A device must naturally connect or reconnect.")
    print("Detection is for this exact BSSID, not every AP with the same network name.")
    print(f"Temporary capture limit: {max_mb} MiB. Unrelated traffic is deleted on exit.")
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
                    check_radio(adapter, network["channel"])
                    last_status = now
            if not found:
                stop(proc)
                detail = clean(log_path.read_text(errors="replace")[-1500:])
                if proc.returncode:
                    raise RuntimeError("Capture failed: " + detail)
                print("Capture limit reached without a complete handshake. No capture saved.")
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
DEFAULT_PORT = 8443
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
        self.max_upload_mb = max_upload_mb
        self.job_timeout = job_timeout

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


def build_hashcat_command(hashcat, hash_file, attack, out_file, potfile, config):
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
                                        self.config.potfile, self.config)
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
        filename = Path(self.headers.get("X-Filename", "capture.bin")).name or "capture.bin"
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
    config = TowerConfig(
        host=args.host, port=args.port,
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
    def __init__(self, url, fingerprint=None, insecure=False, timeout=60):
        parsed = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
        self.scheme = parsed.scheme or "https"
        self.host = parsed.hostname or "localhost"
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.timeout = timeout
        self.fingerprint = fingerprint
        self.insecure = insecure

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
        expected = (self.fingerprint or known_fingerprint(self.host, self.port) or "").replace(":", "").lower()
        if not expected:
            print(f"Tower certificate fingerprint (sha256): {digest}")
            if input("Trust this tower and remember it? Type YES: ").strip() != "YES":
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
    import contextlib
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
    assert clean("bad\x1b\nssid") == "bad??ssid"
    assert signal_label(-1) == "unknown"
    capabilities = "\n".join(["* 2412.0 MHz [1] (20 dBm)", "* 2462 MHz [11] (20 dBm)",
                               "* 5500.0 MHz [100] (no IR, radar detection)",
                               "* 5845.0 MHz [169] (disabled)", "* 5955 MHz [1] (20 dBm)"])
    assert scan_channels(capabilities, "abg") == [1, 11, 100]
    assert scan_channels(capabilities, "bg") == [1, 11]
    assert scan_channels(capabilities, "a", [100]) == [100]
    try:
        scan_channels(capabilities, "abg", [169])
    except RuntimeError:
        pass
    else:
        raise AssertionError("Disabled channel accepted")
    assert parse_channel_list("1,6,11") == [1, 6, 11]
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
    print("Self-test passed: parsing, signal labels, handshake matching (M1+M2 and M1-M4), "
          "tower protocol, hashcat status parsing, attack building, tshark decoding and export.")
    print("No adapter changes, network access or radio capture performed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Capture dependencies on Arch:
  sudo pacman -S --needed iw aircrack-ng wireshark-cli hcxtools python iproute2 sudo

The capture path performs no installs, deauthentication or injection. Cracking
happens only on the tower (--serve), using hashcat on the GPU, and only for
networks you own or have explicit permission to test. Signal strength is not a
throughput test. Security labels are AP advertisements. Capture checks the
EAPOL exchange, not the password or MIC validity. NetworkManager settings are
restored on normal exit, Ctrl+C and SIGTERM; SIGKILL or power loss cannot.

Tower usage (Windows/GPU box):
  wifi-handshake.py --install-tools
  wifi-handshake.py --serve --port 8443
Client usage (Linux laptop):
  wifi-handshake.py --tower https://tower:8443
  wifi-handshake.py --tower https://tower:8443 --send capture.pcapng
  wifi-handshake.py --tower https://tower:8443 --watch <job-id>
""")
    parser.add_argument("--scan-seconds", type=int, default=20)
    parser.add_argument("--band", choices=("bg", "a", "abg"), default="abg",
                        help="scan 2.4 GHz, 5 GHz, or both; no 6 GHz support here")
    parser.add_argument("--channels", type=parse_channel_list,
                        help="scan only these enabled channels, e.g. 1,6,11 or 100")
    parser.add_argument("--timeout", type=int, default=0, help="capture seconds; 0 waits indefinitely")
    parser.add_argument("--max-mb", type=int, default=256, help="temporary capture size limit, default 256 MiB")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent,
                        help="save beside this script unless overridden")
    parser.add_argument("--handshake", choices=("m1m2", "m1m2m3m4"),
                        help="required EAPOL messages; prompted when omitted")
    parser.add_argument("--self-test", action="store_true", help="offline synthetic tests; no sudo or adapter access")
    tower = parser.add_argument_group("tower (Windows/GPU box)")
    tower.add_argument("--serve", action="store_true", help="run the tower cracking server")
    tower.add_argument("--host", default="0.0.0.0", help="server bind address")
    tower.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"server port, default {DEFAULT_PORT}")
    tower.add_argument("--jobs-dir", type=Path, help="where jobs and results are stored")
    tower.add_argument("--tools-dir", type=Path, help="folder holding hashcat/hcxpcapngtool")
    tower.add_argument("--wordlist-dir", type=Path, action="append", dest="wordlist_dirs",
                       help="wordlist folder; repeatable")
    tower.add_argument("--rule-dir", type=Path, action="append", dest="rule_dirs",
                       help="hashcat rule folder; repeatable")
    tower.add_argument("--cert", type=Path, help="TLS certificate PEM")
    tower.add_argument("--key", type=Path, help="TLS private key PEM")
    tower.add_argument("--no-tls", action="store_true", help="serve plain HTTP (Tailscale still encrypts)")
    tower.add_argument("--max-upload-mb", type=int, default=64, help="maximum capture upload size")
    tower.add_argument("--job-timeout", type=int, default=0, help="unused; jobs run to completion")
    tower.add_argument("--install-tools", action="store_true", help="download and verify hashcat")
    client = parser.add_argument_group("client (Linux laptop)")
    client.add_argument("--tower", help="tower base URL, e.g. https://tower:8443")
    client.add_argument("--send", type=Path, help="send this capture instead of capturing")
    client.add_argument("--watch", help="reattach to an existing job id")
    client.add_argument("--attack", type=Path, help="JSON file with attack parameters")
    client.add_argument("--fingerprint", help="pinned tower certificate sha256 fingerprint")
    client.add_argument("--insecure", action="store_true", help="skip tower certificate pinning")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0
    if args.install_tools:
        return install_tools(args.tools_dir)
    if args.serve:
        return serve(args)
    if args.watch:
        if not args.tower:
            parser.error("--watch requires --tower URL")
        return reattach(args)
    if args.send:
        if not args.tower:
            parser.error("--send requires --tower URL")
        return send_capture(args)
    if os.name == "nt":
        raise RuntimeError("Live capture needs Linux (iw/airodump-ng/tshark). On Windows use "
                           "--serve, --install-tools, --send or --watch.")

    if args.scan_seconds < 3 or args.timeout < 0 or args.max_mb < 1:
        parser.error("scan-seconds must be >= 3, timeout >= 0, max-mb >= 1")
    if not sys.stdin.isatty():
        parser.error("Run in an interactive terminal for sudo and the menus.")
    if os.geteuid() != 0:
        if not shutil.which("sudo"):
            raise RuntimeError("sudo is required. Alternatively run this script as root.")
        os.execvp("sudo", ["sudo", "--", sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]])
    # Use standard system utilities, not executables inherited through sudo PATH.
    os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
    os.environ["LC_ALL"] = "C"
    os.umask(0o077)
    missing = [c for c in ("iw", "ip", "airodump-ng", "tshark") if not shutil.which(c)]
    if missing:
        raise RuntimeError("Missing local tools: " + ", ".join(missing) + ". See --help. Nothing was installed.")
    # Check dissector compatibility before taking Wi-Fi offline.
    fields = run("tshark", "-G", "fields").stdout
    if any("\t" + field + "\t" not in fields for field in FIELDS):
        raise RuntimeError("This tshark build is missing required Wi-Fi/EAPOL fields.")
    output_dir = args.output_dir.resolve()
    if not output_dir.is_dir():
        raise RuntimeError(f"Output directory does not exist: {output_dir}")

    if args.handshake:
        messages = {"m1m2": (1, 2), "m1m2m3m4": (1, 2, 3, 4)}[args.handshake]
    else:
        print("\nRequired EAPOL messages to capture:")
        print("  1. M1+M2 only  (fast; enough for hashcat -m 22000)")
        print("  2. M1+M2+M3+M4 (full four-way exchange)")
        messages = (1, 2) if choose("Message set [1/2], or q: ", 2) == 0 else (1, 2, 3, 4)

    available = adapters()
    if not available:
        raise RuntimeError("No wireless interfaces found.")
    print("\nWireless adapters:")
    for i, (name, phy) in enumerate(available, 1):
        print(f"  {i}. {name} [{phy}]")
    name, phy = available[choose("Adapter number, or q: ", len(available))]
    adapter = Adapter(name, phy)
    siblings = [other for other, p in available if p == phy and other != name]
    if siblings:
        raise RuntimeError("Other interfaces share this radio: " + ", ".join(siblings)
                           + ". Use a dedicated radio to avoid disrupting them.")
    print(f"\n{name} will disconnect from Wi-Fi while monitoring.")
    print("Only use this on a network you own or have explicit permission to test.")
    if input("Type YES to proceed: ").strip() != "YES":
        print("Cancelled. No adapter changes made.")
        return 0
    if not adapter.nm_managed:
        print("NetworkManager does not manage this interface. Other Wi-Fi managers may interfere.")
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    saved = None
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
                print("\n  #  Signal             Ch  Advertised security          BSSID              Network")
                for i, net in enumerate(networks, 1):
                    strength = f"{net['power']} dBm {signal_label(net['power'])}" if net["power"] < -1 else "unknown"
                    print(f"{i:3}  {strength:18} {net['channel']:3}  {net['security']:28} "
                          f"{net['bssid']}  {net['ssid']}")
                print("\nSignal is received power, not a speed test. Security labels may be incomplete.")
                answer = input("Network number, r to rescan, or q to quit: ").strip().lower()
                if answer == "r":
                    continue
                if answer == "q":
                    return 0
                if not answer.isdecimal() or not 1 <= int(answer) <= len(networks):
                    print("Invalid selection.")
                    continue
                network = networks[int(answer) - 1]
                if not any(wpa in network["security"].upper() for wpa in ("WPA", "RSN")):
                    print("This network does not advertise WPA/RSN. It has no WPA four-way handshake to capture.")
                    continue
                break
            result = capture(adapter, network, directory, args.timeout, args.max_mb, messages)
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
            names = "+".join(f"M{i}" for i in messages)
            print(f"\nCaptured matching exchange ({names}) for client {frames[0]['client']}.")
            print(f"Saved: {output}")
            print("Contains the exchange and target AP beacons. No password/MIC verification here.")
            saved = output
    finally:
        # A second Ctrl+C should not interrupt adapter restoration.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        adapter.restore()
    if saved is not None and args.tower:
        args.send = saved
        return send_capture(args)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled. No incomplete capture saved.")
        sys.exit(130)
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
