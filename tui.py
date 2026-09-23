#!/usr/bin/env python3
"""Lightweight Textual TUI for wifi-handshake.

The heavy lifting lives in wifi-handshake.py; this module only drives it. The
look is deliberately terminal-plain: a short prompt line, a scrollable log and
the usual menu, not a dashboard.

Run on the laptop:
    python tui.py            # capture + submit to a tower
Run on the tower (Windows):
    python tui.py            # includes Setup and Tower screens

There is no deauthentication or injection anywhere: capture stays passive.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import time
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Label, ListItem, ListView,
    OptionList, RichLog, Static,
)
from textual.widgets.option_list import Option

ENGINE_FILE = Path(__file__).resolve().parent / "wifi-handshake.py"


def load_engine():
    spec = importlib.util.spec_from_file_location("wifi_handshake_engine", ENGINE_FILE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load engine from {ENGINE_FILE}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wh = load_engine()

PLAIN_CSS = """
Screen {
    background: $surface;
}
#menu {
    dock: top;
    height: 1;
    background: $panel;
    color: $text;
    padding: 0 1;
}
#log {
    height: 1fr;
    border: none;
    padding: 0 1;
}
#prompt {
    dock: bottom;
    height: 1;
    background: $panel;
    padding: 0 1;
}
ListView {
    height: 1fr;
    border: none;
}
DataTable {
    height: 1fr;
}
.panel {
    height: auto;
    padding: 0 1;
}
"""


def plain_row(job):
    """One status line, matching the CLI's print_job_line."""
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
    return " | ".join(parts)


class PromptScreen(Screen):
    """Base screen: title bar, scrollable log and a one-line prompt."""

    TITLE = "wifi-handshake"

    def __init__(self, app):
        super().__init__()
        self.app_ref = app

    def compose(self) -> ComposeResult:
        yield Static(self.TITLE, id="menu")
        yield RichLog(id="log", markup=True, wrap=True, highlight=False)
        yield Static("", id="prompt")
        yield Footer()

    def on_mount(self) -> None:
        prompt = self.query_one("#prompt", Static)
        prompt.update(f"[dim]{self.app_ref.status_line()}[/dim]")
        self.query_one("#log", RichLog).can_focus = False

    def log_line(self, message: str) -> None:
        self.query_one("#log", RichLog).write(message)

    def set_prompt(self, message: str) -> None:
        self.query_one("#prompt", Static).update(message)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        handler = getattr(self, f"on_choice_{event.item.id}", None)
        if handler:
            handler()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        handler = getattr(self, f"on_choice_{event.button.id}", None)
        if handler:
            handler()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        handler = getattr(self, f"on_choice_{event.option.id}", None)
        if handler:
            handler()


class MenuScreen(PromptScreen):
    TITLE = "wifi-handshake / menu"
    BINDINGS = [
        Binding("c", "capture", "capture"),
        Binding("t", "tower", "tower status"),
        Binding("j", "jobs", "jobs"),
        Binding("s", "setup", "setup"),
        Binding("q", "quit", "quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Static(self.TITLE, id="menu")
        yield RichLog(id="log", markup=True, wrap=True, highlight=False)
        yield ListView(id="choices")
        yield Static("", id="prompt")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#prompt", Static).update(
            self.app_ref.status_line() + "\n[dim]enter select | c capture | t tower | j jobs | s setup | q quit[/dim]"
        )
        view = self.query_one("#choices", ListView)
        view.append(ListItem(Label("Capture a handshake and crack it on the tower"), id="capture"))
        view.append(ListItem(Label("Tower status and connection test"), id="tower"))
        view.append(ListItem(Label("Jobs: queue, history, reattach"), id="jobs"))
        view.append(ListItem(Label("Setup / diagnose this machine"), id="setup"))
        view.append(ListItem(Label("Quit"), id="quit"))
        if not self.app_ref.engine_is_linux():
            self.log_line("[yellow]Live capture needs Linux. On Windows use Setup and Tower.[/yellow]")

    def on_choice_capture(self):
        if self.app_ref.engine_is_linux():
            self.app.push_screen(CaptureScreen(self.app_ref))
        else:
            self.log_line("[yellow]Capture is Linux-only; falling back to sending a file.[/yellow]")
            self.app.push_screen(AttackScreen(self.app_ref, None))

    def on_choice_tower(self):
        self.app.push_screen(TowerScreen(self.app_ref))

    def on_choice_jobs(self):
        self.app.push_screen(JobsScreen(self.app_ref))

    def on_choice_setup(self):
        self.app.push_screen(SetupScreen(self.app_ref))

    def on_choice_quit(self):
        self.app.exit()

    def action_capture(self):
        self.on_choice_capture()

    def action_tower(self):
        self.on_choice_tower()

    def action_jobs(self):
        self.on_choice_jobs()

    def action_setup(self):
        self.on_choice_setup()

    def action_quit(self):
        self.on_choice_quit()


class TowerScreen(PromptScreen):
    TITLE = "wifi-handshake / tower"

    def compose(self) -> ComposeResult:
        yield Static(self.TITLE, id="menu")
        yield RichLog(id="log", wrap=True, highlight=False)
        with Vertical(classes="panel"):
            yield Label("Tower URL (host:port)")
            yield Input(value=self.app_ref.tower_url or "https://tower:8443", id="tower-url")
            with Horizontal():
                yield Button("Connect", id="connect", variant="primary")
                yield Button("Back", id="back")
        yield Static("", id="prompt")
        yield Footer()

    def on_mount(self):
        self.log_line("Enter the tower URL, then Connect. First contact prints the certificate fingerprint.")

    def on_choice_back(self):
        self.app.pop_screen()

    def on_choice_connect(self):
        self.app_ref.tower_url = self.query_one("#tower-url", Input).value.strip()
        self.set_prompt("Contacting tower...")
        self.fetch_health(self.app_ref.tower_url)

    @work(thread=True, exclusive=True)
    def fetch_health(self, url: str) -> None:
        try:
            client = wh.TowerClient(url, insecure=self.app_ref.insecure)
            health = client.health() or {}
        except (RuntimeError, OSError) as exc:
            self.app.call_from_thread(self.log_line, f"[red]Connection failed: {wh.clean(str(exc))}[/red]")
            self.app.call_from_thread(self.set_prompt, "Connection failed.")
            return
        lines = [f"protocol {health.get('protocol')} on {health.get('os')}",
                 f"hashcat: {health.get('hashcat_version')} ({health.get('hashcat')})",
                 f"hcxpcapngtool: {health.get('hcxpcapngtool')}",
                 f"backend: {health.get('backend') or 'auto'}",
                 f"queue: {health.get('queue')}"]
        for device in health.get("devices", []):
            lines.append("  " + device)
        for line in lines:
            self.app.call_from_thread(self.log_line, line)
        self.app.call_from_thread(self.set_prompt, "Connected.")
        remembered = wh.known_fingerprint(client.host, client.port)
        if remembered:
            self.app.call_from_thread(self.log_line, f"pinned fingerprint: {remembered[:32]}...")
        self.app_ref.remember_tower(url)


class SetupScreen(PromptScreen):
    TITLE = "wifi-handshake / setup"

    def compose(self) -> ComposeResult:
        yield Static(self.TITLE, id="menu")
        yield RichLog(id="log", wrap=True, highlight=False)
        with Horizontal(classes="panel"):
            yield Button("Diagnose", id="diagnose", variant="primary")
            yield Button("Install hashcat", id="install")
            yield Button("Back", id="back")
        yield Static("", id="prompt")
        yield Footer()

    def on_mount(self):
        self.log_line("Diagnose checks this machine and the pinned tools. Nothing is changed.")
        normal = "normal" if sys.stdin.isatty() else "no tty"
        self.log_line(f"platform: {sys.platform} | python: {sys.version.split()[0]} | {normal}")
        for tool in ("hashcat", "hcxpcapngtool", "tshark", "iw", "airodump-ng"):
            found = wh.find_tool(tool, [wh.default_tools_dir()])
            self.log_line(f"{tool}: {found if found else '[yellow]not found[/yellow]'}")

    def on_choice_back(self):
        self.app.pop_screen()

    def on_choice_install(self):
        self.set_prompt("Downloading hashcat...")
        self.install(self.app_ref.tools_dir or wh.default_tools_dir())

    @work(thread=True, exclusive=True)
    def install(self, tools_dir) -> None:
        try:
            wh.install_tools(tools_dir)
            backend = wh.discover_tools(wh.TowerConfig(
                "127.0.0.1", 8443, wh.app_dir() / "jobs", tools_dir,
                [wh.app_dir() / "wordlists"], []))
            summary = wh.backend_summary(backend.get("backends") or {})
            self.app.call_from_thread(self.log_line, f"backend: {backend.get('backend') or 'none'}")
            for line in summary:
                self.app.call_from_thread(self.log_line, "  " + line)
            self.app.call_from_thread(self.set_prompt, "Install finished.")
        except (RuntimeError, OSError) as exc:
            self.app.call_from_thread(self.log_line, f"[red]{wh.clean(str(exc))}[/red]")
            self.app.call_from_thread(self.set_prompt, "Install failed.")

    def on_choice_diagnose(self):
        self.log_line("hashcat backends:")
        hashcat = wh.find_tool("hashcat", [wh.default_tools_dir()])
        for line in wh.backend_summary(wh.detect_backends(hashcat)):
            self.log_line("  " + line)


class CaptureScreen(PromptScreen):
    TITLE = "wifi-handshake / capture"
    BINDINGS = [Binding("escape", "back", "back")]

    def compose(self) -> ComposeResult:
        yield Static(self.TITLE, id="menu")
        yield RichLog(id="log", wrap=True, highlight=False)
        yield ListView(id="choices")
        yield Static("", id="prompt")
        yield Footer()

    def on_mount(self):
        self.messages = (1, 2)
        self.adapter = None
        self.state = "messages"
        self.query_one("#prompt", Static).update(
            "EAPOL messages: [1] M1+M2 only (enough for hashcat) | [2] M1+M2+M3+M4"
        )
        view = self.query_one("#choices", ListView)
        view.append(ListItem(Label("M1+M2 only (fast; enough for hashcat -m 22000)"), id="m12"))
        view.append(ListItem(Label("M1+M2+M3+M4 (full four-way exchange)"), id="m1234"))

    def on_choice_m12(self):
        self.messages = (1, 2)
        self.begin_adapters()

    def on_choice_m1234(self):
        self.messages = (1, 2, 3, 4)
        self.begin_adapters()

    def begin_adapters(self):
        self.state = "adapters"
        self.log_line(f"required messages: {'+'.join('M%d' % m for m in self.messages)}")
        try:
            available = wh.adapters()
        except (RuntimeError, OSError) as exc:
            self.log_line(f"[red]{wh.clean(str(exc))}[/red]")
            return
        if not available:
            self.log_line("[red]No wireless interfaces found.[/red]")
            return
        self.set_prompt("Select a monitor-capable adapter (a dedicated radio).")
        view = self.query_one("#choices", ListView)
        view.clear()
        self._adapters = available
        for name, phy in available:
            view.append(ListItem(Label(f"{name} [{phy}]"), id=f"adapter::{name}::{phy}"))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item_id = event.item.id or ""
        if item_id.startswith("adapter::"):
            _, name, phy = item_id.split("::")
            self.select_adapter(name, phy)
        elif item_id.startswith("network::"):
            self.select_network(int(item_id.split("::")[1]))

    def select_adapter(self, name, phy):
        try:
            adapter = wh.Adapter(name, phy)
        except (RuntimeError, OSError) as exc:
            self.log_line(f"[red]{wh.clean(str(exc))}[/red]")
            return
        siblings = [other for other, p in self._adapters if p == phy and other != name]
        if siblings:
            self.log_line(f"[red]Other interfaces share this radio: {', '.join(siblings)}. "
                     "Use a dedicated radio.[/red]")
            return
        self.adapter = adapter
        self.log_line(f"adapter: {name} (managed, was {adapter.original_type})")
        self.log_line("[yellow]This disconnects the laptop from Wi-Fi while monitoring.[/yellow]")
        self.log_line("Only use this on a network you own or have explicit permission to test.")
        self.state = "confirm"
        self.set_prompt("Press y to enable monitor mode and scan, n to go back.")
        self.query_one("#choices", ListView).clear()

    def key_y(self):
        if self.state == "confirm":
            self.run_scan()

    def key_n(self):
        if self.state == "confirm":
            self.action_back()

    @work(thread=True, exclusive=True)
    def run_scan(self):
        try:
            self.app.call_from_thread(self.set_prompt, "Enabling monitor mode...")
            self.adapter.enable()
            self.app.call_from_thread(self.log_line, "adapter in monitor mode")
            self._networks = self.scan_and_list()
        except (RuntimeError, OSError) as exc:
            self.app.call_from_thread(self.log_line, f"[red]{wh.clean(str(exc))}[/red]")
            self.app.call_from_thread(self.set_prompt, "Error. Press escape to restore.")
            self.app.call_from_thread(self.restore_if_needed)

    def scan_and_list(self):
        import tempfile
        with tempfile.TemporaryDirectory(prefix="wifi-tui-") as tmp:
            directory = Path(tmp)
            self._tmp = directory
            networks = wh.scan(self.adapter, directory, 20, "abg", None)
        self.app.call_from_thread(self.show_networks, networks)
        return networks

    def show_networks(self, networks):
        self.state = "networks"
        if not networks:
            self.log_line("[yellow]No networks found.[/yellow]")
            return
        self.log_line(f"{len(networks)} networks found:")
        view = self.query_one("#choices", ListView)
        view.clear()
        self._networks = networks
        for index, net in enumerate(networks):
            power = f"{net['power']} dBm" if net["power"] < -1 else "unknown"
            label = (f"{net['ssid']}  {net['bssid']}  ch {net['channel']}  "
                     f"{power}  {net['security']}")
            view.append(ListItem(Label(label), id=f"network::{index}"))
        self.set_prompt("Select the network to capture. Signal is received power, not throughput.")

    def select_network(self, index):
        network = self._networks[index]
        if not any(wpa in network["security"].upper() for wpa in ("WPA", "RSN")):
            self.log_line("[yellow]That network does not advertise WPA/RSN; no WPA handshake to capture.[/yellow]")
            return
        self.target = network
        self.log_line(f"target: {network['ssid']} [{network['bssid']}] channel {network['channel']}")
        self.set_prompt("Waiting for a matching EAPOL exchange. A device must reconnect. q cancels.")
        self.wait_for_handshake(self.app_ref.output_dir)

    @work(thread=True, exclusive=True)
    def wait_for_handshake(self, output_dir):
        try:
            result = wh.capture(self.adapter, self.target, self._tmp, 0, 256, self.messages)
        except (RuntimeError, OSError, Exception) as exc:  # noqa: BLE001 - surface anything
            self.app.call_from_thread(self.log_line, f"[red]{wh.clean(str(exc))}[/red]")
            self.app.call_from_thread(self.restore_if_needed)
            return
        if result is None:
            self.app.call_from_thread(self.log_line, "Capture ended without a matching exchange.")
            self.app.call_from_thread(self.restore_if_needed)
            return
        raw, frames = result
        prefix = time.strftime("handshake-%Y%m%d-%H%M%S-") + self.target["bssid"].replace(":", "") + "-"
        out = Path(output_dir) / (prefix + ".pcapng")
        try:
            wh.save_capture(raw, frames, self.target, out)
        except (RuntimeError, OSError) as exc:
            self.app.call_from_thread(self.log_line, f"[red]Save failed: {wh.clean(str(exc))}[/red]")
            self.app.call_from_thread(self.restore_if_needed)
            return
        names = "+".join(f"M{m}" for m in self.messages)
        self.app.call_from_thread(self.log_line, f"[green]Captured {names} for client "
                                 f"{frames[0]['client']}[/green]")
        self.app.call_from_thread(self.log_line, f"saved: {out}")
        self.app.call_from_thread(self.restore_if_needed)
        self.app.call_from_thread(self.offer_submit, out)

    def offer_submit(self, path):
        if not self.app_ref.tower_url:
            self.set_prompt("Saved. No tower configured; set one in Tower, then use --send.")
            return
        self.state = "submit"
        self.set_prompt("Press t to submit to the tower, or escape to keep the file local.")
        self._capture_path = path

    def key_t(self):
        if self.state == "submit":
            self.app.switch_screen(AttackScreen(self.app_ref, self._capture_path))

    def restore_if_needed(self):
        if self.adapter is not None:
            try:
                self.adapter.restore()
            except Exception as exc:  # noqa: BLE001
                self.log_line(f"[yellow]Restore warning: {wh.clean(str(exc))}[/yellow]")
            self.adapter = None
        self.set_prompt("Adapter restored. escape to go back.")

    def action_back(self):
        self.restore_if_needed()
        self.app.pop_screen()


class AttackScreen(PromptScreen):
    TITLE = "wifi-handshake / attack"
    BINDINGS = [Binding("escape", "back", "back")]

    def __init__(self, app, capture_path):
        super().__init__(app)
        self.capture_path = capture_path
        self.attack = {}
        self.wordlists = []
        self.rules = []

    def compose(self) -> ComposeResult:
        yield Static(self.TITLE, id="menu")
        yield RichLog(id="log", wrap=True, highlight=False)
        with Vertical(classes="panel"):
            yield Input(placeholder="capture file (.pcapng/.hc22000), empty = last capture", id="capture")
            yield Input(placeholder="mask, e.g. ?d?d?d?d?d?d?d?d", id="mask")
            yield Label("Wordlist (blank for none)")
            yield OptionList(id="wordlists")
            yield Label("Rules (blank for none)")
            yield OptionList(id="rules")
            with Horizontal():
                yield Button("Submit", id="submit", variant="primary")
                yield Button("Back", id="back")
        yield Static("", id="prompt")
        yield Footer()

    def on_mount(self):
        if self.capture_path:
            self.query_one("#capture", Input).value = str(self.capture_path)
        self.set_prompt("Pick wordlist/rules, set a mask if needed, then Submit.")
        if self.app_ref.tower_url:
            self.load_listing()
        else:
            self.log_line("[yellow]No tower set. Open Tower and connect, then reopen this screen.[/yellow]")

    @work(thread=True, exclusive=True)
    def load_listing(self):
        try:
            client = wh.TowerClient(self.app_ref.tower_url, insecure=self.app_ref.insecure)
            listing = client.wordlists() or {}
        except (RuntimeError, OSError) as exc:
            self.app.call_from_thread(self.log_line, f"[red]{wh.clean(str(exc))}[/red]")
            self.app.call_from_thread(self.log_line, "Tower unreachable; fill the fields manually.")
            return
        self.app.call_from_thread(self.fill, listing)

    def fill(self, listing):
        listing = listing or {}
        self.wordlists = listing.get("wordlists") or []
        self.rules = listing.get("rules") or []
        wordlist_view = self.query_one("#wordlists", OptionList)
        wordlist_view.clear_options()
        for item in self.wordlists:
            wordlist_view.add_option(Option(f"{item['name']} ({item['size']} bytes)", id=f"wl::{item['name']}"))
        rule_view = self.query_one("#rules", OptionList)
        rule_view.clear_options()
        for item in self.rules:
            rule_view.add_option(Option(item["name"], id=f"rule::{item['name']}"))
        self.log_line(f"tower lists {len(self.wordlists)} wordlists and {len(self.rules)} rules")

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        option_id = event.option.id or ""
        if option_id.startswith("wl::"):
            self.attack["wordlist"] = option_id.split("::", 1)[1]
            self.log_line(f"wordlist: {self.attack['wordlist']}")
        elif option_id.startswith("rule::"):
            self.attack.setdefault("rules", [])
            rule = option_id.split("::", 1)[1]
            if rule in self.attack["rules"]:
                self.attack["rules"].remove(rule)
            else:
                self.attack["rules"].append(rule)
            self.log_line("rules: " + (", ".join(self.attack["rules"]) or "none"))

    def on_choice_back(self):
        self.app.pop_screen()

    def on_choice_submit(self):
        capture = self.query_one("#capture", Input).value.strip() or self.capture_path
        if not capture:
            self.log_line("[red]No capture file given.[/red]")
            return
        mask = self.query_one("#mask", Input).value.strip()
        attack = dict(self.attack)
        if attack.get("wordlist") and mask:
            attack["type"] = "hybrid"
            attack["mask"] = mask
            attack["order"] = "wordlist-first"
        elif mask:
            attack["type"] = "mask"
            attack["mask"] = mask
        elif attack.get("wordlist"):
            attack["type"] = "dictionary"
        else:
            self.log_line("[red]Choose a wordlist or a mask.[/red]")
            return
        self.log_line("attack: " + str(attack))
        self.submit(capture, attack)

    @work(thread=True, exclusive=True)
    def submit(self, capture, attack):
        self.app.call_from_thread(self.set_prompt, "Uploading...")
        try:
            client = wh.TowerClient(self.app_ref.tower_url, insecure=self.app_ref.insecure)
            capture = wh.prepare_capture(capture)
            job_id = client.create_job(capture, attack)["job_id"]
        except (RuntimeError, OSError) as exc:
            self.app.call_from_thread(self.log_line, f"[red]{wh.clean(str(exc))}[/red]")
            self.app.call_from_thread(self.set_prompt, "Submit failed.")
            return
        self.app.call_from_thread(self.log_line, f"[green]job queued: {job_id}[/green]")
        self.app.call_from_thread(self.app.switch_screen, CrackScreen(self.app_ref, job_id))


class CrackScreen(PromptScreen):
    TITLE = "wifi-handshake / crack"
    BINDINGS = [Binding("escape", "back", "back")]

    def __init__(self, app, job_id):
        super().__init__(app)
        self.job_id = job_id
        self.last_line = None
        self.finished = False

    def compose(self) -> ComposeResult:
        yield Static(self.TITLE, id="menu")
        yield RichLog(id="log", wrap=True, highlight=False)
        with Horizontal(classes="panel"):
            yield Button("Cancel job", id="cancel")
            yield Button("Back", id="back")
        yield Static("", id="prompt")
        yield Footer()

    def on_mount(self):
        self.log_line(f"job {self.job_id}")
        self.set_prompt("Connecting to the live status stream...")
        if self.app_ref.tower_url:
            self.stream()
        else:
            self.set_prompt("No tower set.")
            self.log_line("[yellow]No tower set.[/yellow]")

    @work(thread=True, exclusive=True)
    def stream(self):
        client = wh.TowerClient(self.app_ref.tower_url, insecure=self.app_ref.insecure)
        started = self.live_capture_helpers()
        self.app.call_from_thread(self.set_prompt, "Live status (WebSocket, polling fallback).")
        client.stream_events(self.job_id, started)
        self.poll_fallback(client)

    def live_capture_helpers(self):
        def on_status(job):
            self.app.call_from_thread(self.apply_status, job)
        return on_status

    def apply_status(self, job):
        line = plain_row(job)
        if line != self.last_line:
            self.last_line = line
            self.log_line(line)
        if job.get("state") in ("done", "failed", "cancelled"):
            self.finished = True
            self.report(job)

    def poll_fallback(self, client):
        while not self.finished:
            try:
                job = client.job(self.job_id)
            except (RuntimeError, OSError) as exc:
                self.app.call_from_thread(self.log_line, f"[yellow]poll error: {wh.clean(str(exc))}[/yellow]")
                time.sleep(3)
                continue
            self.app.call_from_thread(self.apply_status, job)
            if job.get("state") in ("done", "failed", "cancelled"):
                return
            time.sleep(3)

    def report(self, job):
        result = job.get("result") or {}
        if job["state"] == "failed":
            self.log_line(f"[red]tower error: {wh.clean(str(job.get('error')))}[/red]")
            self.set_prompt("Failed. escape to go back.")
        elif result.get("found"):
            self.log_line(f"[green]Password found: {result['password']}[/green]")
            self.set_prompt("Done. escape to go back.")
        else:
            self.log_line("Password not found with this attack.")
            self.set_prompt("Done (not found). escape to go back.")

    def on_choice_cancel(self):
        self.cancel(self.job_id)

    @work(thread=True, exclusive=True)
    def cancel(self, job_id):
        try:
            client = wh.TowerClient(self.app_ref.tower_url, insecure=self.app_ref.insecure)
            client.request("DELETE", f"/api/v1/jobs/{job_id}")
            self.app.call_from_thread(self.log_line, "cancel requested")
        except (RuntimeError, OSError) as exc:
            self.app.call_from_thread(self.log_line, f"[red]{wh.clean(str(exc))}[/red]")

    def on_choice_back(self):
        self.app.pop_screen()

    def action_back(self):
        self.app.pop_screen()


class JobsScreen(PromptScreen):
    TITLE = "wifi-handshake / jobs"
    BINDINGS = [Binding("escape", "back", "back")]

    def compose(self) -> ComposeResult:
        yield Static(self.TITLE, id="menu")
        yield RichLog(id="log", wrap=True, highlight=False)
        yield DataTable(id="jobs")
        with Horizontal(classes="panel"):
            yield Button("Refresh", id="refresh", variant="primary")
            yield Button("Watch selected", id="watch")
            yield Button("Cancel selected", id="cancel")
            yield Button("Back", id="back")
        yield Static("", id="prompt")
        yield Footer()

    def on_mount(self):
        table = self.query_one("#jobs", DataTable)
        table.add_columns("job", "state", "progress", "hash rate", "result")
        table.cursor_type = "row"
        self.jobs = []
        if self.app_ref.tower_url:
            self.refresh_jobs()
        else:
            self.set_prompt("No tower set. Open Tower and connect first.")
            self.log_line("[yellow]No tower set.[/yellow]")

    def on_choice_back(self):
        self.app.pop_screen()

    def action_back(self):
        self.app.pop_screen()

    def on_choice_refresh(self):
        self.refresh_jobs()

    @work(thread=True, exclusive=True)
    def refresh_jobs(self):
        try:
            client = wh.TowerClient(self.app_ref.tower_url, insecure=self.app_ref.insecure)
            jobs = client.request("GET", "/api/v1/jobs").get("jobs") or []
        except (RuntimeError, OSError) as exc:
            self.app.call_from_thread(self.log_line, f"[red]{wh.clean(str(exc))}[/red]")
            return
        self.app.call_from_thread(self.show_jobs, jobs)

    def show_jobs(self, jobs):
        self.jobs = jobs
        table = self.query_one("#jobs", DataTable)
        table.clear()
        for job in jobs:
            result = job.get("result") or {}
            if result.get("found"):
                shown = result.get("password", "")
            elif job.get("error"):
                shown = "error"
            else:
                shown = "-"
            table.add_row(job["id"], job.get("state", "?"),
                          f"{job.get('progress') or 0:.1f}%",
                          job.get("hash_rate") or "-", shown)
        self.set_prompt(f"{len(jobs)} jobs.")

    def selected_job(self):
        table = self.query_one("#jobs", DataTable)
        if table.cursor_row < 0 or table.cursor_row >= len(self.jobs):
            return None
        return self.jobs[table.cursor_row]

    def on_choice_watch(self):
        job = self.selected_job()
        if job:
            self.app.switch_screen(CrackScreen(self.app_ref, job["id"]))

    def on_choice_cancel(self):
        job = self.selected_job()
        if job:
            self.cancel(job["id"])

    @work(thread=True, exclusive=True)
    def cancel(self, job_id):
        try:
            client = wh.TowerClient(self.app_ref.tower_url, insecure=self.app_ref.insecure)
            client.request("DELETE", f"/api/v1/jobs/{job_id}")
            self.app.call_from_thread(self.log_line, f"cancelled {job_id}")
            self.app.call_from_thread(self.refresh_jobs)
        except (RuntimeError, OSError) as exc:
            self.app.call_from_thread(self.log_line, f"[red]{wh.clean(str(exc))}[/red]")


class ServerScreen(PromptScreen):
    """Start the tower server in-process. Kept for the Windows/GPU machine."""

    TITLE = "wifi-handshake / serve"

    def compose(self) -> ComposeResult:
        yield Static(self.TITLE, id="menu")
        yield RichLog(id="log", wrap=True, highlight=False)
        with Horizontal(classes="panel"):
            yield Button("Start server", id="start", variant="primary")
            yield Button("Stop", id="stop")
            yield Button("Back", id="back")
        yield Static("", id="prompt")
        yield Footer()

    def on_mount(self):
        self.server = None
        self.worker = None
        self.log_line("Starts the tower server on this machine (the GPU box).")

    def on_choice_back(self):
        self.action_back()

    def action_back(self):
        self.stop_server()
        self.app.pop_screen()

    def on_choice_start(self):
        config = wh.TowerConfig(
            "0.0.0.0", self.app_ref.port, wh.app_dir() / "jobs",
            self.app_ref.tools_dir or wh.default_tools_dir(),
            [wh.app_dir() / "wordlists"], [])
        for directory in config.wordlist_dirs:
            directory.mkdir(parents=True, exist_ok=True)
        tools = wh.discover_tools(config)
        store = wh.JobStore(config.jobs_dir)
        self.worker = wh.TowerWorker(store, config, tools)
        self.worker.start()
        self.server = wh.TowerServer(("0.0.0.0", self.app_ref.port), wh.TowerHandler)
        self.server.store, self.server.config, self.server.tools = store, config, tools
        context = wh.ensure_server_context(config)
        if context:
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        import threading
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        scheme = "https" if context else "http"
        self.log_line(f"[green]{scheme}://0.0.0.0:{self.app_ref.port} listening[/green]")
        self.log_line(f"backend: {tools.get('backend') or 'none'}")
        for line in wh.backend_summary(tools.get("backends") or {}):
            self.log_line("  " + line)

    def on_choice_stop(self):
        self.stop_server()

    def stop_server(self):
        if self.worker is not None:
            self.worker.stop()
            self.worker = None
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            self.log_line("server stopped")


class HandshakeTUI(App):
    CSS = PLAIN_CSS
    BINDINGS = [Binding("ctrl+q", "quit", "quit", show=False)]

    def __init__(self, tower_url=None, tools_dir=None, output_dir=None,
                 port=wh.DEFAULT_PORT, insecure=False):
        super().__init__()
        self.tower_url = tower_url
        self.tools_dir = tools_dir
        self.output_dir = Path(output_dir) if output_dir else Path.cwd()
        self.port = port
        self.insecure = insecure
        self.screens_stack = []

    def engine_is_linux(self):
        return os.name == "posix"

    def status_line(self):
        tower = self.tower_url or "no tower set"
        role = "tower+client" if os.name == "nt" else "capture client"
        return f"[bold]wifi-handshake[/bold] | role: {role} | tower: {tower}"

    def remember_tower(self, url):
        self.tower_url = url

    def on_mount(self):
        if os.name == "nt":
            self.push_screen(MenuScreen(self))
        else:
            self.push_screen(MenuScreen(self))


def parse_args(argv):
    parser = argparse.ArgumentParser(description="TUI for wifi-handshake (passive capture + tower cracking).")
    parser.add_argument("--tower", help="tower base URL, e.g. https://tower:8443")
    parser.add_argument("--tools-dir", type=Path, help="folder holding hashcat")
    parser.add_argument("--output-dir", type=Path, help="where captures are saved")
    parser.add_argument("--port", type=int, default=wh.DEFAULT_PORT, help="tower server port")
    parser.add_argument("--insecure", action="store_true", help="skip certificate pinning")
    parser.add_argument("--serve", action="store_true", help="open the server screen (GPU box)")
    parser.add_argument("--self-test", action="store_true", help="run the engine self-test and exit")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.self_test:
        wh.self_test()
        return 0
    if os.name == "posix" and os.geteuid() != 0 and not args.self_test:
        # Capture needs root; the TUI re-execs itself the same way the CLI did.
        import shutil
        if shutil.which("sudo"):
            os.execvp("sudo", ["sudo", "--", sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]])
    app = HandshakeTUI(tower_url=args.tower, tools_dir=args.tools_dir,
                       output_dir=args.output_dir, port=args.port, insecure=args.insecure)
    if args.serve:
        app.push_screen(MenuScreen(app))
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
