# wifi-handshake

Passive WPA handshake capture on a Linux laptop and GPU cracking on a
Windows tower. The laptop grabs the handshake and sends it over Tailscale to
the tower; the tower cracks it with `hashcat` on the GPU and sends the result
back. Everything is driven from an interactive terminal menu or classically
from a shell (`--run-capture`).

> Only for networks you own or have explicit permission to test. The purpose
> of this setup is to secure your own network.

---

## 1. Overview

```
   Laptop (Linux, Arch)                     Tower (Windows + GPU)
   ┌───────────────────────┐   Tailscale   ┌──────────────────────────┐
   │ WLAN card monitor     │   + TLS/WS    │ HTTP/JSON + WebSocket    │
   │ → Handshake (.pcapng) │ ────────────► │ hcxpcapngtool → .hc22000 │
   │ Internet via USB      │               │ hashcat -m 22000 (GPU)   │
   │ tethering (phone)     │ ◄──────────── │ live status + password   │
   └───────────────────────┘               └──────────────────────────┘
```

* **Capture is purely passive**: no deauth, no injection. There is
  deliberately no deauthentication sender — active radio interference is a
  criminal offense (§ 303b StGB) and "range" cannot be addressed in 802.11.
* **Transport** is HTTPS with a self-signed certificate and fingerprint
  pinning, additionally encrypted by Tailscale (WireGuard).
* **No app-level authentication**: the tailnet is the trust boundary. Anyone
  in the tailnet may start jobs. Restrict it with Tailscale ACLs if needed.
* **One file for everything**: `wifi-handshake.py` contains the engine and the
  terminal menu. The mode (capture / tower / client) is chosen in the menu.

---

## 2. Requirements

### Laptop (Linux)
* WLAN card with **monitor mode**. Monitor mode is a driver/firmware
  capability — the software cannot add it. Check your card with:
  ```
  iw phy | grep -A1 "Supported interface modes"    # look for "monitor"
  ```
  Known to work on Linux (monitor mode): Atheros `ath9k`/`ath9k_htc`
  (AR9271, AR9000), MediaTek `mt76` (MT7601, MT7612U, MT7921), Realtek
  `rtw88` (RTL8723DE, RTL8821CE, 2.4 GHz only) and `rtl88xxau`
  (RTL8811AU/RTL8812AU/RTL8814AU), and many Intel cards (monitor yes,
  injection usually no). Many **Broadcom** onboard chips and some older Intel
  parts cannot monitor at all.
* Ideally a **dedicated radio** (no shared PHY) so your normal Wi-Fi stays up.
  The tool warns if another interface shares the radio.
* Internet **in parallel** to sniffing, e.g. via **USB tethering** from a phone.
* Packages:
  ```
  sudo pacman -S --needed iw aircrack-ng wireshark-cli hcxtools python iproute2 sudo
  ```
* Tailscale installed and in the same tailnet as the tower.

### Tower (Windows)
* GPU: NVIDIA (CUDA) or AMD (OpenCL/HIP) — backend is auto-selected.
* `hashcat` as a project copy under `tools\hashcat-7.1.2\`.
* `hcxpcapngtool.exe` **optional** (see note below).
* Tailscale installed and in the same tailnet as the laptop.

### Network
* Both devices in the same tailnet. Discovery matches the tower by its tailnet
  hostname and connects to its tailnet **IP** (`100.x.y.z`), so MagicDNS is not
  required.
* The tower does not need to be publicly reachable — Tailscale handles NAT traversal.
* Join the tailnet on each device with `sudo tailscale up`, or from the tool with
  `python wifi-handshake.py --tailscale-login` (menu item **7 – Tailscale**).
  `--tailscale-status` shows the peers and their tailnet IPs.

---

## 3. Installation

### Tower: GPU toolchain
```
python wifi-handshake.py --install-tools
```
Downloads the pinned `hashcat` version from GitHub, verifies the SHA256
checksum and unpacks it into `tools\`. Alternatively use menu item
**Install hashcat**.

> **Important:** There is **no official Windows binary** for `hcxtools`
> (ZerBea only publishes source). That is why by default the **Linux laptop**
> does the conversion (there `hcxtools` is a package). The tower only converts
> if `hcxpcapngtool` is actually present. Without it the tower cannot process
> raw `.pcapng` files — send it `.hc22000` instead (the client does this
> automatically).

### Laptop: capture tools
```
sudo pacman -S --needed iw aircrack-ng wireshark-cli hcxtools python iproute2 sudo
```
Verify without radio/sudo:
```
python wifi-handshake.py --self-test
```

---

## 4. Roles and usage

Without arguments `wifi-handshake.py` starts an interactive terminal menu:

```
wifi-handshake - Terminal Menu
  1. Capture handshake  (Linux, monitor mode, root)
  2. Start tower        (server + hashcat, for the GPU box)
  3. Send capture       (client, to --tower URL)
  4. Help / Install     (--help, download hashcat)
  5. Inspect capture    (offline: find/verify a handshake in a file)
  6. Example captures   (download public test data)
  7. Tailscale          (status, log in, pick the tower in your tailnet)
  q  Quit
```

The menu stays open after each action. After a successful capture it asks
whether to send the file to the tower right away (menu item 1 → capture →
"Send this capture to a tower now? [y/N]"). When run without root, the
`sudo` password is asked **once** at the start of the capture and kept alive
in the background, so long captures never prompt again; the capture itself runs
as a child process, so the menu survives.

The whole interface is **English-only by project rule** (enforced by a comment
at the top of `wifi-handshake.py`).

Run modes without the menu:

**Tower (Windows/GPU):**
```
python wifi-handshake.py --serve --port 8443
```
**Laptop (Linux):**
```
python wifi-handshake.py --run-capture
```
**Client upload (platform-neutral):**
```
python wifi-handshake.py --tower https://tower:8443 --send capture.pcapng
```
Options:
`--tower URL`, `--tools-dir DIR`, `--output-dir DIR`, `--port N`, `--insecure`,
`--serve`, `--self-test`, `--inspect FILE`, `--download-captures [DIR]`,
`--tower-name NAME`, `--tailscale-status`, `--tailscale-login`,
`--discover-towers`.

### Tailscale (tower discovery)

The tower does not need a public address: put both machines in the same
**tailnet** and let Tailscale handle NAT traversal. The tool wraps the
`tailscale` CLI so you rarely have to type a URL:

```
python wifi-handshake.py --tailscale-status   # show this node and all peers
python wifi-handshake.py --tailscale-login    # join the tailnet (`tailscale up`)
python wifi-handshake.py --discover-towers    # scan peers for a running tower
python wifi-handshake.py --send capture.pcapng --tower-name tower
```

`--tailscale-status` prints the login state, this device's tailnet IP and a
numbered list of peers. `--tower-name NAME` looks that peer up by its hostname
and builds the tower URL from its **tailnet IP**, e.g.
`https://100.x.y.z:<port>` (the default name when discovering is `tower`).

**Auto-discovery:** `--discover-towers` probes every online peer on the tower
port and performs the tower **health handshake** (`/api/v1/health`), so only
peers that really run the tower are listed. When no peer matches `--tower-name`,
an upload (`--send`/`--watch`) falls back to scanning the tailnet and connecting
to the first reachable tower automatically. Menu item **7 – Tailscale** offers
this as action **d** (scan + connect) and lets you store a peer as the tower for
later sends.

`--serve` prints the tailnet IP the tower is reachable at, e.g.
`use: --tower https://100.x.y.z:8443`.

If Tailscale is not installed or the daemon is not running the helpers only warn
and the tool keeps working with an explicit `--tower URL`. A userspace daemon
(no root) is supported by pointing at its socket:

```
WIFI_HANDSHAKE_TAILSCALE_SOCKET=/run/user/1000/tailscaled.sock \
  python wifi-handshake.py --tailscale-status
```

### Offline inspection and example captures

A capture can be checked **without a radio or root** — useful before uploading it
to the tower, and for testing the parser against known-good data:

```
python wifi-handshake.py --inspect capture.pcapng
python wifi-handshake.py --inspect capture.pcapng --essid MyNetwork --password secret123
```

`--inspect` finds four-way handshakes with the same parser the live capture uses.
With `--essid` and `--password` it also derives the PTK (PBKDF2 + the 802.11 PRF)
and **verifies the M2/M4 MIC**, i.e. proves the handshake is complete and usable.

`--download-captures` fetches the public example captures from
[`vanhoefm/wifi-example-captures`](https://github.com/vanhoefm/wifi-example-captures)
into `./test-captures` (or a directory you pass). When those files are present,
`--self-test` additionally verifies the documented WPA2 example, so the crypto
path is covered by a real capture. Use `--captures-repo owner/repo` to point at a
different repository of `.pcap`/`.pcapng` files.

The scan list also shows a **Cl** column (associated clients seen in the
airodump CSV). APs with clients are the best passive targets: they rekey when
their own devices reconnect, no deauthentication needed.

### Step 1 – Start the tower (Windows)
Via menu item **2 – Start tower** or directly:
```
python wifi-handshake.py --serve --port 8443
```
```
tower tools: hashcat=...\tools\hashcat-7.1.2\hashcat.exe
GPU backend: cuda
  CUDA GPU: NVIDIA GeForce RTX 4070 SUPER
https://0.0.0.0:8443 listening
```
A self-signed certificate is created automatically on first start
(`~/.wifi-handshake/tower-cert.pem` / `tower-key.pem`).

### Step 2 – Capture a handshake (Laptop)
Via menu item **1 – Capture handshake** (or `--run-capture`):

The adapter is put into monitor mode automatically, using the most compatible
path available: an interface that is already in monitor mode is reused; if the
managed interface cannot be switched directly, a dedicated monitor interface is
created (`iw phy <phy> interface add ... type monitor`). If neither works, the
card genuinely does not support monitor mode. The original mode/state is
restored afterwards.

1. Choose the EAPOL set: `--handshake m1m2` (fast, enough for `hashcat -m 22000`)
   or `--handshake m1m2m3m4` (full four-way). **`m1m2` is the default** because
   M3/M4 are frequently lost in practice and hashcat only needs M1+M2.
2. Choose the adapter (monitor mode, dedicated radio).
3. Confirm with `YES` to start the scan; pick a network from the list. The scan
   band defaults to `abg` (2.4 + 5 GHz); use `--band 6` (or `abg6`) for Wi-Fi 6E
   and `--channels 1,6,11` / `--channels 5180` to restrict channels or
   frequencies. If the
   scanner lists several SSIDs of the same access point (same AP base MAC), a
   note tells you so — connect the test device to exactly the SSID you pick.
4. Wait for a matching exchange (a device must reconnect). The tool prints
   actionable hints when nothing arrives (toggle Wi-Fi on the test device,
   check SSID/band, move closer). The result is saved as
   `handshake-<date>-<BSSID>-.pcapng`.
5. Send the capture to the tower via menu item **3 – Send capture**.

### Step 3 – Have it cracked
The tower lists its wordlists/rules in the API; attacks start via `--attack`
JSON through the client (see below). Live status runs over WebSocket (with
polling fallback):
```
running | 12.3% | 845.2 kH/s | 64C | util 98% | ETA ... | base: rockyou.txt | rules: best64.rule
```
At the end it shows `Password found: <pw>` or `Password not found with this attack.`

### Step 4 – Reattach later
Reattach to a running job via `--watch <job-id>`. The job keeps running on the
tower even if the tethering connection drops.

### Certificate pinning
On first contact the SHA256 fingerprint is shown and confirmed once (stored in
`~/.wifi-handshake/known_hosts.json`). `--insecure` skips pinning (only if you
fully trust the network).

---

## 5. Choosing the attack (scripts/engine)

The tower lists its wordlists/rules in the API. With `--attack attack.json` on
the command line you choose a wordlist and/or mask; the engine builds:

```json
{ "type": "dictionary", "wordlist": "rockyou.txt", "rules": ["best64.rule"] }
{ "type": "mask", "mask": "?d?d?d?d?d?d?d?d" }
{ "type": "hybrid", "wordlist": "rockyou.txt", "mask": "?d?d", "order": "wordlist-first" }
{ "type": "combination", "wordlist": "a.txt", "wordlist2": "b.txt" }
```

For scripts the engine API stays usable; it accepts the same fields including
`extra_args` (whitelist includes `-w`, `-O`, `--force`, `-d`, `--increment*`)
and `backend` (`cuda`/`opencl`/`hip`).

---

## 6. GPU backend

The tower detects backends automatically via `hashcat -I`:

| GPU | Backend |
|---|---|
| NVIDIA | **CUDA** (preferred) |
| AMD on Windows | **OpenCL** |
| AMD on Linux | **HIP** |
| Intel | OpenCL |

Only backends actually reported by `hashcat -I` are disabled (avoids invalid
flags such as `--backend-ignore-metal` on Windows). CPU backends are ignored as
long as a GPU is present.

---

## 7. HTTP API (tower)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/health` | status, hashcat version, backend, devices, queue |
| GET | `/api/v1/wordlists` | available wordlists and rules |
| GET | `/api/v1/jobs` | job list |
| GET | `/api/v1/jobs/{id}` | job status |
| GET | `/api/v1/jobs/{id}/result` | result |
| GET | `/api/v1/jobs/{id}/events` | WebSocket live stream |
| POST | `/api/v1/jobs` | create job (body = capture, headers `X-Attack`/`X-Filename`) |
| DELETE | `/api/v1/jobs/{id}` | cancel job |

`X-Attack` is Base64-encoded JSON of the attack parameters.

Uploads are limited to 64 MiB by default (changeable with `--max-upload-mb`
on the tower; `options: --tower URL, --serve, --port N, --max-upload-mb ...`).

---

## 8. Storage & files

Base folder: `~/.wifi-handshake` (changeable via the `WIFI_HANDSHAKE_DIR`
environment variable).

```
~/.wifi-handshake/
├── tower-cert.pem / tower-key.pem   # TLS (auto-generated)
├── known_hosts.json                 # pinned fingerprints (client)
├── tower.potfile                    # hashcat potfile (saves compute time)
└── jobs/<job-id>/
    ├── status.json                  # state + live values + command
    ├── <upload>                     # uploaded .pcapng/.hc22000
    ├── capture.hc22000              # if converted server-side
    ├── convert.log                  # output of hcxpcapngtool
    ├── hashcat.log                  # full hashcat status log
    └── cracked.txt                  # plaintext, if found
```
Additionally the hashcat program copy lives under `<project>\tools\`.

**Nothing is deleted automatically** (everything stays for traceability).

---

## 9. Security

* TLS self-signed + **fingerprint pinning** (TOFU).
* **No app auth** — the trust boundary is the tailnet. Whoever can reach the
  port can start jobs and consume GPU time.
* Hardening: set Tailscale ACLs so only the laptop can reach the port.
* Uploads: size limit, magic-byte check (pcap/pcapng/hc22000), the original is
  never executed, only the fixed conversion.
* hashcat arguments: only whitelisted flags; wordlists/rules are resolved by
  name only (no path traversal).
* **No deauth/injection**: The tool sends nothing, so it cannot accidentally
  disturb foreign networks.

---

## 10. Troubleshooting

| Problem | Cause / fix |
|---|---|
| `./OpenCL/: No such file or directory` | hashcat runs with the wrong working directory. The engine sets `cwd` to the hashcat folder automatically. |
| `hashcat exited with code ...` | check `hashcat.log` in the job folder (driver, `--force` needed?). |
| `Upload is a raw capture but hcxpcapngtool is not available` | `hcxtools` is missing on the tower (no Windows binary). Install `pacman -S hcxtools` on the laptop — the client then converts locally. |
| `Unknown or disallowed file: x.txt` | wordlist is not in a tower wordlist folder. |
| `Certificate fingerprint mismatch` | certificate of the tower was recreated. Adjust `known_hosts.json` or connect with `--insecure`. |
| Upload always fails / "connection reset" | old towers crash the upload handler when started without `--max-upload-mb` (it defaulted to `None`). Restart the tower with this build; the limit now defaults to 64 MiB. |
| hashcat does not start (`is not a valid Win32 application`) | only a `.cmd` shim was found; use the project copy under `tools\`. |
| "No tower set" | set the tower URL with `--tower URL` or enter it in menu item 3. |
| Capture runs but never finds EAPOL | the test device must reconnect, and it must join exactly the selected SSID/band. The tool prints hint messages; if the AP broadcasts several SSIDs (same AP base MAC), pick the one the device actually joins. Toggling Wi-Fi on the device creates a fresh four-way handshake. |

---

## 11. Limits (honest)

* **No hcxtools auto-install on Windows** — conversion happens on the Linux
  laptop by default.
* The capture part only runs **on Linux** (iw/airodump-ng/tshark). On
  macOS/Windows only the tower and client upload are available.
* **Monitor mode is hardware**: no software can make a card capture if its
  driver/firmware does not expose monitor mode. The tool covers the common
  setup paths, but it cannot create the capability.
* On 2.4 GHz and 6 GHz some channel numbers are identical (e.g. channel 1).
  Scanning both bands at once can therefore mislabel a 6 GHz AP as 2.4 GHz.
  Scan 6 GHz on its own with `--band 6` when that matters.
* M1+M2 detection checks **packet structure, not the MIC** — a "matching"
  exchange may still not be a valid handshake.
* Brute force frequently fails in practice; "not found" is normal.
* One job at a time (GPU); the rest wait in the queue.
* **No deauth/disassoc sender and no "range" control**: active radio
  interference is a criminal offense (§ 303b StGB), and 802.11 has no range
  field. As protection instead enable **802.11w/PMF** on the AP and check
  WPA3/SAE — then management frames are protected.

---

## 12. Related projects (research)

This tool deliberately stays **passive** (no deauth, no injection). The
following established open-source projects solve adjacent problems and were
reviewed while building the compatibility layer:

| Project | What it is good for | Note |
|---|---|---|
| [ZerBea/hcxdumptool](https://github.com/ZerBea/hcxdumptool) | Modern capture of EAPOL handshakes **and PMKID**, best chipset coverage | Transmits association/deauth frames; not passive. Use `--disable_deauthentication` and only on your own network |
| [ZerBea/hcxtools](https://github.com/ZerBea/hcxtools) | `hcxpcapngtool` converts captures to `.hc22000` | Recommended by hashcat; the client uses it locally |
| [derv82/wifite2](https://github.com/derv82/wifite2) | Automated audit workflow (scan → capture → crack) | Wraps aircrack-ng/hashcat; active by default |
| [bettercap/bettercap](https://github.com/bettercap/bettercap) | Wi-Fi recon, PMKID, deauth in a scriptable framework | Active attacks |
| [aircrack-ng/aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) | `airodump-ng` scanning and `aircrack-ng` cracking | Used here for scanning |
| [x4v1l0k/wifi-snatcher](https://github.com/x4v1l0k/wifi-snatcher) | Automated grab workflow: scan for APs **with clients**, capture, validate, wordlists | Active (broadcast deauth / PMKID). Only the passive parts (client detection, validation) are reflected here |
| [vanhoefm/wifi-example-captures](https://github.com/vanhoefm/wifi-example-captures) | Real captures with documented passphrases | Used by `--download-captures` and the optional self-test |
| [morrownr/USB-WiFi](https://github.com/morrownr/USB-WiFi) | Adapter buying guide: which chipsets do monitor mode / injection on Linux | Great for choosing hardware |

What this project adds on top: a **strictly passive** capture path, a
self-contained `.hc22000` upload, and GPU cracking over Tailscale.

---

## 13. Quick reference

```
Start (menu):
  python wifi-handshake.py                  # interactive terminal menu
  python wifi-handshake.py --run-capture     # capture directly (Linux)
  python wifi-handshake.py --serve --port 8443   # tower server
  python wifi-handshake.py --tower URL --send cap.pcapng   # client upload
  python wifi-handshake.py --self-test       # engine tests, no radio
  python wifi-handshake.py --inspect cap.pcapng   # find a handshake offline
  python wifi-handshake.py --inspect cap.pcapng --essid SSID --password PW
  python wifi-handshake.py --download-captures    # example captures -> ./test-captures

Capture flow (menu item 1):
  choose adapter -> confirm YES -> scan -> pick a network
  -> select EAPOL set (M1+M2 default) -> wait for a handshake
  -> saved as handshake-<date>-<BSSID>.pcapng
  -> offer to send to the tower, then back to the menu
  -> q quit / r rescan

Band/channel options (--run-capture):
  --band abg           2.4 + 5 GHz (default)      --band 6     6 GHz only
  --band abg6          all three bands            --channels 1,6,11
  --channels 5180      a frequency in MHz         --scan-seconds 30

Engine API output (for scripts):
  Engine functions in wifi-handshake.py stay importable
  (TowerConfig/TowerClient/JobStore/build_hashcat_command/...).
```