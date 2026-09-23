# wifi-handshake

Passive WPA-Handshake-Aufnahme auf einem Linux-Laptop und GPU-Cracking auf einem
Windows-Tower. Der Laptop greift den Handshake auf und schickt ihn über
Tailscale an den Tower; der Tower knackt ihn mit `hashcat` auf der GPU und
schickt das Ergebnis zurück. Bedient wird alles über ein schlankes
Terminal-TUI (Textual) oder klassisch im Terminal (`--run-capture`).

> Nur für Netze, die dir gehören oder für die du eine ausdrückliche Erlaubnis
> hast. Ziel dieses Setups ist, das eigene Netz abzusichern.

---

## 1. Überblick

```
   Laptop (Linux, Arch)                     Tower (Windows + GPU)
   ┌───────────────────────┐   Tailscale   ┌──────────────────────────┐
   │ WLAN-Karte Monitor    │   + TLS/WS    │ HTTP/JSON + WebSocket    │
   │ → Handshake (.pcapng) │ ────────────► │ hcxpcapngtool → .hc22000 │
   │ Internet per USB-     │               │ hashcat -m 22000 (GPU)   │
   │ Tethering (Handy)     │ ◄──────────── │ Live-Status + Passwort   │
   └───────────────────────┘               └──────────────────────────┘
```

* **Capture** ist rein passiv: kein Deauth, keine Injection. Es gibt bewusst
  keinen Deauthentication-Sender — aktive Funkeingriffe sind strafbar (§ 303b
  StGB) und „Reichweite" lässt sich bei 802.11 nicht adressieren.
* **Transport** ist HTTPS mit selbstsigniertem Zertifikat und
  Fingerprint-Pinning, zusätzlich durch Tailscale (WireGuard) verschlüsselt.
* **Keine App-Authentifizierung**: das Tailnet ist die Vertrauensgrenze. Jedes
  Gerät im Tailnet darf Jobs starten. Mit Tailscale-ACLs einschränkbar.
* **Alles in einer Datei**: `wifi-handshake.py` enthält Engine und TUI. Die
  Rolle (`-c/--client` oder `-h/--host`) wird über die Argumente gewählt.


Alles steckt in **einer Datei**: `wifi-handshake.py`. Die Rolle (Capture-Client
oder Tower-Server) wird über die Argumente und das Betriebssystem gewählt.

---

## 2. Voraussetzungen

### Laptop (Linux)
* WLAN-Karte mit **Monitor-Mode** (dediziertes Radio, kein geteiltes PHY).
* Internet **parallel** zum Sniffen, z. B. per **USB-Tethering** vom Handy.
* Pakete:
  ```
  sudo pacman -S --needed iw aircrack-ng wireshark-cli hcxtools python iproute2 sudo
  ```
* Tailscale installiert und im selben Tailnet wie der Tower.

### Tower (Windows)
* GPU: NVIDIA (CUDA) oder AMD (OpenCL/HIP) – Backend wird automatisch gewählt.
* `hashcat` liegt als Projekt-Kopie unter `tools\hashcat-7.1.2\`.
* `hcxpcapngtool.exe` **optional** (siehe Hinweis unten).
* Tailscale installiert und im selben Tailnet wie der Laptop.

### Netzwerk
* Beide Geräte im selben Tailnet (z. B. `tower` per MagicDNS erreichbar).
* Tower muss nicht öffentlich erreichbar sein – Tailscale übernimmt NAT-Traversal.

---

## 3. Installation

### Tower: GPU-Toolchain
```
python wifi-handshake.py --install-tools
```
Lädt die gepinnte `hashcat`-Version von GitHub, prüft die SHA256-Summe und
entpackt sie nach `tools\`. Alternativ im TUI über **Setup → Install hashcat**.

> **Wichtig:** Für `hcxtools` gibt es **kein offizielles Windows-Binary**
> (ZerBea veröffentlicht nur Quellcode). Deshalb konvertiert standardmäßig der
> **Linux-Laptop** (dort ist `hcxtools` ein Paket). Der Tower konvertiert nur,
> falls `hcxpcapngtool` doch vorhanden ist. Ohne das Tool kann der Tower keine
> rohen `.pcapng` verarbeiten – schick ihm `.hc22000` (macht der Client
> automatisch).

### Laptop: Capture-Tools
```
sudo pacman -S --needed iw aircrack-ng wireshark-cli hcxtools python iproute2 sudo
pip install --user textual
```
Prüfen ohne Radio/Sudo:
```
python wifi-handshake.py --self-test
```

---

## 4. Rollen und Benutzung

`wifi-handshake.py` startet standardmäßig die TUI; die Rolle wählst du mit
`-c/--client` (Capture-Laptop) oder `-h/--host` (GPU-Tower). Ohne Rolle läuft
die Datei auf jedem System als kombinierte TUI und zeigt nur die passenden
Screens. Capture (`--run-capture`) funktioniert klassisch ohne TUI und nur
unter Linux.

### Starten (TUI)

**Tower (Windows/GPU):**
```
python wifi-handshake.py -h --port 8443
```
**Laptop (Linux):**
```
python wifi-handshake.py -c --tower https://tower:8443
```
Optionen:
`--tower URL`, `--tools-dir DIR`, `--output-dir DIR`, `--port N`, `--insecure`,
`--serve` (öffnet den Server-Screen), `--self-test`.

Auf Linux startet sich die Capture-Logik per `sudo` neu (wie das TUI es früher
tat).

### Menü und Tasten

```
[↑/↓] navigieren   [enter] wählen   [q] quit
[c] Capture        capture a handshake and crack it on the tower
[t] Tower          tower status and connection test
[j] Jobs           queue, history, reattach
[s] Setup          setup / diagnose this machine
```

### Schritt 1 – Tower starten (Windows)
Setup → **Install hashcat** falls noch nicht vorhanden, dann im Menü `[t]` den
Status prüfen. Der Server-Screen (`--serve`) startet den Dienst im TUI und
zeigt Backend und Geräte:
```
tower tools: hashcat=...\tools\hashcat-7.1.2\hashcat.exe
GPU backend: cuda
  CUDA GPU: NVIDIA GeForce RTX 4070 SUPER
https://0.0.0.0:8443 listening
```
Ein selbstsigniertes Zertifikat wird beim ersten Start automatisch erzeugt
(`~/.wifi-handshake/tower-cert.pem` / `tower-key.pem`).

### Schritt 2 – Handshake aufnehmen (Laptop)
Menü `[c]`:
1. EAPOL-Set wählen: **M1+M2** (schnell, reicht für `hashcat -m 22000`) oder
   **M1+M2+M3+M4** (voller Vierweg).
2. Adapter wählen (Monitor-Mode, dediziertes Radio).
3. `y` bestätigt und startet den Scan; Netz aus der Liste wählen.
4. Warten, bis ein passender Exchange auftaucht (ein Gerät muss sich neu
   verbinden). Danach wird gespeichert als
   `handshake-<datum>-<BSSID>-.pcapng`.
5. `t` schickt die Aufnahme direkt an den Tower.

### Schritt 3 – Cracken lassen
Menü `[c]` → Capture → `t`, oder direkt den Attack-Screen. Der Tower listet
seine Wortlisten/Regeln; Angriffsart wählen und **Submit**.
Der Crack-Screen zeigt Live-Status per WebSocket (mit Polling-Fallback):
```
running | 12.3% | 845.2 kH/s | 64C | util 98% | ETA ... | base: rockyou.txt | rules: best64.rule
```
Am Ende steht `Password found: <pw>` oder `Password not found with this attack.`

### Schritt 4 – Später wieder anhängen
Menü `[j]` → Job markieren → **Watch selected**. Der Job läuft auf dem Tower
weiter, auch wenn die Tethering-Verbindung abreißt.

### Zertifikat-Pinning
Beim ersten Kontakt wird der SHA256-Fingerprint angezeigt und einmalig
bestätigt (gespeichert in `~/.wifi-handshake/known_hosts.json`). Im TUI
überspringt `--insecure` das Pinning (nur bei vollem Vertrauen ins Netz).

---

## 5. Angriffsarten

Im Attack-Screen wählst du Wortliste und/oder Maske; die Engine baut daraus:

```json
{ "type": "dictionary", "wordlist": "rockyou.txt", "rules": ["best64.rule"] }
{ "type": "mask", "mask": "?d?d?d?d?d?d?d?d" }
{ "type": "hybrid", "wordlist": "rockyou.txt", "mask": "?d?d", "order": "wordlist-first" }
{ "type": "combination", "wordlist": "a.txt", "wordlist2": "b.txt" }
```

Für Skripte bleibt die Engine-API nutzbar; sie akzeptiert dieselben Felder,
inklusive `extra_args` (Whitelist u. a. `-w`, `-O`, `--force`, `-d`,
`--increment*`) und `backend` (`cuda`/`opencl`/`hip`).

```

---

## 6. GPU-Backend

Der Tower erkennt die Backends automatisch über `hashcat -I`:

| GPU | Backend |
|---|---|
| NVIDIA | **CUDA** (bevorzugt) |
| AMD unter Windows | **OpenCL** |
| AMD unter Linux | **HIP** |
| Intel | OpenCL |

Es werden nur Backends abgeschaltet, die `hashcat -I` tatsächlich gemeldet hat
(vermeidet ungültige Flags wie `--backend-ignore-metal` unter Windows).
CPU-Backends werden ignoriert, solange eine GPU vorhanden ist.

---

## 7. HTTP-API (Tower)

| Methode | Pfad | Zweck |
|---|---|---|
| GET | `/api/v1/health` | Status, hashcat-Version, Backend, Geräte, Queue |
| GET | `/api/v1/wordlists` | verfügbare Wortlisten und Regeln |
| GET | `/api/v1/jobs` | Job-Liste |
| GET | `/api/v1/jobs/{id}` | Job-Status |
| GET | `/api/v1/jobs/{id}/result` | Ergebnis |
| GET | `/api/v1/jobs/{id}/events` | WebSocket-Livestream |
| POST | `/api/v1/jobs` | Job anlegen (Body = Capture, Header `X-Attack`/`X-Filename`) |
| DELETE | `/api/v1/jobs/{id}` | Job abbrechen |

`X-Attack` ist Base64-kodiertes JSON der Angriffsparameter.

---

## 8. Ablage & Dateien

Basisordner: `~/.wifi-handshake` (per Umgebungsvariable `WIFI_HANDSHAKE_DIR`
änderbar).

```
~/.wifi-handshake/
├── tower-cert.pem / tower-key.pem   # TLS (automatisch erzeugt)
├── known_hosts.json                 # gepinnte Fingerprints (Client)
├── tower.potfile                    # hashcat-Potfile (spart Rechenzeit)
└── jobs/<job-id>/
    ├── status.json                  # Zustand + Live-Werte + Kommando
    ├── <upload>                     # hochgeladene .pcapng/.hc22000
    ├── capture.hc22000              # falls serverseitig konvertiert
    ├── convert.log                  # Ausgabe von hcxpcapngtool
    ├── hashcat.log                  # vollständiges hashcat-Status-Log
    └── cracked.txt                  # Klartext, falls gefunden
```
Zusätzlich liegt die hashcat-Programmkopie unter `<Projekt>\tools\`.

Es wird **nichts automatisch gelöscht** (alles bleibt zur Nachvollziehbarkeit).

---

## 9. Sicherheit

* TLS selbstsigniert + **Fingerprint-Pinning** (TOFU).
* **Keine App-Auth** – die Vertrauensgrenze ist das Tailnet. Wer den Port
  erreicht, kann Jobs starten und GPU-Zeit verbrauchen.
* Härtung: Tailscale-ACLs so setzen, dass nur der Laptop den Port erreichen darf.
* Uploads: Größenlimit, Magic-Byte-Prüfung (pcap/pcapng/hc22000), Original wird
  nie ausgeführt, nur die feste Konvertierung.
* hashcat-Argumente: nur Whitelist-Flags; Wortlisten/Regeln werden nur als Name
  aufgelöst (kein Path-Traversal).
* **Kein Deauth/Injection**: Das Tool sendet nichts. Es kann also auch nicht
  versehentlich fremde Netze stören.

---

## 10. Fehlersuche

| Problem | Ursache / Lösung |
|---|---|
| `./OpenCL/: No such file or directory` | hashcat läuft mit falschem Arbeitsverzeichnis. Die Engine setzt automatisch `cwd` auf den hashcat-Ordner. |
| `hashcat exited with code ...` | `hashcat.log` im Job-Ordner prüfen (Treiber, `--force` nötig?). |
| `Upload is a raw capture but hcxpcapngtool is not available` | Auf dem Tower fehlt `hcxtools` (kein Windows-Binary). Auf dem Laptop `pacman -S hcxtools` installieren – der Client konvertiert dann lokal. |
| `Unknown or disallowed file: x.txt` | Wortliste liegt nicht in einem Wortlisten-Ordner des Towers. |
| `Certificate fingerprint mismatch` | Zertifikat des Towers neu erzeugt. `known_hosts.json` anpassen oder TUI mit `--insecure` starten. |
| hashcat startet nicht (`is not a valid Win32 application`) | Nur ein `.cmd`-Shim gefunden; die Projekt-Kopie unter `tools\` verwenden. |
| TUI zeigt „No tower set" | Im Tower-Screen verbinden, dann Screen neu öffnen. |
| `rich`/`textual` fehlt | `pip install --user textual`. |

---

## 11. Grenzen (ehrlich)

* **Kein hcxtools-Auto-Install unter Windows** möglich – Konvertierung passiert
  standardmäßig auf dem Linux-Laptop.
* Der Capture-Teil ist **nur unter Linux** lauffähig (iw/airodump-ng/tshark).
  Unter Windows zeigt das TUI deshalb Setup/Tower/Jobs/Attack.
* Die M1+M2-Erkennung prüft **Paketstruktur, nicht die MIC** – ein „passender“
  Exchange kann trotzdem kein gültiger Handshake sein.
* Brute-Force scheitert in der Praxis häufig; „nicht gefunden“ ist normal.
* Ein Job gleichzeitig (GPU), der Rest wartet in der Queue.
* **Kein Deauth/Disassoc-Sender und keine „Reichweiten"-Steuerung**: aktive
  Funkeingriffe sind strafbar (§ 303b StGB), und 802.11 hat kein Range-Feld.
  Als Schutzmaßnahme stattdessen **802.11w/PMF** im AP aktivieren und WPA3/SAE
  prüfen – dann sind Management-Frames geschützt.

---

## 12. TUI-Kurzreferenz

```
Starten:
  python wifi-handshake.py -c                          # Laptop (client)
  python wifi-handshake.py -h --tower https://tower    # GPU-Box (host)
  python wifi-handshake.py -h --port 8443 --serve      # Server-Screen
  python wifi-handshake.py --self-test                 # Engine-Tests, kein Radio
  python wifi-handshake.py --run-capture               # klassisch, ohne TUI (Linux)

Tasten im Menü:
  c capture    Capture-Screen (Linux)
  t tower      Tower-Status / Verbindung
  j jobs       Queue/Historie, reattach, cancel
  s setup      Diagnose + hashcat installieren
  q quit       Beenden
  esc          zurück

Ausgabe der Engine-API (für Skripte):
  Engine-Funktionen in wifi-handshake.py bleiben importierbar
  (TowerConfig/TowerClient/JobStore/build_hashcat_command/...).
```

