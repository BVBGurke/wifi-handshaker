# wifi-handshake

Passive WPA-Handshake-Aufnahme auf einem Linux-Laptop und GPU-Cracking auf einem
Windows-Tower. Der Laptop greift den Handshake auf und schickt ihn über
Tailscale an den Tower; der Tower knackt ihn mit `hashcat` auf der GPU und
schickt das Ergebnis zurück.

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

* **Capture** ist rein passiv: kein Deauth, keine Injection.
* **Transport** ist HTTPS mit selbstsigniertem Zertifikat und
  Fingerprint-Pinning, zusätzlich durch Tailscale (WireGuard) verschlüsselt.
* **Keine App-Authentifizierung**: das Tailnet ist die Vertrauensgrenze. Jedes
  Gerät im Tailnet darf Jobs starten. Mit Tailscale-ACLs einschränkbar.

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
entpackt sie nach `tools\`. Danach:
```
python wifi-handshake.py --serve --port 8443
```

> **Wichtig:** Für `hcxtools` gibt es **kein offizielles Windows-Binary**
> (ZerBea veröffentlicht nur Quellcode). Deshalb konvertiert standardmäßig der
> **Linux-Laptop** (dort ist `hcxtools` ein Paket). Der Tower konvertiert nur,
> falls `hcxpcapngtool` doch vorhanden ist. Ohne das Tool kann der Tower keine
> rohen `.pcapng` verarbeiten – schick ihm `.hc22000` (macht der Client
> automatisch).

### Laptop: Capture-Tools
```
sudo pacman -S --needed iw aircrack-ng wireshark-cli hcxtools python iproute2 sudo
```
Prüfen ohne Radio/Sudo:
```
python wifi-handshake.py --self-test
```

---

## 4. Benutzung

### Schritt 1 – Tower starten (Windows)
```
python wifi-handshake.py --serve --port 8443
```
Ausgabe u. a.:
```
Tower tools: hashcat=...\tools\hashcat-7.1.2\hashcat.exe hcxpcapngtool=None
GPU backend: cuda
  CUDA GPU: NVIDIA GeForce RTX 4070 SUPER
Tower listening on https://0.0.0.0:8443
```
Optionen:

| Flag | Bedeutung |
|---|---|
| `--host` | Bind-Adresse (Default `0.0.0.0`) |
| `--port` | Port (Default `8443`) |
| `--jobs-dir` | Ablage der Jobs (Default `~/.wifi-handshake/jobs`) |
| `--tools-dir` | Ordner mit `hashcat`/`hcxpcapngtool` (Default `.\tools`) |
| `--wordlist-dir` | Wortlisten-Ordner, **mehrfach** angebbar |
| `--rule-dir` | hashcat-Regelordner, **mehrfach** angebbar |
| `--cert` / `--key` | eigenes TLS-Zertifikat/-Key (PEM) |
| `--no-tls` | Klartext-HTTP (Tailscale verschlüsselt trotzdem) |
| `--max-upload-mb` | Upload-Limit (Default 64 MiB) |

Beim ersten Start wird automatisch ein selbstsigniertes Zertifikat erzeugt
(`~/.wifi-handshake/tower-cert.pem` / `tower-key.pem`).

### Schritt 2 – Handshake aufnehmen (Laptop)
```
python wifi-handshake.py
```
Ablauf:
1. Wahl der benötigten EAPOL-Nachrichten: **M1+M2** (schnell, reicht für
   `hashcat -m 22000`) oder **M1+M2+M3+M4** (voller Vierweg).
2. Adapter wählen (Monitor-Mode fähig, dediziertes Radio).
3. Netz scannen, Ziel wählen, warten bis ein passender Exchange auftaucht.
4. Datei wird gespeichert, z. B. `handshake-20260923-...-<BSSID>-.pcapng`.

Nicht-interaktiv vorgeben:
```
python wifi-handshake.py --handshake m1m2
python wifi-handshake.py --handshake m1m2m3m4
```

### Schritt 3 – Cracken lassen (Laptop → Tower)
Direkt nach der Aufnahme:
```
python wifi-handshake.py --tower https://tower:8443
```
Oder eine vorhandene Aufnahme schicken:
```
python wifi-handshake.py --tower https://tower:8443 --send handshake-....pcapng
```
Ablauf:
* Der Client wandelt `.pcapng` lokal zu `.hc22000` um (wenn `hcxpcapngtool` da
  ist) und schickt sie hoch.
* Der Tower listet seine Wortlisten/Regeln; du wählst die Angriffsart.
* Live-Status per WebSocket (mit Polling-Fallback):
  ```
  running | 12.3% | 845.2 kH/s | 64C | util 98% | ETA ... | base: rockyou.txt | rules: best64.rule
  ```
* Am Ende: `Password found: <pw>` oder `Password not found with this attack.`

### Schritt 4 – Später wieder anhängen
Bricht die Verbindung (z. B. Tethering) ab, läuft der Job auf dem Tower weiter:
```
python wifi-handshake.py --tower https://tower:8443 --watch <job-id>
```

### Zertifikat-Pinning
Beim ersten Kontakt wird der SHA256-Fingerprint angezeigt und einmalig
bestätigt (gespeichert in `~/.wifi-handshake/known_hosts.json`). Optionen:
* `--fingerprint <sha256>` – Fingerprint fest vorgeben
* `--insecure` – Pinning überspringen (nur wenn du dem Netz voll vertraust)

---

## 5. Angriffsarten

Der Client fragt interaktiv ab oder nimmt eine JSON-Datei per `--attack`:

```json
{ "type": "dictionary", "wordlist": "rockyou.txt", "rules": ["best64.rule"] }
```
```json
{ "type": "mask", "mask": "?d?d?d?d?d?d?d?d" }
```
```json
{ "type": "hybrid", "wordlist": "rockyou.txt", "mask": "?d?d", "order": "wordlist-first" }
```
```json
{ "type": "combination", "wordlist": "a.txt", "wordlist2": "b.txt" }
```

Zusatzfelder (optional):
* `"extra_args": ["-w", "3", "--force"]` – nur erlaubte hashcat-Flags
  (Whitelist; u. a. `-w`, `-O`, `--force`, `-d`, `--increment*`).
* `"backend": "cuda" | "opencl" | "hip"` – Backend erzwingen statt Auto-Wahl.

Beispiel:
```
python wifi-handshake.py --tower https://tower:8443 --send cap.pcapng --attack attack.json
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

---

## 10. Fehlersuche

| Problem | Ursache / Lösung |
|---|---|
| `./OpenCL/: No such file or directory` | hashcat läuft mit falschem Arbeitsverzeichnis. Die Skript-Kopie setzt automatisch `cwd` auf den hashcat-Ordner. |
| `hashcat exited with code ...` | `hashcat.log` im Job-Ordner prüfen (Treiber, `--force` nötig?). |
| `Upload is a raw capture but hcxpcapngtool is not available` | Auf dem Tower fehlt `hcxtools` (kein Windows-Binary). Auf dem Laptop `pacman -S hcxtools` installieren – der Client konvertiert dann lokal. |
| `Unknown or disallowed file: x.txt` | Wortliste liegt nicht in einem `--wordlist-dir` des Towers. |
| `Certificate fingerprint mismatch` | Zertifikat des Towers neu erzeugt. `known_hosts.json` anpassen oder `--fingerprint` setzen. |
| hashcat startet nicht (`is not a valid Win32 application`) | Nur ein `.cmd`-Shim gefunden; die Projekt-Kopie unter `tools\` verwenden. |
| `--backend-ignore-metal` unbekannt | Wird vermieden; es werden nur erkannte Backends ignoriert. |

---

## 11. Grenzen (ehrlich)

* **Kein hcxtools-Auto-Install unter Windows** möglich – Konvertierung passiert
  standardmäßig auf dem Linux-Laptop.
* Der Capture-Teil ist **nur unter Linux** lauffähig (iw/airodump-ng/tshark).
  Unter Windows gibt es nur `--serve`, `--install-tools`, `--send`, `--watch`.
* Die M1+M2-Erkennung prüft **Paketstruktur, nicht die MIC** – ein „passender“
  Exchange kann trotzdem kein gültiger Handshake sein.
* Brute-Force scheitert in der Praxis häufig; „nicht gefunden“ ist normal.
* Ein Job gleichzeitig (GPU), der Rest wartet in der Queue.

---

## 12. CLI-Kurzreferenz

```
Capture (Linux):
  --handshake {m1m2,m1m2m3m4}   benötigte EAPOL-Nachrichten
  --scan-seconds N              Scandauer
  --band {bg,a,abg}             Frequenzband
  --channels 1,6,11             nur diese Kanäle
  --timeout N                   Aufnahmezeit (0 = unbegrenzt)
  --max-mb N                    Größenlimit des temporären Captures
  --output-dir DIR              Ablageort der Aufnahme
  --self-test                   Offline-Tests, kein Sudo/Radio

Tower (Windows):
  --serve                       Server starten
  --host / --port               Bind-Adresse / Port
  --jobs-dir / --tools-dir      Ablage / Toolchain
  --wordlist-dir / --rule-dir   (mehrfach) Wortlisten / Regeln
  --cert / --key / --no-tls     TLS-Konfiguration
  --max-upload-mb N             Upload-Limit
  --install-tools               hashcat herunterladen + prüfen + entpacken

Client (Linux):
  --tower URL                   Tower-Basis-URL
  --send FILE                   vorhandenes Capture senden
  --watch JOB-ID                an laufenden Job wieder anhängen
  --attack FILE.json            Angriffsparameter
  --fingerprint SHA256          Zertifikat pinnen
  --insecure                    Pinning überspringen
```
