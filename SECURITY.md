# Security

This project **captures WPA handshakes passively** and cracks them on a GPU
host. You may only use it on networks **you own or have explicit permission to
test**.

## Design guarantees

* **No deauthentication, no injection, no radio interference.** The tool
  transmits nothing on the wireless interface. Active interference is a
  criminal offense in many jurisdictions (§ 303b StGB in Germany) and is
  deliberately not implemented. To harden your own network, enable
  **802.11w/PMF** and WPA3/SAE on the access point.
* **Tailnet is the trust boundary.** The host has no application-level
  authentication; anyone who can reach the host port can start jobs. Restrict
  the port with **Tailscale ACLs** so only your laptop can reach it.
* **Transport security.** HTTPS with an automatically generated self-signed
  certificate plus SHA-256 fingerprint pinning (TOFU). `--insecure` disables
  pinning and should only be used when you fully trust the network.
* **Server-side hardening.** Uploads are size-limited (default 64 MiB) and
  magic-byte checked; the uploaded file is never executed, only parsed by the
  fixed conversion and passed to hashcat with whitelisted arguments.
  Wordlists/rules are resolved by name only (no path traversal).

## Reporting a vulnerability

Do **not** open a public issue for a vulnerability. Send a private report to
the repository owner (GitHub private vulnerability reporting, or a direct
message) describing the issue and a minimal reproduction. Public disclosure
should be coordinated once a fix ships.