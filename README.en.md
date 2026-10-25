<div align="center">
  <img src="docs/assets/owl-card.png" width="120" alt="Qulogi owl" />
  <h1>Qulogi</h1>
  <p><em>An owl sees in the dark. Traffic goes through the filters.</em></p>
</div>

[Русский](README.md) | [English](README.en.md)

Qulogi is a cross-platform tool for keeping the internet open under active traffic filtering. Three bypass methods in one core: an obfuscated tunnel to your own server, tunnel camouflage that imitates whitelisted services, and a local TLS-level DPI bypass. The core is written in Go, the interface is Flutter with Material 3 Expressive. No third-party servers in the middle: traffic goes only through what you configured.

Status: the core, CLI clients and the desktop path are fully working. Android VPN mode (VpnService + gVisor netstack), TLS camouflage and zapret-style DPI strategies are implemented; iOS ships as a NetworkExtension scaffold (see the roadmap).

![CI](https://github.com/mel0k1/Qulogi/actions/workflows/build.yml/badge.svg)
![License](https://img.shields.io/badge/license-GPL--3.0-blue)

## How it works

### VPN mode (Android, full-device tunnel)

The app brings up Android VpnService, the TUN file descriptor is passed into the Go core where a gVisor netstack terminates TCP and UDP and feeds the flows into the engine — through the tunnel or directly with DPI tricks. The kill switch keeps the interface up and blocks all traffic when protection goes down, so nothing leaks. In tunnel egress DNS travels over TCP (RFC 7766), leaving no UDP leak.

```text
device apps
      |
      v
Android VpnService (TUN fd)
      |
      v
gVisor netstack (internal/vpn) -- TCP/UDP flows
      |
      +-- egress tunnel --> AES-256-GCM + camouflage --> qulogid (VPS) --> the internet
      +-- egress direct --> zapret-style TLS splits --> straight out
```

### SOCKS5 proxy modes (desktop and Android)

- **Tunnel.** All traffic goes through an encrypted tunnel to your server and reaches the internet from there.
- **Tunnel + camouflage.** The tunnel stream is wrapped in a TLS-shaped envelope: the client emits a realistic ClientHello with the SNI of a whitelisted platform (`vkvideo.ru`, `rutube.ru`, …), the server answers with a fake ServerHello, and every payload byte afterwards travels inside application-data records. To an inspector it looks like HTTPS to a video host, while underneath runs our GCM stream.
- **DPI.** Traffic goes directly, but the ClientHello is split so the inspector cannot see the host name in the first packet. No server needed.

## What is inside

- `internal/tunnel` — tunnel protocol: handshake with fresh salts, HKDF-SHA256, AES-256-GCM, sequenced frames. A wrong key is dropped on the first frame.
- `internal/transport` — TLS camouflage: a ClientHello generator with configurable SNI (browser cipher set, GREASE, key share, padding to ~517 bytes), a fake ServerHello+CCS flight, automatic mode detection on the server. This is the "transport through permitted services" piece: the connection imitates whitelisted-platform traffic.
- `internal/dpi` — ClientHello desync strategies in the spirit of zapret/goodbye-dpi: auto split after SNI, first byte, 8/32 bytes, multi-split (extra cuts inside the hostname to defeat segment reassemblers), optional inter-segment delay. All tricks are server-transparent and need no privileges.
- `internal/vpn` — userspace TCP/IP stack on gVisor netstack over TUN: TCP forwarding, UDP relay, DNS-over-TCP through the tunnel, kill switch (SetBlocked), traffic counters.
- `internal/socks5` — local SOCKS5 server with a pluggable traffic pump.
- `internal/engine` — modes, socket protect routing, counters, status.
- `internal/discover` — relay directory: Ed25519 signatures, TTL, latency probing and automatic best-transport selection. The foundation of auto-discovery — [docs/RELAY_DISCOVERY.md](docs/RELAY_DISCOVERY.md).
- `cmd/qulogi` — client console, `cmd/qulogid` — server console.
- `mobile` — gomobile bindings: the SOCKS5 engine and the VPN engine (`ConfigureVPN`/`StartVPN(fd, mtu)`/`StopVPN`/`SetBlocked`), plus `Protector` and `LogSink` interfaces.
- `app` — Flutter client: VPN/Tunnel/DPI modes, camouflage settings, auto-start and kill switch, log screen.
- `app/android` — `QulogiVpnService` (foreground, specialUse), `BootReceiver` (auto-start, off by default), in-app kill switch.
- `ios` — NetworkExtension scaffold (experimental).

## Quick start

### Server

On any Linux VPS:

```bash
go install github.com/mel0k1/qulogi/cmd/qulogid@latest
qulogid -listen :443 -psk LONG_RANDOM_KEY
```

Open the chosen TCP port in the firewall. The server accepts both camouflaged and plain connections automatically — no extra setup. The PSK is the only entry guard, make it long and treat it like a password.

### Client (console)

```bash
go install github.com/mel0k1/qulogi/cmd/qulogi@latest
qulogi -server example.com:443 -psk THE_SAME_KEY -camo -fake-ch -sni vkvideo.ru
```

A SOCKS5 listener appears on `127.0.0.1:1080`. The `-camo`, `-fake-ch` and `-sni` flags enable whitelisted-domain camouflage; without them the tunnel uses the original wire format.

Without `-server` the client works in DPI mode: `qulogi -split 0 -multi`, where 0 picks the split point after SNI automatically and `-multi` adds extra splits.

### App

```bash
git clone https://github.com/mel0k1/Qulogi.git
cd Qulogi/app
flutter pub get
flutter run
```

On Android: pick the **VPN** mode, enter the server and key, press the button — the system asks for VPN permission. Settings cover camouflage (TLS envelope + SNI), auto-start (off by default) and the kill switch. For hard protection also enable "Always-on VPN" and "Block connections without VPN" in system settings.

On desktop the app launches the `qulogi` binary from PATH; VPN mode is Android-only — use SOCKS5 there.

## Building from source

Core:

```bash
go build ./cmd/qulogi ./cmd/qulogid
```

Android bindings for the app:

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
gomobile init
gomobile bind -target=android -androidapi 29 \
  -abi arm64-v8a,armeabi-v7a,x86_64 \
  -o app/android/app/libs/mobile.aar ./mobile
```

Ready-made binaries and APK are built by CI in the Actions tab.

## Security

- The key is derived from the PSK via HKDF-SHA256 with fresh salts on every connection; salts never repeat.
- Every frame is encrypted with AES-256-GCM under its own nonce, the frame counter is bound into the AAD — replay and tampering are rejected.
- A wrong PSK reveals nothing: the connection is silently closed on the first frame.
- Camouflage is an envelope, not protection: cryptography stays in the GCM layer, TLS headers only shape the traffic.
- Kill switch: after switching the VPN off the interface stays up and new flows are refused — no packet escapes the tunnel.
- Logging is off by default; `-v` shows connection events only, never traffic content.

## Limitations

- In VPN + tunnel egress only TCP is relayed; UDP (except DNS over TCP) is dropped and QUIC clients fall back to TCP automatically. In direct egress UDP passes as-is.
- SNI camouflage defeats SNI filtering; if the server IP itself is blocked, only another address/port or CDN fronting (on the roadmap) helps.
- ClientHello split tricks do not work on every ISP: DPI keeps evolving, pick a strategy that fits your network.

## Roadmap

- [x] Android: VpnService routing via gomobile (gVisor netstack in the core)
- [x] Transport through permitted services: tunnel masked as whitelisted-platform traffic (TLS envelope + SNI + fake ServerHello)
- [x] DPI desync in the spirit of zapret: splits, multi-split, standalone fake ClientHello
- [x] Auto-start (off by default) and kill switch in the app
- [ ] iOS via NetworkExtension — scaffold ready, needs an Xcode target and a developer account
- [ ] UDP flows over the tunnel (QUIC-like frames inside the GCM channel)
- [x] Transport auto-discovery, M1: Ed25519-signed relay directory, latency probing and automatic selection ([docs/RELAY_DISCOVERY.md](docs/RELAY_DISCOVERY.md))
- [x] Auto-discovery, M2: directory mirrors (HTTPS, DNS TXT, DoH), last-good-mirror cache, `qulogi://` links, QR import and QR sharing of relays, a "Relays" tab in the app, the operator tool `qulogicat`
- [x] Auto-discovery, M3: the `storage-webdav` transport — tunnel frames through a whitelisted cloud (Yandex Disk and compatible WebDAV): "device → cloud → internet" with no VPS of your own; the community relay catalog [mel0k1/qulogi-catalog](https://github.com/mel0k1/qulogi-catalog) with a key pinned in clients
- [x] SNI sniffing in the TUN stack: in VPN mode the split matches domains from the ClientHello, not just IPs
- [x] CDN fronting: the tunnel through a whitelisted CDN edge (TLS with an allowed SNI, Host-routed to the relay behind the same CDN)
- [x] Bot long-poll: tunnel frames via a whitelisted platform's official API (generic send/poll contract)
- [x] UDP over the tunnel: QUIC and other UDP ride the relay as framed datagrams
- [ ] Domain fronting via real CDNs of whitelisted platforms
- [x] Smart split: whitelisted domains and networks go directly, the tunnel carries only the rest; embedded starter whitelist + user rules (direct/proxy), per-flow routing in VPN mode

## Download

Prebuilt binaries live in [Releases](https://github.com/mel0k1/Qulogi/releases):

- **Android** — APK (SOCKS5 and VPN modes, relay auto-discovery, smart split, cloud transport);
- **Windows / Linux / macOS** — `qulogi` (client) and `qulogid` (relay).

Every `v*` tag is built by CI automatically: core binaries for amd64/arm64 and a release APK.

## Legal notice

This project exists to restore access to information. Use it in accordance with the laws of your country; the authors are not responsible for how the code is used.

## Mascot

The Qulogi mascot is a barn owl painted in ink. Owls hunt in the dark, hear what others cannot and fly silently — fitting talents for a whitelist bypasser.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/owl-ink-white.png">
    <img src="docs/assets/owl-ink.png" width="180" alt="Qulogi owl, ink painting">
  </picture>
</p>

## License

[GPL-3.0](LICENSE)
