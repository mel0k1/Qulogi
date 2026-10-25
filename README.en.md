# Qulogi

[Русский](README.md) | [English](README.en.md)

Qulogi is a cross-platform tool for keeping the internet open under active traffic filtering. Two bypass methods in one core: an obfuscated tunnel to your own server and a local TLS-level DPI bypass. The core is written in Go, the interface is Flutter with Material 3 Expressive. No third-party servers in the middle: traffic goes only through what you configured.

Status: the core and CLI clients are fully working, the desktop path is covered. Android integration via VpnService is the next step (see the roadmap).

![CI](https://github.com/mel0k1/Qulogi/actions/workflows/build.yml/badge.svg)
![License](https://img.shields.io/badge/license-GPL--3.0-blue)

## How it works

The app or the CLI client starts a local SOCKS5 proxy on your device and routes traffic one of two ways:

- **Tunnel.** All traffic goes through an encrypted tunnel to your server and reaches the internet from there. To an inspector it is an unreadable stream of random bytes between you and your own server.
- **DPI.** Traffic goes directly, but the TLS ClientHello is split into segments so the inspector cannot see the host name in the first packet. No server needed.

```text
app (Flutter)
      |
      v
local SOCKS5 -- qulogi (Go)
      |
      +-- DPI mode ----> split ClientHello after SNI ----> straight to the internet
      |
      +-- tunnel mode -> AES-256-GCM over TCP ----------> qulogid (VPS) ---> the internet
```

## What is inside

- `internal/tunnel` — tunnel protocol: handshake with fresh salts, HKDF-SHA256, AES-256-GCM, sequenced frames. A wrong key is dropped on the first frame.
- `internal/socks5` — local SOCKS5 server with a pluggable traffic pump.
- `internal/dpi` — ClientHello parsing and a split after SNI, or manual: 1, 8 or 32 bytes.
- `internal/engine` — modes combined, traffic counters, status.
- `cmd/qulogi` — client console, `cmd/qulogid` — server console.
- `mobile` — gomobile bindings for the Android app.
- `app` — Flutter client: dynamic color, connection screen, settings, log.

## Quick start

### Server

On any Linux VPS:

```bash
go install github.com/mel0k1/qulogi/cmd/qulogid@latest
qulogid -listen :443 -psk LONG_RANDOM_KEY
```

Open the chosen TCP port in the firewall. The PSK is the only entry guard, make it long and treat it like a password.

### Client

```bash
go install github.com/mel0k1/qulogi/cmd/qulogi@latest
qulogi -server example.com:443 -psk THE_SAME_KEY
```

A SOCKS5 listener appears on `127.0.0.1:1080`. Point your browser or any app there, and traffic goes through the server.

Without `-server` the client works in DPI mode: `qulogi -split 0`, where 0 picks the split point after SNI automatically.

### App

```bash
git clone https://github.com/mel0k1/Qulogi.git
cd Qulogi/app
flutter create . --project-name qulogi --platforms android,windows
flutter pub get
flutter run
```

On the Settings tab enter the server address and the key, then press the button on the Connection screen. On desktop the app launches the `qulogi` binary from PATH.

## Building from source

```bash
go build ./cmd/qulogi ./cmd/qulogid
```

Ready-made binaries and APK are built by CI in the Actions tab.

## Security

- The key is derived from the PSK via HKDF-SHA256 with fresh salts on every connection; salts never repeat.
- Every frame is encrypted with AES-256-GCM under its own nonce, the frame counter is bound into the AAD — replay and tampering are rejected.
- A wrong PSK reveals nothing: the connection is silently closed on the first frame.
- Logging is off by default; `-v` shows connection events only, never traffic content.

## Roadmap

- [ ] Android: VpnService routing via gomobile — bindings are ready
- [ ] Transport through permitted services: masking the tunnel as whitelisted platform traffic
- [ ] Fake packets and DPI desync in the spirit of zapret
- [ ] Auto-start and kill switch in the app
- [ ] iOS via NetworkExtension

## Legal notice

This project exists to restore access to information. Use it in accordance with the laws of your country; the authors are not responsible for how the code is used.

## License

[GPL-3.0](LICENSE)
