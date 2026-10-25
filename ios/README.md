# Qulogi для iOS — статус и план (NetworkExtension)

Статус: **экспериментальный каркас**. Файл `PacketTunnelProvider.swift` —
заготовка туннельного провайдера; CI его пока не собирает.

## Что уже готово в ядре

Весь сетевой стек работает в Go (`internal/vpn`, gVisor netstack) и не
зависит от платформы — на iOS он собирается той же командой, что и для
Android:

```bash
gomobile bind -target=ios -o Qulogi.xcframework ./mobile
```

API биндингов идентично Android: `Mobile.configureVPN`,
`Mobile.startVPN`, `Mobile.stopVPN`, `Mobile.setBlocked`,
`Mobile.vpnStatus`.

## Чек-лист интеграции

1. `flutter create . --platforms ios` — сгенерировать Runner-проект.
2. Добавить таргет **Packet Tunnel Provider** (Network Extension) в Xcode,
   положить `PacketTunnelProvider.swift` из этого каталога.
3. Entitlements:
   - Runner: `com.apple.developer.networking.networkextension` =
     `packet-tunnel-provider`;
   - App Groups для обмена конфигом между приложением и расширением.
4. Сконструировать `NETunnelProviderManager` в приложении и передавать
   конфиг (server/psk/sni/camo) через `providerConfiguration`.
5. Мост `NEPacketTunnelFlow → fd`: читать пакеты из `packetFlow`
   и передавать в Go (тот же подход, что в libbox/sing-box для iOS).
6. Подпись иcapabilities требуют платной учётной записи Apple Developer.

## Ограничения

- Kill switch на iOS реализуется системно: в профиле VPN включите
  «Disconnect on demand» / `DisconnectOnDemand`-правила.
- `gomobile bind -target=ios` требует macOS с Xcode.
