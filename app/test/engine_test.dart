import 'dart:async';

import 'package:flutter_test/flutter_test.dart';

import 'package:qulogi/services/engine_bridge.dart';
import 'package:qulogi/services/settings_store.dart';
import 'package:qulogi/state/engine_controller.dart';

class _FakeBridge implements EngineBridge {
  int starts = 0;
  int stops = 0;
  int vpnStarts = 0;
  final _logs = StreamController<String>.broadcast();
  final _vpnState = StreamController<VpnState>.broadcast();

  @override
  Future<void> start(EngineConfig config) async {
    starts++;
  }

  @override
  Future<void> stop() async {
    stops++;
  }

  @override
  Future<EngineStatus> status() async {
    return EngineStatus(running: starts > stops, connections: 1);
  }

  @override
  Future<void> startVpn(EngineConfig config) async {
    vpnStarts++;
    _vpnState.add(VpnState.connected);
  }

  @override
  Future<void> stopVpn(EngineConfig config) async {
    _vpnState.add(VpnState.stopped);
  }

  @override
  Future<VpnSnapshot> vpnStatus() async =>
      const VpnSnapshot(running: true, flows: 3, egress: 'tunnel');

  @override
  Future<List<String>> drainLogs() async => const [];

  @override
  Stream<String> get logs => _logs.stream;

  @override
  Stream<VpnState> get vpnState => _vpnState.stream;
}

class _MemoryStore extends SettingsStore {
  EngineConfig? lastSaved;

  @override
  Future<EngineConfig> load() async => lastSaved ?? EngineConfig();

  @override
  Future<void> save(EngineConfig config) async {
    lastSaved = config;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('start and stop update state', () async {
    final bridge = _FakeBridge();
    final controller = EngineController(bridge, _MemoryStore());
    await controller.start();
    expect(controller.running, isTrue);
    expect(controller.error, isNull);
    await controller.stop();
    expect(controller.running, isFalse);
    expect(bridge.starts, 1);
    expect(bridge.stops, 1);
    controller.dispose();
  });

  test('mode switch persists config', () async {
    final store = _MemoryStore();
    final controller = EngineController(_FakeBridge(), store);
    await controller.setMode(EngineMode.tunnel);
    expect(controller.config.mode, EngineMode.tunnel);
    expect(store.lastSaved?.mode, EngineMode.tunnel);
    controller.dispose();
  });

  test('mode switch blocked while running', () async {
    final controller = EngineController(_FakeBridge(), _MemoryStore());
    await controller.start();
    await controller.setMode(EngineMode.tunnel);
    expect(controller.config.mode, EngineMode.dpi);
    expect(controller.error, isNotNull);
    await controller.stop();
    controller.dispose();
  });

  test('vpn start routes through startVpn and tracks state', () async {
    final bridge = _FakeBridge();
    final controller = EngineController(bridge, _MemoryStore());
    await controller.setMode(EngineMode.vpn);
    await controller.start();
    expect(bridge.vpnStarts, 1);
    expect(controller.running, isTrue);
    await controller.stop();
    expect(controller.running, isFalse);
    controller.dispose();
  });

  test('config json round trip keeps new fields', () {
    final cfg = EngineConfig(
      mode: EngineMode.vpn,
      server: 'vpn.example.org:443',
      psk: 'secret',
      camo: true,
      sni: 'rutube.ru',
      fakeCh: true,
      multiSplit: true,
      autostart: true,
      killswitch: true,
    );
    final restored = EngineConfig.fromJson(cfg.toJson());
    expect(restored.mode, EngineMode.vpn);
    expect(restored.server, 'vpn.example.org:443');
    expect(restored.camo, isTrue);
    expect(restored.sni, 'rutube.ru');
    expect(restored.fakeCh, isTrue);
    expect(restored.multiSplit, isTrue);
    expect(restored.autostart, isTrue);
    expect(restored.killswitch, isTrue);
    // Engine payload carries the Go json tags but not the Android-only keys.
    final engineJson = cfg.toEngineJson();
    expect(engineJson.containsKey('autostart'), isFalse);
    expect(engineJson['multi_split'], isTrue);
    expect(engineJson['fake_ch'], isTrue);
  });
}
