import 'dart:async';

import 'package:flutter_test/flutter_test.dart';

import 'package:qulogi/services/engine_bridge.dart';
import 'package:qulogi/services/settings_store.dart';
import 'package:qulogi/state/engine_controller.dart';

class _FakeBridge implements EngineBridge {
  int starts = 0;
  int stops = 0;
  final _logs = StreamController<String>.broadcast();

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
  Stream<String> get logs => _logs.stream;
}

class _MemoryStore extends SettingsStore {
  EngineConfig? lastSaved;

  @override
  Future<EngineConfig> load() async => EngineConfig();

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
}
