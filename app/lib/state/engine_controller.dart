import 'dart:async';

import 'package:flutter/services.dart';

import '../services/engine_bridge.dart';
import '../services/settings_store.dart';

class EngineController extends ChangeNotifier {
  EngineController(this._bridge, this._store) {
    _logSub = _bridge.logs.listen((entry) {
      logs.add(entry);
      if (logs.length > 500) {
        logs.removeRange(0, logs.length - 500);
      }
      notifyListeners();
    });
    _store.load().then((config) {
      this.config = config;
      notifyListeners();
    }).catchError((_) => config);
  }

  final EngineBridge _bridge;
  final SettingsStore _store;
  StreamSubscription<String>? _logSub;
  Timer? _timer;

  EngineConfig config = EngineConfig();
  bool running = false;
  EngineStatus status = const EngineStatus(running: false);
  List<String> logs = [];
  String? error;

  Future<void> start() async {
    error = null;
    try {
      await _bridge.start(config);
      running = true;
      _timer ??= Timer.periodic(const Duration(seconds: 1), (_) => _refresh());
      await _refresh();
    } on MissingPluginException {
      error = 'Движок недоступен на этой платформе';
    } on PlatformException catch (e) {
      error = 'Движок вернул ошибку: ${e.message ?? e.code}';
    } catch (e) {
      error = 'Не удалось запустить: $e';
    }
    notifyListeners();
  }

  Future<void> stop() async {
    error = null;
    _timer?.cancel();
    _timer = null;
    try {
      await _bridge.stop();
    } catch (e) {
      error = 'Не удалось остановить: $e';
    }
    running = false;
    status = const EngineStatus(running: false);
    notifyListeners();
  }

  Future<void> setMode(EngineMode mode) async {
    if (running) {
      error = 'Остановите соединение, чтобы сменить режим';
      notifyListeners();
      return;
    }
    config.mode = mode;
    await _store.save(config);
    notifyListeners();
  }

  Future<void> update({
    String? server,
    String? psk,
    String? listen,
    int? split,
  }) async {
    if (server != null) config.server = server;
    if (psk != null) config.psk = psk;
    if (listen != null) config.listen = listen;
    if (split != null) config.split = split;
    await _store.save(config);
    notifyListeners();
  }

  void clearLogs() {
    logs.clear();
    notifyListeners();
  }

  Future<void> _refresh() async {
    try {
      status = await _bridge.status();
      if (!status.running && running) {
        running = false;
        _timer?.cancel();
        _timer = null;
      }
    } catch (_) {}
    notifyListeners();
  }

  @override
  void dispose() {
    _timer?.cancel();
    _logSub?.cancel();
    super.dispose();
  }
}
