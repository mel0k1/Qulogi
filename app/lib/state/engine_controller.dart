import 'dart:async';

import 'package:flutter/foundation.dart';
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
    _vpnSub = _bridge.vpnState.listen(_onVpnState);
    _ready = _loadSettings();
    unawaited(_ready);
  }

  Future<void> _loadSettings() async {
    try {
      config = await _store.load();
    } catch (_) {
      // saved settings are unreadable - keep the defaults
    }
    if (!_disposed) notifyListeners();
  }

  final EngineBridge _bridge;
  final SettingsStore _store;
  StreamSubscription<String>? _logSub;
  StreamSubscription<VpnState>? _vpnSub;
  Timer? _timer;
  late final Future<void> _ready;
  bool _disposed = false;

  /// Platform bridge handle for feature screens (relay discovery).
  EngineBridge get bridge => _bridge;

  /// qulogi:// invites opened via deep links (Android) — "invite" calls
  /// from the platform side arrive here.
  Stream<String> get invites => _bridge.invites;

  EngineConfig config = EngineConfig();
  bool running = false;
  bool vpnBlocked = false;
  VpnState vpnState = VpnState.stopped;
  EngineStatus status = const EngineStatus(running: false);
  List<String> logs = [];
  String? error;

  bool get vpnAvailable => config.mode == EngineMode.vpn;

  /// Applies a qulogi:// invite without needing a BuildContext.
  /// Returns an error string or null on success; the UI layer shows
  /// snackbars and reloads its state.
  Future<String?> applyInvite(String link) async {
    return _inviteHandler?.call(link);
  }

  set inviteHandler(Future<String?> Function(String link)? handler) =>
      _inviteHandler = handler;
  Future<String?> Function(String link)? _inviteHandler;

  Future<void> start() async {
    await _ready; // initial load completes before any engine call
    error = null;
    vpnBlocked = false;
    try {
      if (config.mode == EngineMode.vpn) {
        await _bridge.startVpn(config);
        running = true;
        vpnState = VpnState.connected;
        _timer ??= Timer.periodic(const Duration(seconds: 1), (_) => _refresh());
        await _refresh();
      } else {
        await _bridge.start(config);
        running = true;
        _timer ??= Timer.periodic(const Duration(seconds: 1), (_) => _refresh());
        await _refresh();
      }
    } on UnsupportedError catch (e) {
      error = e.message;
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
      if (config.mode == EngineMode.vpn) {
        await _bridge.stopVpn(config);
        // With the kill switch enabled the platform reports "blocked"
        // through vpnState instead of a full teardown.
        running = false;
        vpnBlocked = false;
        vpnState = VpnState.stopped;
        status = const EngineStatus(running: false);
      } else {
        await _bridge.stop();
        running = false;
        status = const EngineStatus(running: false);
      }
    } on UnsupportedError catch (e) {
      error = e.message;
    } on PlatformException catch (e) {
      error = 'Не удалось остановить: ${e.message ?? e.code}';
    } catch (e) {
      error = 'Не удалось остановить: $e';
    }
    notifyListeners();
  }

  void _onVpnState(VpnState state) {
    vpnState = state;
    switch (state) {
      case VpnState.connected:
        running = true;
        vpnBlocked = false;
        _timer ??= Timer.periodic(const Duration(seconds: 1), (_) => _refresh());
      case VpnState.blocked:
        running = true;
        vpnBlocked = true;
      case VpnState.stopped:
        running = false;
        vpnBlocked = false;
        _timer?.cancel();
        _timer = null;
      case VpnState.error:
        running = false;
        vpnBlocked = false;
        _timer?.cancel();
        _timer = null;
        error = 'VPN остановлен с ошибкой — смотрите журнал';
    }
    notifyListeners();
  }

  Future<void> setMode(EngineMode mode) async {
    await _ready; // never let a pending load overwrite user changes
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
    bool? multiSplit,
    bool? camo,
    String? sni,
    bool? fakeCh,
    bool? autostart,
    bool? killswitch,
    bool? smartSplit,
    String? directDomains,
    String? proxyDomains,
  }) async {
    await _ready;
    if (server != null) config.server = server;
    if (psk != null) config.psk = psk;
    if (listen != null) config.listen = listen;
    if (split != null) config.split = split;
    if (multiSplit != null) config.multiSplit = multiSplit;
    if (camo != null) config.camo = camo;
    if (sni != null) config.sni = sni;
    if (fakeCh != null) config.fakeCh = fakeCh;
    if (autostart != null) config.autostart = autostart;
    if (killswitch != null) config.killswitch = killswitch;
    if (smartSplit != null) config.smartSplit = smartSplit;
    if (directDomains != null) config.directDomains = directDomains;
    if (proxyDomains != null) config.proxyDomains = proxyDomains;
    await _store.save(config);
    notifyListeners();
  }

  void clearLogs() {
    logs.clear();
    notifyListeners();
  }

  Future<void> _refresh() async {
    try {
      if (config.mode == EngineMode.vpn) {
        final vpn = await _bridge.vpnStatus();
        status = EngineStatus(
          running: vpn.running,
          connections: vpn.flows,
          bytesUp: status.bytesUp,
          bytesDown: status.bytesDown,
        );
        return;
      }
      status = await _bridge.status();
      if (!status.running && running && vpnState != VpnState.blocked) {
        running = false;
        _timer?.cancel();
        _timer = null;
      }
    } catch (_) {}
    notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    _timer?.cancel();
    _logSub?.cancel();
    _vpnSub?.cancel();
    super.dispose();
  }
}
