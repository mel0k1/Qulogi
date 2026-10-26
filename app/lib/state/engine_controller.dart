import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../services/engine_bridge.dart';
import '../services/relays.dart';
import '../services/settings_store.dart';

/// Stages of the one-tap auto connection (catalog → probes → best
/// transport → engine start).
enum AutoConnectState { idle, probing, connecting }

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

  /// One-tap auto connection state and the chosen transport description.
  AutoConnectState autoState = AutoConnectState.idle;
  String autoInfo = '';

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

  /// One-tap auto connection: race the catalog mirrors, probe every
  /// transport (turn-relay gets a real Allocate round trip), take the
  /// best candidate, wire it into the config and start the engine.
  Future<void> autoConnect() async {
    await _ready;
    if (running || autoState != AutoConnectState.idle) return;
    error = null;
    autoInfo = '';
    autoState = AutoConnectState.probing;
    notifyListeners();
    try {
      final params = await RelaysStore().fetchParams();
      final map = await _bridge.fetchDirectory(params);
      final report = DiscoveryReport.fromJson(map);
      if (report.error.isNotEmpty) {
        throw Exception(report.error);
      }
      if (report.relays.isEmpty) {
        throw Exception('в каталоге нет доступных релеев');
      }
      final best = report.relays.first;
      _applyTransport(best);
      // Auto-failover chain: the remaining live transports become the
      // reserves in probe order.
      final reserves = <Map<String, dynamic>>[];
      for (final r in report.relays.skip(1)) {
        final spec = _fallbackSpec(r);
        if (spec != null) reserves.add(spec);
      }
      config.fallbacks = reserves;
      autoState = AutoConnectState.connecting;
      notifyListeners();

      await start();
      if (error != null) {
        throw Exception(error!);
      }
      autoInfo = '${best.relayId} · ${best.type} · ${best.rttMs.round()} мс'
          + (reserves.isEmpty ? '' : ' · резервы: ${reserves.length}');
    } catch (e) {
      error = 'Автоподключение не удалось: ${_cleanError(e)}';
      autoState = AutoConnectState.idle;
      notifyListeners();
      return;
    }
    autoState = AutoConnectState.idle;
    notifyListeners();
  }

  /// Maps one discovered transport to a failover reserve spec; returns
  /// null when the transport needs credentials the user does not have.
  Map<String, dynamic>? _fallbackSpec(DiscoveredRelay r) {
    switch (r.type) {
      case 'qulogi-tls':
      case 'qulogi-tcp':
        if (config.psk.isEmpty) return null;
        return {'kind': 'tcp', 'server': r.addr};
      case 'turn-relay':
        if (config.psk.isEmpty || r.host.isEmpty) return null;
        return {'kind': 'turn', 'server': r.addr, 'host': r.host};
      case 'storage-webdav':
        return {'kind': 'dav', 'url': r.addr};
      case 'bot-longpoll':
        if (config.botlpToken.isEmpty) return null;
        return {
          'kind': 'botlp',
          'url': r.addr,
          'room': config.botlpRoom.isEmpty ? 'qulogi' : config.botlpRoom,
          if (config.botlpKind.isNotEmpty) 'platform': config.botlpKind,
          if (config.botlpChat.isNotEmpty) 'chat': config.botlpChat,
        };
      case 'cdn-front':
        if (r.host.isEmpty) return null;
        return {
          'kind': 'cdn',
          'server': r.addr,
          'host': r.host,
          if (r.sni.isNotEmpty) 'sni': r.sni,
          if (r.ws) 'ws': true,
        };
      default:
        return null;
    }
  }

  /// Wires one discovered transport into the config, clearing every other
  /// transport choice (the engine picks by its own priority otherwise).
  void _applyTransport(DiscoveredRelay r) {
    final psk = config.psk;
    switch (r.type) {
      case 'qulogi-tls':
      case 'qulogi-tcp':
        if (psk.isEmpty) {
          throw Exception(
              'для релея ${r.relayId} нужен ключ — импортируйте qulogi://-ссылку');
        }
        config.server = r.addr;
        config.camo = r.type == 'qulogi-tls';
        if (r.sni.isNotEmpty) config.sni = r.sni;
      case 'turn-relay':
        if (psk.isEmpty || r.host.isEmpty) {
          throw Exception(
              'для релея ${r.relayId} нужен ключ и адрес релея в каталоге');
        }
        config.server = r.host;
        config.turnServer = r.addr;
        config.turnUser = '';
        config.turnPass = '';
      case 'storage-webdav':
        config.davUrl = r.addr;
      case 'bot-longpoll':
        if (config.botlpToken.isEmpty) {
          throw Exception(
              'транспорт ${r.relayId} требует токен платформы в настройках');
        }
        config.botlpUrl = r.addr;
      case 'cdn-front':
        config.cdnEdge = r.addr;
        config.cdnHost = r.host;
        if (r.sni.isNotEmpty) config.cdnSni = r.sni;
      default:
        throw Exception('неизвестный тип транспорта: ${r.type}');
    }
    // Only one transport class can be active at a time; qulogi-tls/tcp and
    // turn-relay keep the relay address in server, the rest carry their
    // own endpoints.
    if (r.type == 'qulogi-tls' || r.type == 'qulogi-tcp') {
      config.server = r.addr;
    } else if (r.type == 'turn-relay') {
      config.server = r.host;
    } else {
      config.server = '';
    }
    if (r.type != 'turn-relay') config.turnServer = '';
    if (r.type != 'storage-webdav') config.davUrl = '';
    if (r.type != 'bot-longpoll') config.botlpUrl = '';
    if (r.type != 'cdn-front') config.cdnEdge = '';
    config.cdnWs = r.type == 'cdn-front' && r.ws;
    _store.save(config);
  }

  static String _cleanError(Object e) {
    final s = e.toString();
    if (s.startsWith('Exception: ')) return s.substring('Exception: '.length);
    if (s.startsWith('Exception(')) {
      return s.substring('Exception('.length).replaceFirst(RegExp(r'\)$'), '');
    }
    return s;
  }

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
    String? davUrl,
    String? davUser,
    String? davPass,
    String? davMailbox,
    String? cdnEdge,
    String? cdnSni,
    String? cdnHost,
    bool? cdnWs,
    List<Map<String, dynamic>>? fallbacks,
    bool? noFailover,
    String? botlpUrl,
    String? botlpToken,
    String? botlpRoom,
    String? botlpKind,
    String? botlpChat,
    String? turnServer,
    String? turnUser,
    String? turnPass,
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
    if (davUrl != null) config.davUrl = davUrl;
    if (davUser != null) config.davUser = davUser;
    if (davPass != null) config.davPass = davPass;
    if (davMailbox != null) config.davMailbox = davMailbox;
    if (cdnEdge != null) config.cdnEdge = cdnEdge;
    if (cdnSni != null) config.cdnSni = cdnSni;
    if (cdnHost != null) config.cdnHost = cdnHost;
    if (cdnWs != null) config.cdnWs = cdnWs;
    if (fallbacks != null) config.fallbacks = fallbacks;
    if (noFailover != null) config.noFailover = noFailover;
    if (botlpUrl != null) config.botlpUrl = botlpUrl;
    if (botlpToken != null) config.botlpToken = botlpToken;
    if (botlpRoom != null) config.botlpRoom = botlpRoom;
    if (botlpKind != null) config.botlpKind = botlpKind;
    if (botlpChat != null) config.botlpChat = botlpChat;
    if (turnServer != null) config.turnServer = turnServer;
    if (turnUser != null) config.turnUser = turnUser;
    if (turnPass != null) config.turnPass = turnPass;
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
