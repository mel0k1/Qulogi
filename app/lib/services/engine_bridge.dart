import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';

enum EngineMode { dpi, tunnel, vpn }

class EngineConfig {
  EngineConfig({
    this.mode = EngineMode.dpi,
    this.server = '',
    this.psk = '',
    this.listen = '127.0.0.1:1080',
    this.split = 0,
    this.multiSplit = false,
    this.camo = false,
    this.sni = 'vkvideo.ru',
    this.fakeCh = true,
    this.mtu = 8500,
    this.autostart = false,
    this.killswitch = false,
    this.smartSplit = true,
    this.directDomains = '',
    this.proxyDomains = '',
  });

  EngineMode mode;
  String server;
  String psk;
  String listen;
  int split;
  bool multiSplit;
  bool camo;
  String sni;
  bool fakeCh;
  int mtu;
  bool autostart;
  bool killswitch;

  /// Smart split: whitelisted destinations bypass the relay.
  bool smartSplit;

  /// Extra direct rules (newline/comma separated), on top of the
  /// embedded whitelist.
  String directDomains;

  /// Rules forced through the tunnel even if whitelisted.
  String proxyDomains;

  /// Fields forwarded to the Go engine. autostart/killswitch are consumed
  /// by the Android layer only.
  Map<String, dynamic> toEngineJson() => {
        'mode': _modeName(mode),
        'server': server,
        'psk': psk,
        'listen': listen,
        'split': split,
        'multi_split': multiSplit,
        'camo': camo,
        'sni': sni,
        'fake_ch': fakeCh,
        'mtu': mtu,
        'smart_split': smartSplit,
        'direct': _splitLines(directDomains),
        'proxy': _splitLines(proxyDomains),
      };

  Map<String, dynamic> toJson() => {
        ...toEngineJson(),
        'autostart': autostart,
        'killswitch': killswitch,
      };

  factory EngineConfig.fromJson(Map<String, dynamic> json) => EngineConfig(
        mode: _modeFrom(json['mode'] as String?),
        server: json['server'] as String? ?? '',
        psk: json['psk'] as String? ?? '',
        listen: json['listen'] as String? ?? '127.0.0.1:1080',
        split: json['split'] as int? ?? 0,
        multiSplit: json['multi_split'] as bool? ?? false,
        camo: json['camo'] as bool? ?? false,
        sni: json['sni'] as String? ?? 'vkvideo.ru',
        fakeCh: json['fake_ch'] as bool? ?? true,
        mtu: json['mtu'] as int? ?? 8500,
        autostart: json['autostart'] as bool? ?? false,
        killswitch: json['killswitch'] as bool? ?? false,
        smartSplit: json['smart_split'] as bool? ?? true,
        directDomains: _joinLines(json['direct'] as List<dynamic>?),
        proxyDomains: _joinLines(json['proxy'] as List<dynamic>?),
      );

  static String _modeName(EngineMode m) =>
      m == EngineMode.tunnel ? 'tunnel' : (m == EngineMode.vpn ? 'vpn' : 'dpi');

  static List<String> _splitLines(String raw) => raw
      .split(RegExp(r'[\n,;]'))
      .map((s) => s.trim())
      .where((s) => s.isNotEmpty)
      .toList();

  static String _joinLines(List<dynamic>? items) =>
      items?.whereType<String>().join('\n') ?? '';

  static EngineMode _modeFrom(String? s) {
    switch (s) {
      case 'tunnel':
        return EngineMode.tunnel;
      case 'vpn':
        return EngineMode.vpn;
      default:
        return EngineMode.dpi;
    }
  }
}

class EngineStatus {
  const EngineStatus({
    required this.running,
    this.connections = 0,
    this.bytesUp = 0,
    this.bytesDown = 0,
    this.uptime = 0,
  });

  final bool running;
  final int connections;
  final int bytesUp;
  final int bytesDown;
  final int uptime;

  factory EngineStatus.fromJson(Map<String, dynamic> json) => EngineStatus(
        running: json['running'] as bool? ?? false,
        connections: json['connections'] as int? ?? 0,
        bytesUp: json['bytes_up'] as int? ?? 0,
        bytesDown: json['bytes_down'] as int? ?? 0,
        uptime: json['uptime'] as int? ?? 0,
      );
}

class VpnSnapshot {
  const VpnSnapshot({
    this.running = false,
    this.blocked = false,
    this.flows = 0,
    this.egress = '',
  });

  final bool running;
  final bool blocked;
  final int flows;
  final String egress;

  factory VpnSnapshot.fromJson(Map<String, dynamic> json) => VpnSnapshot(
        running: json['running'] as bool? ?? false,
        blocked: json['blocked'] as bool? ?? false,
        flows: json['flows'] as int? ?? 0,
        egress: json['egress'] as String? ?? '',
      );
}

enum VpnState { stopped, connected, blocked, error }

abstract class EngineBridge {
  Future<void> start(EngineConfig config);
  Future<void> stop();
  Future<EngineStatus> status();

  /// Starts the full-device VPN (Android VpnService). Throws
  /// [UnsupportedError] on platforms without a TUN implementation.
  Future<void> startVpn(EngineConfig config);

  /// Stops the VPN. With the kill switch enabled the platform keeps the
  /// TUN interface up in blocking mode instead of tearing it down.
  Future<void> stopVpn(EngineConfig config);
  Future<VpnSnapshot> vpnStatus();
  Future<List<String>> drainLogs();

  /// Races the relay catalog mirrors (HTTPS, DNS TXT, DoH), verifies the
  /// signature and probes live transports. Returns the DiscoveryReport
  /// JSON as a raw map.
  Future<Map<String, dynamic>> fetchDirectory(String paramsJson);

  /// qulogi:// invites delivered by the platform layer (deep links).
  Stream<String> get invites;

  Stream<String> get logs;
  Stream<VpnState> get vpnState;
}

EngineBridge createEngineBridge() {
  if (Platform.isAndroid) {
    return MobileEngineBridge();
  }
  return DesktopEngineBridge();
}

class MobileEngineBridge implements EngineBridge {
  static const _channel = MethodChannel('qulogi/engine');
  final _logs = StreamController<String>.broadcast();
  final _vpnState = StreamController<VpnState>.broadcast();
  final _invites = StreamController<String>.broadcast();

  MobileEngineBridge() {
    _channel.setMethodCallHandler((call) async {
      switch (call.method) {
        case 'log':
          _logs.add(call.arguments as String? ?? '');
        case 'vpnState':
          _vpnState.add(_stateFrom(call.arguments as String?));
        case 'invite':
          final link = call.arguments as String? ?? '';
          if (link.startsWith('qulogi://')) _invites.add(link);
      }
    });
  }

  static VpnState _stateFrom(String? s) {
    switch (s) {
      case 'connected':
        return VpnState.connected;
      case 'blocked':
        return VpnState.blocked;
      case 'error':
        return VpnState.error;
      default:
        return VpnState.stopped;
    }
  }

  @override
  Future<void> start(EngineConfig config) =>
      _channel.invokeMethod('start', jsonEncode(config.toEngineJson()));

  @override
  Future<void> stop() => _channel.invokeMethod('stop');

  @override
  Future<void> startVpn(EngineConfig config) =>
      _channel.invokeMethod('startVpn', jsonEncode(config.toJson()));

  @override
  Future<void> stopVpn(EngineConfig config) =>
      _channel.invokeMethod('stopVpn', jsonEncode(config.toJson()));

  @override
  Future<EngineStatus> status() async {
    final raw = await _channel.invokeMethod<String>('status');
    return EngineStatus.fromJson(
        jsonDecode(raw ?? '{}') as Map<String, dynamic>);
  }

  @override
  Future<VpnSnapshot> vpnStatus() async {
    final raw = await _channel.invokeMethod<String>('vpnStatus');
    return VpnSnapshot.fromJson(
        jsonDecode(raw ?? '{}') as Map<String, dynamic>);
  }

  @override
  Future<List<String>> drainLogs() async {
    final list = await _channel.invokeListMethod<dynamic>('drainLogs');
    return list?.cast<String>() ?? const [];
  }

  @override
  Future<Map<String, dynamic>> fetchDirectory(String paramsJson) async {
    final raw = await _channel.invokeMethod<String>('fetchDirectory', paramsJson);
    return jsonDecode(raw ?? '{}') as Map<String, dynamic>;
  }

  @override
  Stream<String> get invites => _invites.stream;

  @override
  Stream<String> get logs => _logs.stream;

  @override
  Stream<VpnState> get vpnState => _vpnState.stream;
}

class DesktopEngineBridge implements EngineBridge {
  Process? _process;
  final _logs = StreamController<String>.broadcast();
  final _vpnState = StreamController<VpnState>.broadcast();

  @override
  Future<void> start(EngineConfig config) async {
    _process?.kill();
    _process = null;
    final bin = Platform.isWindows ? 'qulogi.exe' : 'qulogi';
    final args = [
      '-mode',
      config.mode == EngineMode.tunnel ? 'tunnel' : 'dpi',
      '-listen',
      config.listen,
      '-split',
      '${config.split}',
      if (config.multiSplit) '-multi',
      if (config.mode == EngineMode.tunnel) ...[
        '-server',
        config.server,
        '-psk',
        config.psk,
        if (config.camo) ...[
          '-camo',
          '-sni',
          config.sni,
          if (config.fakeCh) '-fake-ch',
        ],
      ],
    ];
    final process = await Process.start(bin, args);
    _process = process;
    unawaited(process.exitCode.then((_) {
      if (_process == process) {
        _process = null;
      }
    }));
    process.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(_logs.add);
    process.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(_logs.add);
  }

  @override
  Future<void> stop() async {
    _process?.kill();
    _process = null;
  }

  @override
  Future<EngineStatus> status() async {
    return EngineStatus(running: _process != null);
  }

  @override
  Future<void> startVpn(EngineConfig config) async {
    throw UnsupportedError('VPN mode is available on Android only');
  }

  @override
  Future<void> stopVpn(EngineConfig config) async {
    throw UnsupportedError('VPN mode is available on Android only');
  }

  @override
  Future<VpnSnapshot> vpnStatus() async => const VpnSnapshot();

  @override
  Future<Map<String, dynamic>> fetchDirectory(String paramsJson) async {
    final bin = Platform.isWindows ? 'qulogi.exe' : 'qulogi';
    final result = await Process.run(bin, ['-discover', paramsJson]);
    if (result.exitCode != 0) {
      return {'error': (result.stderr as String).trim()};
    }
    // The engine prints exactly one JSON line.
    final line = (result.stdout as String)
        .split('\n')
        .lastWhere((l) => l.trim().isNotEmpty, orElse: () => '{}');
    try {
      return jsonDecode(line.trim()) as Map<String, dynamic>;
    } catch (_) {
      return {'error': 'непонятный ответ движка'};
    }
  }

  @override
  Future<List<String>> drainLogs() async => const [];

  @override
  Stream<String> get invites => const Stream.empty();

  @override
  Stream<String> get logs => _logs.stream;

  @override
  Stream<VpnState> get vpnState => _vpnState.stream;
}
