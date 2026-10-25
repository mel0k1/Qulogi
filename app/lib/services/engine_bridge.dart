import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';

enum EngineMode { tunnel, dpi }

class EngineConfig {
  EngineConfig({
    this.mode = EngineMode.dpi,
    this.server = '',
    this.psk = '',
    this.listen = '127.0.0.1:1080',
    this.split = 0,
  });

  EngineMode mode;
  String server;
  String psk;
  String listen;
  int split;

  Map<String, dynamic> toJson() => {
        'mode': mode == EngineMode.tunnel ? 'tunnel' : 'dpi',
        'server': server,
        'psk': psk,
        'listen': listen,
        'split': split,
      };

  factory EngineConfig.fromJson(Map<String, dynamic> json) => EngineConfig(
        mode: json['mode'] == 'tunnel' ? EngineMode.tunnel : EngineMode.dpi,
        server: json['server'] as String? ?? '',
        psk: json['psk'] as String? ?? '',
        listen: json['listen'] as String? ?? '127.0.0.1:1080',
        split: json['split'] as int? ?? 0,
      );
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

abstract class EngineBridge {
  Future<void> start(EngineConfig config);
  Future<void> stop();
  Future<EngineStatus> status();
  Stream<String> get logs;
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

  MobileEngineBridge() {
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'log') {
        _logs.add(call.arguments as String? ?? '');
      }
    });
  }

  @override
  Future<void> start(EngineConfig config) =>
      _channel.invokeMethod('start', jsonEncode(config.toJson()));

  @override
  Future<void> stop() => _channel.invokeMethod('stop');

  @override
  Future<EngineStatus> status() async {
    final raw = await _channel.invokeMethod<String>('status');
    return EngineStatus.fromJson(
        jsonDecode(raw ?? '{}') as Map<String, dynamic>);
  }

  @override
  Stream<String> get logs => _logs.stream;
}

class DesktopEngineBridge implements EngineBridge {
  Process? _process;
  final _logs = StreamController<String>.broadcast();

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
      if (config.mode == EngineMode.tunnel) ...[
        '-server',
        config.server,
        '-psk',
        config.psk,
      ] else ...[
        '-split',
        '${config.split}',
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
  Stream<String> get logs => _logs.stream;
}
