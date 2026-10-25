import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

import 'engine_bridge.dart';

class SettingsStore {
  static const _key = 'engine_config';

  Future<EngineConfig> load() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_key);
    if (raw == null) {
      return EngineConfig();
    }
    try {
      return EngineConfig.fromJson(jsonDecode(raw) as Map<String, dynamic>);
    } catch (_) {
      return EngineConfig();
    }
  }

  Future<void> save(EngineConfig config) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_key, jsonEncode(config.toJson()));
  }
}
