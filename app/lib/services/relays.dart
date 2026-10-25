import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

/// A relay the user can tunnel through. Mirrors the Go discover.Transport
/// plus the PSK needed by qulogi transports.
class RelayEntry {
  RelayEntry({
    required this.id,
    required this.type,
    required this.addr,
    this.sni = '',
    this.psk = '',
    this.name = '',
  });

  final String id;
  final String type; // qulogi-tls, qulogi-tcp, ...
  final String addr; // host:port
  final String sni; // camouflage SNI for qulogi-tls
  final String psk;
  final String name;

  String get displayName => name.isNotEmpty ? name : id;

  Map<String, dynamic> toJson() => {
        'id': id,
        'type': type,
        'addr': addr,
        if (sni.isNotEmpty) 'sni': sni,
        if (psk.isNotEmpty) 'psk': psk,
        if (name.isNotEmpty) 'name': name,
      };

  factory RelayEntry.fromJson(Map<String, dynamic> json) => RelayEntry(
        id: json['id'] as String? ?? '',
        type: json['type'] as String? ?? 'qulogi-tls',
        addr: json['addr'] as String? ?? '',
        sni: json['sni'] as String? ?? '',
        psk: json['psk'] as String? ?? '',
        name: json['name'] as String? ?? '',
      );

  RelayEntry copyWith({String? name, String? psk}) => RelayEntry(
        id: id,
        type: type,
        addr: addr,
        sni: sni,
        psk: psk ?? this.psk,
        name: name ?? this.name,
      );

  @override
  bool operator ==(Object other) =>
      other is RelayEntry && other.id == id && other.addr == addr;

  @override
  int get hashCode => Object.hash(id, addr);
}

/// A parsed qulogi:// invite: a single relay or a catalog subscription.
class Invite {
  const Invite.relay(this.relay, {this.catalogUrl = ''});
  const Invite.catalog(this.catalogUrl, {this.relay});

  final RelayEntry? relay;
  final String catalogUrl;
  bool get isCatalog => relay == null;
}

/// Parses a qulogi://relay/... or qulogi://catalog/?... link.
/// Returns null for anything that is not a well-formed invite.
Invite? parseInvite(String raw) {
  final link = raw.trim();
  if (!link.startsWith('qulogi://')) return null;
  final uri = Uri.tryParse(link);
  if (uri == null) return null;
  final kind = uri.host.toLowerCase();
  if (kind == 'relay') {
    final q = uri.queryParameters;
    final type = q['type'] ?? '';
    final addr = q['addr'] ?? '';
    if (type.isEmpty || addr.isEmpty) return null;
    final id = uri.path.replaceAll('/', '');
    return Invite.relay(RelayEntry(
      id: id.isEmpty ? addr : id,
      type: type,
      addr: addr,
      sni: q['sni'] ?? '',
      psk: q['psk'] ?? '',
      name: q['name'] ?? '',
    ));
  }
  if (kind == 'catalog' || kind == 'dir') {
    final q = uri.queryParameters;
    final url = q['url'] ?? q['u'] ?? '';
    if (!url.startsWith('http://') && !url.startsWith('https://')) return null;
    return Invite.catalog(url);
  }
  return null;
}

/// Builds a shareable invite link for the relay (fits a QR code).
String buildRelayInvite(RelayEntry r) {
  final q = <String, String>{
    'type': r.type,
    'addr': r.addr,
    if (r.sni.isNotEmpty) 'sni': r.sni,
    if (r.psk.isNotEmpty) 'psk': r.psk,
    if (r.name.isNotEmpty) 'name': r.name,
  };
  return Uri(
    scheme: 'qulogi',
    host: 'relay',
    path: '/${r.id}',
    queryParameters: q,
  ).toString();
}

/// A catalog probe result as reported by the Go side (mobile.FetchDirectory).
class DiscoveredRelay {
  const DiscoveredRelay({
    required this.relayId,
    required this.type,
    required this.addr,
    required this.rttMs,
    this.sni = '',
  });

  final String relayId;
  final String type;
  final String addr;
  final String sni;
  final double rttMs;

  factory DiscoveredRelay.fromJson(Map<String, dynamic> json) =>
      DiscoveredRelay(
        relayId: json['relay_id'] as String? ?? '',
        type: json['type'] as String? ?? '',
        addr: json['addr'] as String? ?? '',
        sni: json['sni'] as String? ?? '',
        rttMs: (json['rtt_ms'] as num?)?.toDouble() ?? 0,
      );

  RelayEntry toEntry({String psk = ''}) => RelayEntry(
        id: relayId,
        type: type,
        addr: addr,
        sni: sni,
        psk: psk,
        name: relayId,
      );
}

/// Discovery report returned by the engine bridge.
class DiscoveryReport {
  const DiscoveryReport({
    this.relays = const [],
    this.source = '',
    this.verified = false,
    this.fromCache = false,
    this.error = '',
  });

  final List<DiscoveredRelay> relays;
  final String source;
  final bool verified;
  final bool fromCache;
  final String error;

  factory DiscoveryReport.fromJson(Map<String, dynamic> json) {
    final err = json['error'] as String? ?? '';
    final probes = (json['probes'] as List<dynamic>? ?? [])
        .whereType<Map<String, dynamic>>()
        .map(DiscoveredRelay.fromJson)
        .toList();
    return DiscoveryReport(
      relays: err.isEmpty ? probes : const [],
      source: json['source'] as String? ?? '',
      verified: json['verified'] as bool? ?? false,
      fromCache: json['from_cache'] as bool? ?? false,
      error: err,
    );
  }
}

/// Persists the user's relay list, the active relay and catalog
/// subscription URLs in SharedPreferences.
class RelaysStore {
  static const _relaysKey = 'relays';
  static const _activeKey = 'active_relay';
  static const _catalogKey = 'catalog_urls';

  Future<List<RelayEntry>> load() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_relaysKey);
    if (raw == null) return [];
    try {
      final list = jsonDecode(raw) as List<dynamic>;
      return list
          .whereType<Map<String, dynamic>>()
          .map(RelayEntry.fromJson)
          .toList();
    } catch (_) {
      return [];
    }
  }

  Future<void> save(List<RelayEntry> relays) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(
      _relaysKey,
      jsonEncode(relays.map((r) => r.toJson()).toList()),
    );
  }

  Future<String?> activeId() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_activeKey);
  }

  Future<void> setActive(String? id) async {
    final prefs = await SharedPreferences.getInstance();
    if (id == null || id.isEmpty) {
      await prefs.remove(_activeKey);
    } else {
      await prefs.setString(_activeKey, id);
    }
  }

  Future<List<String>> catalogUrls() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getStringList(_catalogKey) ?? const [];
  }

  Future<void> addCatalogUrl(String url) async {
    final prefs = await SharedPreferences.getInstance();
    final urls = await catalogUrls();
    if (!urls.contains(url)) {
      await prefs.setStringList(_catalogKey, [...urls, url]);
    }
  }

  /// Fetch parameters for the engine: user catalog URLs ride on top of the
  /// built-in mirrors.
  Future<String> fetchParams() async {
    final urls = await catalogUrls();
    final sources = urls
        .map((u) => {'type': 'https', 'url': u})
        .cast<Map<String, dynamic>>()
        .toList();
    return jsonEncode({'sources': sources, 'probe': 6});
  }
}
