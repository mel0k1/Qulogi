import 'dart:io';

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../services/relays.dart';
import '../state/engine_controller.dart';

/// Relays tab: community catalog auto-discovery (M2), the user's relay
/// list, import via qulogi:// links / QR codes and QR sharing.
class RelaysScreen extends StatefulWidget {
  const RelaysScreen({super.key, required this.controller});

  final EngineController controller;

  @override
  State<RelaysScreen> createState() => _RelaysScreenState();
}

class _RelaysScreenState extends State<RelaysScreen> {
  final RelaysStore _store = RelaysStore();
  List<RelayEntry> _relays = [];
  String _activeId = '';
  bool _loading = true;
  bool _searching = false;
  DiscoveryReport? _report;

  @override
  void initState() {
    super.initState();
    _reload();
    // Deep-link invites (qulogi://…) are applied here; the home screen
    // switches to this tab and calls controller.applyInvite(link).
    widget.controller.inviteHandler = _applyInvite;
  }

  @override
  void dispose() {
    widget.controller.inviteHandler = null;
    super.dispose();
  }

  Future<void> _reload() async {
    final relays = await _store.load();
    final active = await _store.activeId();
    if (!mounted) return;
    setState(() {
      _relays = relays;
      _activeId = active ?? '';
      _loading = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
      children: [
        _discoveryCard(),
        const SizedBox(height: 24),
        _myRelaysSection(),
        const SizedBox(height: 24),
        _addSection(),
        const SizedBox(height: 24),
        const Card(
          child: ListTile(
            leading: Icon(Icons.info_outline),
            title: Text('Что такое релей'),
            subtitle: Text(
                'Транзит, через который идёт трафик мимо белых списков. '
                'Публичные релеи находятся автопоиском, личные распространяются ссылками qulogi:// и QR-кодами.'),
          ),
        ),
      ],
    );
  }

  Widget _discoveryCard() {
    final report = _report;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.radar),
                const SizedBox(width: 12),
                Expanded(
                  child: Text('Автопоиск релеев',
                      style: Theme.of(context).textTheme.titleMedium),
                ),
              ],
            ),
            const SizedBox(height: 4),
            const Text(
              'Каталог сообщества ищется на зеркалах HTTPS и в DNS TXT; '
              'найденные релеи проверяются замером задержки.',
              style: TextStyle(fontSize: 12),
            ),
            const SizedBox(height: 12),
            FilledButton.tonalIcon(
              onPressed: _searching ? null : _runDiscovery,
              icon: _searching
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2))
                  : const Icon(Icons.travel_explore),
              label: Text(_searching ? 'Ищу…' : 'Найти релеи'),
            ),
            if (report != null) ...[
              const SizedBox(height: 12),
              if (report.error.isNotEmpty)
                Text('Не удалось: ${report.error}',
                    style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                        fontSize: 12))
              else ...[
                Text(
                  'источник: ${report.source}'
                  '${report.verified ? ', подпись ок' : ', без подписи'}'
                  '${report.fromCache ? ', из кэша' : ''}',
                  style: const TextStyle(fontSize: 11),
                ),
                const SizedBox(height: 8),
                for (final r in report.relays)
                  ListTile(
                    contentPadding: EdgeInsets.zero,
                    dense: true,
                    leading: const Icon(Icons.dns_outlined),
                    title: Text(r.relayId),
                    subtitle: Text('${r.type} · ${r.addr}'),
                    trailing: Text('${r.rttMs.round()} мс'),
                    onTap: () => _adoptDiscovered(r),
                  ),
              ],
            ],
          ],
        ),
      ),
    );
  }

  Future<void> _runDiscovery() async {
    setState(() => _searching = true);
    try {
      final params = await _store.fetchParams();
      final map = await widget.controller.bridge.fetchDirectory(params);
      if (!mounted) return;
      setState(() => _report = DiscoveryReport.fromJson(map));
    } catch (e) {
      if (!mounted) return;
      setState(() => _report = DiscoveryReport(error: '$e'));
    } finally {
      if (mounted) setState(() => _searching = false);
    }
  }

  Future<void> _adoptDiscovered(DiscoveredRelay r) async {
    String psk = '';
    if (r.type.startsWith('qulogi')) {
      psk = await _promptPsk(r.relayId);
      if (psk.isEmpty) return; // qulogi transports cannot work without a key
    }
    final entry = r.toEntry(psk: psk);
    await _saveAndSelect(entry);
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Релей ${entry.displayName} сохранён')),
      );
    }
  }

  Widget _myRelaysSection() {
    if (_loading) {
      return const Center(child: CircularProgressIndicator());
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('Мои релеи', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        if (_relays.isEmpty)
          const Text(
            'Пока пусто. Найдите релей автопоиском или импортируйте ссылку/QR от друга.',
            style: TextStyle(fontSize: 13),
          )
        else
          ..._relays.map(_relayTile),
      ],
    );
  }

  Widget _relayTile(RelayEntry r) {
    final active = r.id == _activeId;
    return Card(
      margin: const EdgeInsets.symmetric(vertical: 4),
      child: ListTile(
        leading: Icon(
          active ? Icons.radio_button_checked : Icons.radio_button_off,
          color: active ? Theme.of(context).colorScheme.primary : null,
        ),
        title: Text(r.displayName),
        subtitle: Text('${r.type} · ${r.addr}${r.sni.isNotEmpty ? ' · SNI ${r.sni}' : ''}'),
        onTap: () => _select(r),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            IconButton(
              tooltip: 'Показать QR',
              icon: const Icon(Icons.qr_code_2),
              onPressed: () => _showQr(r),
            ),
            IconButton(
              tooltip: 'Удалить',
              icon: const Icon(Icons.delete_outline),
              onPressed: () => _delete(r),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _select(RelayEntry r) async {
    await _store.setActive(r.id);
    final cfg = widget.controller;
    await cfg.update(
      server: r.addr,
      psk: r.psk,
      sni: r.sni.isNotEmpty ? r.sni : cfg.config.sni,
      camo: r.type == 'qulogi-tls' ? true : cfg.config.camo,
    );
    setState(() => _activeId = r.id);
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Активный релей: ${r.displayName}')),
      );
    }
  }

  Future<void> _saveAndSelect(RelayEntry entry) async {
    final relays = [
      ..._relays.where((e) => e.id != entry.id),
      entry,
    ];
    await _store.save(relays);
    await _select(entry);
    await _reload();
  }

  Future<void> _delete(RelayEntry r) async {
    final relays = _relays.where((e) => e.id != r.id).toList();
    await _store.save(relays);
    if (r.id == _activeId) {
      await _store.setActive(null);
      setState(() => _activeId = '');
    }
    await _reload();
  }

  Future<void> _showQr(RelayEntry r) async {
    final link = buildRelayInvite(r);
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('QR: ${r.displayName}'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(8),
              ),
              child: QrImageView(data: link, size: 220, backgroundColor: Colors.white),
            ),
            const SizedBox(height: 8),
            Text(link, style: const TextStyle(fontSize: 10)),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Закрыть'),
          ),
        ],
      ),
    );
  }

  Widget _addSection() => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Добавить релей', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              FilledButton.tonalIcon(
                onPressed: _importLinkDialog,
                icon: const Icon(Icons.link),
                label: const Text('Ссылка qulogi://'),
              ),
              if (Platform.isAndroid || Platform.isIOS)
                FilledButton.tonalIcon(
                  onPressed: _scanQr,
                  icon: const Icon(Icons.qr_code_scanner),
                  label: const Text('Сканировать QR'),
                ),
              FilledButton.tonalIcon(
                onPressed: _manualDialog,
                icon: const Icon(Icons.edit_outlined),
                label: const Text('Вручную'),
              ),
            ],
          ),
        ],
      );

  Future<void> _importLinkDialog() async {
    final controller = TextEditingController();
    final link = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Импорт ссылки'),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: const InputDecoration(
            labelText: 'qulogi://relay/… или qulogi://catalog/…',
            border: OutlineInputBorder(),
          ),
          onSubmitted: (v) => Navigator.pop(ctx, v),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Отмена')),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, controller.text),
            child: const Text('Импорт'),
          ),
        ],
      ),
    );
    if (link != null) await _applyInvite(link);
  }

  Future<void> _scanQr() async {
    final link = await Navigator.push<String>(
      context,
      MaterialPageRoute(builder: (_) => const ScannerScreen()),
    );
    if (link != null) await _applyInvite(link);
  }

  /// Applies a qulogi:// invite. Used by the import dialogs and by the
  /// deep-link flow when the app is opened from a link or QR.
  Future<String?> applyInvite(String link) => _applyInvite(link);

  Future<String?> _applyInvite(String link) async {
    final invite = parseInvite(link);
    if (invite == null) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Это не похоже на ссылку qulogi://')),
        );
      }
      return 'bad invite';
    }
    if (invite.isCatalog) {
      await _store.addCatalogUrl(invite.catalogUrl);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Каталог добавлен: ${invite.catalogUrl}')),
        );
      }
      return null;
    }
    final relay = invite.relay!;
    if (relay.type.startsWith('qulogi') && relay.psk.isEmpty) {
      final psk = await _promptPsk(relay.displayName);
      if (psk.isEmpty) return 'cancelled';
      await _saveAndSelect(relay.copyWith(psk: psk));
    } else {
      await _saveAndSelect(relay);
    }
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Релей ${relay.displayName} добавлен')),
      );
    }
    return null;
  }

  Future<void> _manualDialog() async {
    final name = TextEditingController();
    final addr = TextEditingController();
    final psk = TextEditingController();
    final sni = TextEditingController(text: 'vkvideo.ru');
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Ручной релей'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(controller: name, decoration: const InputDecoration(labelText: 'Имя')),
              const SizedBox(height: 8),
              TextField(controller: addr, decoration: const InputDecoration(labelText: 'Адрес host:port')),
              const SizedBox(height: 8),
              TextField(controller: psk, decoration: const InputDecoration(labelText: 'Ключ (PSK)')),
              const SizedBox(height: 8),
              TextField(controller: sni, decoration: const InputDecoration(labelText: 'SNI для камуфляжа')),
            ],
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Отмена')),
          FilledButton(
            onPressed: () =>
                addr.text.trim().isEmpty ? null : Navigator.pop(ctx, true),
            child: const Text('Сохранить'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    final entry = RelayEntry(
      id: name.text.trim().isEmpty ? 'manual-${addr.text.trim()}' : name.text.trim(),
      type: 'qulogi-tls',
      addr: addr.text.trim(),
      psk: psk.text.trim(),
      sni: sni.text.trim(),
      name: name.text.trim(),
    );
    await _saveAndSelect(entry);
  }

  Future<String> _promptPsk(String relayName) async {
    final controller = TextEditingController();
    final psk = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Ключ для $relayName'),
        content: TextField(
          controller: controller,
          autofocus: true,
          obscureText: true,
          decoration: const InputDecoration(labelText: 'PSK', border: OutlineInputBorder()),
          onSubmitted: (v) => Navigator.pop(ctx, v),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Отмена')),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, controller.text.trim()),
            child: const Text('ОК'),
          ),
        ],
      ),
    );
    return psk ?? '';
  }
}

/// Full-screen camera scanner (Android/iOS). Pops with the decoded string.
class ScannerScreen extends StatefulWidget {
  const ScannerScreen({super.key});

  @override
  State<ScannerScreen> createState() => _ScannerScreenState();
}

class _ScannerScreenState extends State<ScannerScreen> {
  bool _done = false;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Сканирование QR')),
      body: MobileScanner(
        onDetect: (capture) {
          if (_done) return;
          for (final barcode in capture.barcodes) {
            final value = barcode.rawValue;
            if (value != null && value.isNotEmpty) {
              _done = true;
              Navigator.of(context).pop(value);
              return;
            }
          }
        },
      ),
    );
  }
}
