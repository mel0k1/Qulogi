import 'dart:io';

import 'package:flutter/material.dart';

import '../services/engine_bridge.dart';
import '../state/engine_controller.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key, required this.controller});

  final EngineController controller;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late final TextEditingController _server;
  late final TextEditingController _psk;
  late final TextEditingController _listen;
  late final TextEditingController _sni;
  bool _obscure = true;
  int _split = 0;
  bool _multi = false;
  bool _camo = false;
  bool _fakeCh = true;
  bool _autostart = false;
  bool _killswitch = false;

  static const _sniPresets = ['vkvideo.ru', 'rutube.ru', 'ok.ru', 'dzen.ru'];

  @override
  void initState() {
    super.initState();
    final cfg = widget.controller.config;
    _server = TextEditingController(text: cfg.server);
    _psk = TextEditingController(text: cfg.psk);
    _listen = TextEditingController(text: cfg.listen);
    _sni = TextEditingController(text: cfg.sni);
    _split = cfg.split;
    _multi = cfg.multiSplit;
    _camo = cfg.camo;
    _fakeCh = cfg.fakeCh;
    _autostart = cfg.autostart;
    _killswitch = cfg.killswitch;
  }

  @override
  void dispose() {
    _server.dispose();
    _psk.dispose();
    _listen.dispose();
    _sni.dispose();
    super.dispose();
  }

  void _save() {
    widget.controller.update(
      server: _server.text.trim(),
      psk: _psk.text,
      listen: _listen.text.trim(),
      split: _split,
      multiSplit: _multi,
      camo: _camo,
      sni: _sni.text.trim(),
      fakeCh: _fakeCh,
      autostart: _autostart,
      killswitch: _killswitch,
    );
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Настройки сохранены')),
    );
  }

  @override
  Widget build(BuildContext context) {
    final mode = widget.controller.config.mode;
    final usesServer = mode != EngineMode.dpi;
    return ListView(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
      children: [
        Text('Режим работы', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 12),
        SegmentedButton<EngineMode>(
          segments: const [
            ButtonSegment(value: EngineMode.dpi, label: Text('DPI')),
            ButtonSegment(
                value: EngineMode.tunnel, label: Text('Туннель')),
            ButtonSegment(value: EngineMode.vpn, label: Text('VPN')),
          ],
          selected: {mode},
          onSelectionChanged: (s) {
            widget.controller.setMode(s.first).then((_) => setState(() {}));
          },
        ),
        const SizedBox(height: 8),
        Text(
          mode == EngineMode.dpi
              ? 'Локальный SOCKS5-прокси с обходом DPI (трафик только тех приложений, которые настроены на прокси).'
              : mode == EngineMode.tunnel
                  ? 'Локальный SOCKS5-прокси через шифрованный туннель к вашему VPS.'
                  : 'Полнотуннельный VPN: весь трафик устройства через Android VpnService.',
          style: Theme.of(context).textTheme.bodySmall,
        ),
        const SizedBox(height: 24),
        if (usesServer) ..._serverSection(),
        if (mode == EngineMode.dpi) ..._proxySection(),
        if (mode == EngineMode.dpi) ..._dpiSection(),
        if (Platform.isAndroid) ..._androidSection(),
        const SizedBox(height: 16),
        FilledButton.icon(
          onPressed: _save,
          icon: const Icon(Icons.save_outlined),
          label: const Text('Сохранить'),
        ),
        const SizedBox(height: 24),
        Card(
          child: ListTile(
            leading: const Icon(Icons.info_outline),
            title: const Text('Как подключиться'),
            subtitle: Text(
              mode == EngineMode.vpn
                  ? 'При включении Android спросит разрешение на VPN. Для жёсткой защиты включите в системе «Always-on VPN» и «Блокировать без VPN».'
                  : 'Направьте приложения на SOCKS5-адрес из поля выше. На компьютере укажите его в системных настройках сети.',
            ),
          ),
        ),
      ],
    );
  }

  List<Widget> _serverSection() => [
        Text('Сервер туннеля', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 12),
        TextFormField(
          controller: _server,
          decoration: const InputDecoration(
            labelText: 'Адрес сервера',
            hintText: 'example.com:443',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 12),
        TextFormField(
          controller: _psk,
          obscureText: _obscure,
          decoration: InputDecoration(
            labelText: 'Ключ (PSK)',
            border: const OutlineInputBorder(),
            suffixIcon: IconButton(
              icon: Icon(_obscure
                  ? Icons.visibility_outlined
                  : Icons.visibility_off_outlined),
              onPressed: () => setState(() => _obscure = !_obscure),
            ),
          ),
        ),
        const SizedBox(height: 24),
        Text('Маскировка трафика',
            style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 12),
        SwitchListTile(
          contentPadding: EdgeInsets.zero,
          title: const Text('TLS-камуфляж'),
          subtitle: const Text(
              'Соединение с сервером выглядит как HTTPS к разрешённой платформе'),
          value: _camo,
          onChanged: (v) => setState(() => _camo = v),
        ),
        if (_camo) ...[
          TextFormField(
            controller: _sni,
            decoration: const InputDecoration(
              labelText: 'SNI (whitelisted-домен)',
              hintText: 'vkvideo.ru',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            children: [
              for (final s in _sniPresets)
                ActionChip(
                  label: Text(s),
                  onPressed: () => setState(() => _sni.text = s),
                ),
            ],
          ),
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('Отдельный fake ClientHello'),
            subtitle: const Text(
                'Рассинхронизация DPI: фиктивный ClientHello летит первым отдельным сегментом'),
            value: _fakeCh,
            onChanged: (v) => setState(() => _fakeCh = v),
          ),
        ],
        const SizedBox(height: 24),
      ];

  List<Widget> _proxySection() => [
        Text('Локальный прокси',
            style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 12),
        TextFormField(
          controller: _listen,
          decoration: const InputDecoration(
            labelText: 'SOCKS5-адрес',
            hintText: '127.0.0.1:1080',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 24),
      ];

  List<Widget> _dpiSection() => [
        Text('Обход DPI', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 12),
        DropdownButtonFormField<int>(
          initialValue: _split,
          decoration: const InputDecoration(
            labelText: 'Точка разрыва ClientHello',
            border: OutlineInputBorder(),
          ),
          items: const [
            DropdownMenuItem(value: 0, child: Text('Авто — после SNI')),
            DropdownMenuItem(value: 1, child: Text('Первый байт')),
            DropdownMenuItem(value: 8, child: Text('8 байт')),
            DropdownMenuItem(value: 32, child: Text('32 байта')),
            DropdownMenuItem(value: -1, child: Text('Без фрагментации')),
          ],
          onChanged: (value) {
            if (value != null) setState(() => _split = value);
          },
        ),
        SwitchListTile(
          contentPadding: EdgeInsets.zero,
          title: const Text('Multi-split (в духе zapret)'),
          subtitle: const Text(
              'Дополнительные разрывы внутри ClientHello против сборщиков сегментов'),
          value: _multi,
          onChanged: (v) => setState(() => _multi = v),
        ),
        const SizedBox(height: 24),
      ];

  List<Widget> _androidSection() => [
        Text('Android', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 12),
        SwitchListTile(
          contentPadding: EdgeInsets.zero,
          title: const Text('Автозапуск при включении'),
          subtitle: const Text('Поднимать туннель после перезагрузки устройства'),
          value: _autostart,
          onChanged: (v) => setState(() => _autostart = v),
        ),
        SwitchListTile(
          contentPadding: EdgeInsets.zero,
          title: const Text('Kill switch'),
          subtitle: const Text(
              'При выключении VPN-интерфейс остаётся поднятым и блокирует весь трафик — без утечек'),
          value: _killswitch,
          onChanged: (v) => setState(() => _killswitch = v),
        ),
        const SizedBox(height: 24),
      ];
}
