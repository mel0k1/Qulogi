import 'dart:convert';
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
  late final TextEditingController _direct;
  late final TextEditingController _proxy;
  late final TextEditingController _davUrl;
  late final TextEditingController _davUser;
  late final TextEditingController _davPass;
  late final TextEditingController _davMailbox;
  late final TextEditingController _cdnEdge;
  late final TextEditingController _cdnSni;
  late final TextEditingController _cdnHost;
  late final TextEditingController _botlpUrl;
  late final TextEditingController _botlpToken;
  late final TextEditingController _botlpRoom;
  late final TextEditingController _botlpChat;
  late final TextEditingController _turnServer;
  late final TextEditingController _turnUser;
  late final TextEditingController _turnPass;
  late final TextEditingController _fallbacks;
  bool _obscure = true;
  bool _obscureBotlp = true;
  bool _obscureDav = true;
  bool _obscureTurn = true;
  // Platform adapter for the bot long-poll transport ('' | 'vk' | 'max').
  String _botlpKind = '';
  int _split = 0;
  bool _multi = false;
  bool _camo = false;
  bool _fakeCh = true;
  bool _autostart = false;
  bool _killswitch = false;
  bool _smartSplit = true;
  bool _cdnWs = false;
  bool _noFailover = false;
  String _fallbacksError = '';

  static const _sniPresets = ['vkvideo.ru', 'rutube.ru', 'ok.ru', 'dzen.ru'];

  @override
  void initState() {
    super.initState();
    final cfg = widget.controller.config;
    _server = TextEditingController(text: cfg.server);
    _psk = TextEditingController(text: cfg.psk);
    _listen = TextEditingController(text: cfg.listen);
    _sni = TextEditingController(text: cfg.sni);
    _direct = TextEditingController(text: cfg.directDomains);
    _proxy = TextEditingController(text: cfg.proxyDomains);
    _davUrl = TextEditingController(text: cfg.davUrl);
    _davUser = TextEditingController(text: cfg.davUser);
    _davPass = TextEditingController(text: cfg.davPass);
    _davMailbox = TextEditingController(text: cfg.davMailbox);
    _cdnEdge = TextEditingController(text: cfg.cdnEdge);
    _cdnSni = TextEditingController(text: cfg.cdnSni);
    _cdnHost = TextEditingController(text: cfg.cdnHost);
    _botlpUrl = TextEditingController(text: cfg.botlpUrl);
    _botlpToken = TextEditingController(text: cfg.botlpToken);
    _botlpRoom = TextEditingController(text: cfg.botlpRoom);
    _botlpChat = TextEditingController(text: cfg.botlpChat);
    _turnServer = TextEditingController(text: cfg.turnServer);
    _turnUser = TextEditingController(text: cfg.turnUser);
    _turnPass = TextEditingController(text: cfg.turnPass);
    _fallbacks = TextEditingController(
      text: cfg.fallbacks.isEmpty
          ? ''
          : const JsonEncoder.withIndent('  ').convert(cfg.fallbacks),
    );
    _split = cfg.split;
    _multi = cfg.multiSplit;
    _camo = cfg.camo;
    _fakeCh = cfg.fakeCh;
    _botlpKind = cfg.botlpKind;
    _autostart = cfg.autostart;
    _killswitch = cfg.killswitch;
    _smartSplit = cfg.smartSplit;
    _cdnWs = cfg.cdnWs;
    _noFailover = cfg.noFailover;
  }

  @override
  void dispose() {
    _server.dispose();
    _psk.dispose();
    _listen.dispose();
    _sni.dispose();
    _direct.dispose();
    _proxy.dispose();
    _davUrl.dispose();
    _davUser.dispose();
    _davPass.dispose();
    _davMailbox.dispose();
    _cdnEdge.dispose();
    _cdnSni.dispose();
    _cdnHost.dispose();
    _botlpUrl.dispose();
    _botlpToken.dispose();
    _botlpRoom.dispose();
    _botlpChat.dispose();
    _turnServer.dispose();
    _turnUser.dispose();
    _turnPass.dispose();
    _fallbacks.dispose();
    super.dispose();
  }

  void _save() {
    // Резервы failover: пусто = нет; иначе — JSON-массив TransportSpec.
    List<Map<String, dynamic>>? parsed;
    if (_fallbacks.text.trim().isNotEmpty) {
      try {
        final v = jsonDecode(_fallbacks.text);
        if (v is! List) throw const FormatException('нужен массив');
        final items = v.whereType<Map<String, dynamic>>().toList();
        if (items.length != v.length) {
          throw const FormatException('каждый элемент должен быть объектом');
        }
        parsed = items;
        _fallbacksError = '';
      } catch (e) {
        setState(() => _fallbacksError = 'Некорректный JSON резервов: $e');
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Не сохранено: $_fallbacksError')),
        );
        return;
      }
    } else {
      _fallbacksError = '';
    }
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
      smartSplit: _smartSplit,
      directDomains: _direct.text,
      proxyDomains: _proxy.text,
      davUrl: _davUrl.text.trim(),
      davUser: _davUser.text.trim(),
      davPass: _davPass.text,
      davMailbox: _davMailbox.text.trim(),
      cdnEdge: _cdnEdge.text.trim(),
      cdnSni: _cdnSni.text.trim(),
      cdnHost: _cdnHost.text.trim(),
      cdnWs: _cdnWs,
      fallbacks: parsed,
      noFailover: _noFailover,
      botlpUrl: _botlpUrl.text.trim(),
      botlpToken: _botlpToken.text,
      botlpRoom: _botlpRoom.text.trim(),
      botlpKind: _botlpKind,
      botlpChat: _botlpChat.text.trim(),
      turnServer: _turnServer.text.trim(),
      turnUser: _turnUser.text.trim(),
      turnPass: _turnPass.text,
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
        if (usesServer) ..._davSection(),
        if (usesServer) ..._cdnSection(),
        if (usesServer) ..._botlpSection(),
        if (usesServer) ..._turnSection(),
        if (usesServer) ..._failoverSection(),
        if (usesServer) ..._splitSection(),
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

  List<Widget> _davSection() => [
        Text('Транспорт через облако (без VPS)',
            style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 12),
        TextFormField(
          controller: _davUrl,
          onChanged: (_) => setState(() {}),
          decoration: const InputDecoration(
            labelText: 'WebDAV-сервер',
            hintText: 'https://webdav.yandex.ru',
            border: OutlineInputBorder(),
            helperText:
                'Заполнив это поле, туннель пойдёт через облако — адрес релея можно не указывать. Задержка — секунды.',
          ),
        ),
        if (_davUrl.text.trim().isNotEmpty) ...[
          const SizedBox(height: 12),
          TextFormField(
            controller: _davMailbox,
            decoration: const InputDecoration(
              labelText: 'Каталог-почтовый ящик',
              hintText: 'qulogi',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _davUser,
            decoration: const InputDecoration(
              labelText: 'Логин облака',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _davPass,
            obscureText: _obscureDav,
            decoration: InputDecoration(
              labelText: 'Пароль облака',
              border: const OutlineInputBorder(),
              suffixIcon: IconButton(
                icon: Icon(_obscureDav
                    ? Icons.visibility_outlined
                    : Icons.visibility_off_outlined),
                onPressed: () => setState(() => _obscureDav = !_obscureDav),
              ),
            ),
          ),
        ],
        const SizedBox(height: 24),
      ];

  List<Widget> _cdnSection() => [
        Text('CDN-фронтинг', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 12),
        TextFormField(
          controller: _cdnEdge,
          decoration: const InputDecoration(
            labelText: 'Край белого CDN',
            hintText: 'edge.whitelisted-cdn.ru:443',
            border: OutlineInputBorder(),
            helperText:
                'TLS идёт к разрешённому краю CDN, а Host-заголовок заводит соединение на ваш релей за тем же CDN',
          ),
        ),
        if (_cdnEdge.text.trim().isNotEmpty) ...[
          const SizedBox(height: 12),
          TextFormField(
            controller: _cdnSni,
            decoration: const InputDecoration(
              labelText: 'SNI края (белый домен)',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _cdnHost,
            decoration: const InputDecoration(
              labelText: 'Имя релея за CDN (Host)',
              hintText: 'relay.example.net',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 12),
          SwitchListTile(
            value: _cdnWs,
            onChanged: (v) => setState(() => _cdnWs = v),
            title: const Text('Реальный CDN (WebSocket RFC 6455)'),
            subtitle: const Text(
                'включать, когда релей стоит за настоящей CDN-сетью (Cloudflare, Gcore, Selectel, Yandex Cloud): кадры едут WS-фреймами'),
          ),
        ],
        const SizedBox(height: 24),
      ];

  List<Widget> _botlpSection() => [
        Text('Bot long-poll (платформа как шина)',
            style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 12),
        TextFormField(
          controller: _botlpUrl,
          onChanged: (_) => setState(() {}),
          decoration: const InputDecoration(
            labelText: 'API платформы (send/poll)',
            hintText: 'https://api.example.org/bot',
            border: OutlineInputBorder(),
            helperText:
                'Кадры туннеля едут сообщениями бота через официальный long-poll API; задержка — секунды',
          ),
        ),
        if (_botlpUrl.text.trim().isNotEmpty) ...[
          const SizedBox(height: 12),
          TextFormField(
            controller: _botlpToken,
            obscureText: _obscureBotlp,
            decoration: InputDecoration(
              labelText: 'Токен бота',
              border: const OutlineInputBorder(),
              suffixIcon: IconButton(
                icon: Icon(_obscureBotlp
                    ? Icons.visibility_outlined
                    : Icons.visibility_off_outlined),
                onPressed: () =>
                    setState(() => _obscureBotlp = !_obscureBotlp),
              ),
            ),
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _botlpRoom,
            decoration: const InputDecoration(
              labelText: 'Базовая комната',
              hintText: 'qulogi',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 12),
          DropdownButtonFormField<String>(
            initialValue: _botlpKind,
            decoration: const InputDecoration(
              labelText: 'Адаптер платформы',
              border: OutlineInputBorder(),
              helperText:
                  'vk/max — официальные Bot API; обе стороны держат РАЗНЫЕ токены ботов в одном чате',
            ),
            items: const [
              DropdownMenuItem(value: '', child: Text('Обычный (send/poll)')),
              DropdownMenuItem(value: 'vk', child: Text('VK Bot API')),
              DropdownMenuItem(value: 'max', child: Text('Max Bot API')),
            ],
            onChanged: (v) => setState(() => _botlpKind = v ?? ''),
          ),
          if (_botlpKind == 'vk' || _botlpKind == 'max') ...[
            const SizedBox(height: 12),
            TextFormField(
              controller: _botlpChat,
              decoration: InputDecoration(
                labelText: _botlpKind == 'vk' ? 'peer_id чата' : 'chat_id чата',
                hintText: '2000000001',
                border: const OutlineInputBorder(),
              ),
            ),
          ],
        ],
        const SizedBox(height: 24),
      ];

  List<Widget> _turnSection() => [
        Text('TURN-релей (как в WebRTC)',
            style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 12),
        TextFormField(
          controller: _turnServer,
          onChanged: (_) => setState(() {}),
          decoration: const InputDecoration(
            labelText: 'TURN-сервер',
            hintText: 'turn.example.org:3478',
            border: OutlineInputBorder(),
            helperText:
                'Туннель едёт TCP-связкой через TURN (RFC 6062); адрес релея — из поля «Сервер туннеля»',
          ),
        ),
        if (_turnServer.text.trim().isNotEmpty) ...[
          const SizedBox(height: 12),
          TextFormField(
            controller: _turnUser,
            decoration: const InputDecoration(
              labelText: 'Имя пользователя (пусто = анонимно)',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _turnPass,
            obscureText: _obscureTurn,
            decoration: InputDecoration(
              labelText: 'Пароль TURN',
              border: const OutlineInputBorder(),
              suffixIcon: IconButton(
                icon: Icon(_obscureTurn
                    ? Icons.visibility_outlined
                    : Icons.visibility_off_outlined),
                onPressed: () => setState(() => _obscureTurn = !_obscureTurn),
              ),
            ),
          ),
        ],
        const SizedBox(height: 24),
      ];

  List<Widget> _failoverSection() => [
        Text('Авто-переезд при деградации',
            style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 12),
        SwitchListTile(
          value: !_noFailover,
          onChanged: (v) => setState(() => _noFailover = !v),
          title: const Text('Переехать на резервный транспорт'),
          subtitle: const Text(
              'монитор проверяет активный транспорт и переезжает на резерв при деградации; когда лучший восстановится — вернётся'),
        ),
        const SizedBox(height: 12),
        TextFormField(
          controller: _fallbacks,
          maxLines: 6,
          minLines: 2,
          decoration: InputDecoration(
            labelText: 'Резервные транспорты (JSON-массив)',
            hintText:
                '[{"kind":"tcp","server":"r2.example.net:443"},\n {"kind":"cdn","server":"edge:443","host":"relay","ws":true}]',
            border: const OutlineInputBorder(),
            errorText:
                _fallbacksError.isEmpty ? null : _fallbacksError,
            helperText:
                'kind: tcp | cdn | turn | dav | botlp; попробуются по порядку, если основной ляжет',
          ),
        ),
        const SizedBox(height: 24),
      ];

  List<Widget> _splitSection() => [
        Text('Умный сплит', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 12),
        SwitchListTile(
          contentPadding: EdgeInsets.zero,
          title: const Text('Белые списки напрямую, остальное — через релей'),
          subtitle: const Text(
              'Яндекс, VK, банки и прочие разрешённые ресурсы ходят как обычно: быстрее и без нагрузки на релей'),
          value: _smartSplit,
          onChanged: (v) => setState(() => _smartSplit = v),
        ),
        if (_smartSplit) ...[
          TextFormField(
            controller: _direct,
            minLines: 2,
            maxLines: 5,
            decoration: const InputDecoration(
              labelText: 'Всегда напрямую',
              hintText: 'example.ru\n10.0.0.0/8',
              border: OutlineInputBorder(),
              helperText: 'Домены или CIDR, по одному в строке — дополнение к встроенному списку',
            ),
          ),
          const SizedBox(height: 8),
          TextFormField(
            controller: _proxy,
            minLines: 2,
            maxLines: 5,
            decoration: const InputDecoration(
              labelText: 'Всегда через релей',
              hintText: 'leaky.example.com',
              border: OutlineInputBorder(),
              helperText: 'Перекрывает белый список',
            ),
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
