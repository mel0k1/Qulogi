import 'package:flutter/material.dart';

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
  bool _obscure = true;
  int _split = 0;

  @override
  void initState() {
    super.initState();
    _server = TextEditingController(text: widget.controller.config.server);
    _psk = TextEditingController(text: widget.controller.config.psk);
    _listen = TextEditingController(text: widget.controller.config.listen);
    _split = widget.controller.config.split;
  }

  @override
  void dispose() {
    _server.dispose();
    _psk.dispose();
    _listen.dispose();
    super.dispose();
  }

  void _save() {
    widget.controller.update(
      server: _server.text.trim(),
      psk: _psk.text,
      listen: _listen.text.trim(),
      split: _split,
    );
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Настройки сохранены')),
    );
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
      children: [
        Text('Туннель', style: Theme.of(context).textTheme.titleMedium),
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
              icon: Icon(_obscure ? Icons.visibility_outlined : Icons.visibility_off_outlined),
              onPressed: () => setState(() => _obscure = !_obscure),
            ),
          ),
        ),
        const SizedBox(height: 24),
        Text('Локальный прокси', style: Theme.of(context).textTheme.titleMedium),
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
        Text('Фрагментация TLS', style: Theme.of(context).textTheme.titleMedium),
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
          ],
          onChanged: (value) {
            if (value != null) {
              setState(() => _split = value);
            }
          },
        ),
        const SizedBox(height: 24),
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
            subtitle: const Text(
              'Направьте приложения на SOCKS5-адрес из поля выше. '
              'На компьютере укажите его в системных настройках сети, '
              'в приложениях — в настройках прокси.',
            ),
          ),
        ),
      ],
    );
  }
}
