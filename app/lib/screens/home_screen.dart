import 'package:flutter/material.dart';

import '../services/engine_bridge.dart';
import '../state/engine_controller.dart';
import '../widgets/stat_card.dart';
import '../widgets/status_button.dart';
import 'logs_screen.dart';
import 'settings_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  late final EngineController _controller;
  int _page = 0;

  @override
  void initState() {
    super.initState();
    _controller = EngineController(createEngineBridge(), SettingsStore());
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _controller,
      builder: (context, _) {
        return Scaffold(
          appBar: AppBar(title: const Text('Qulogi')),
          body: IndexedStack(
            index: _page,
            children: [
              _StatusPage(controller: _controller),
              SettingsScreen(controller: _controller),
              LogsScreen(controller: _controller),
            ],
          ),
          bottomNavigationBar: NavigationBar(
            selectedIndex: _page,
            onDestinationSelected: (i) => setState(() => _page = i),
            destinations: const [
              NavigationDestination(
                icon: Icon(Icons.shield_outlined),
                selectedIcon: Icon(Icons.shield),
                label: 'Соединение',
              ),
              NavigationDestination(
                icon: Icon(Icons.tune),
                label: 'Настройки',
              ),
              NavigationDestination(
                icon: Icon(Icons.receipt_long_outlined),
                selectedIcon: Icon(Icons.receipt_long),
                label: 'Журнал',
              ),
            ],
          ),
        );
      },
    );
  }
}

class _StatusPage extends StatelessWidget {
  const _StatusPage({required this.controller});

  final EngineController controller;

  static String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes Б';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} КБ';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / 1024 / 1024).toStringAsFixed(1)} МБ';
    }
    return '${(bytes / 1024 / 1024 / 1024).toStringAsFixed(2)} ГБ';
  }

  static String _formatUptime(int seconds) {
    final m = seconds ~/ 60;
    final s = seconds % 60;
    if (m == 0) return '$s с';
    return '$m мин $s с';
  }

  @override
  Widget build(BuildContext context) {
    final running = controller.running;
    final scheme = Theme.of(context).colorScheme;
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
        child: Column(
          children: [
            StatusButton(
              connected: running,
              onTap: running ? controller.stop : controller.start,
            ),
            const SizedBox(height: 12),
            Text(
              controller.vpnBlocked
                  ? 'Kill switch: трафик заблокирован'
                  : running
                      ? 'Подключено'
                      : 'Отключено',
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            if (running && !controller.vpnBlocked)
              Text(
                'активно ${_formatUptime(controller.status.uptime)}',
                style: Theme.of(context)
                    .textTheme
                    .bodyMedium
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
            if (controller.vpnBlocked)
              Text(
                'новые связи отклоняются, утечек нет',
                style: Theme.of(context)
                    .textTheme
                    .bodyMedium
                    ?.copyWith(color: scheme.error),
              ),
            if (controller.error != null) ...[
              const SizedBox(height: 12),
              Card(
                color: scheme.errorContainer,
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Text(
                    controller.error!,
                    style: TextStyle(color: scheme.onErrorContainer),
                  ),
                ),
              ),
            ],
            const SizedBox(height: 24),
            SegmentedButton<EngineMode>(
              segments: const [
                ButtonSegment(
                  value: EngineMode.vpn,
                  icon: Icon(Icons.enhanced_encryption_outlined),
                  label: Text('VPN'),
                ),
                ButtonSegment(
                  value: EngineMode.tunnel,
                  icon: Icon(Icons.vpn_lock_outlined),
                  label: Text('Туннель'),
                ),
                ButtonSegment(
                  value: EngineMode.dpi,
                  icon: Icon(Icons.alt_route_outlined),
                  label: Text('DPI'),
                ),
              ],
              selected: {controller.config.mode},
              onSelectionChanged: (selection) =>
                  controller.setMode(selection.first),
            ),
            const SizedBox(height: 24),
            Row(
              children: [
                Expanded(
                  child: StatCard(
                    icon: Icons.upload_outlined,
                    label: 'Отдано',
                    value: _formatBytes(controller.status.bytesUp),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: StatCard(
                    icon: Icons.download_outlined,
                    label: 'Принято',
                    value: _formatBytes(controller.status.bytesDown),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: StatCard(
                    icon: Icons.link,
                    label: 'Связи',
                    value: '${controller.status.connections}',
                  ),
                ),
              ],
            ),
            if (controller.config.mode != EngineMode.dpi &&
                controller.config.server.isNotEmpty) ...[
              const SizedBox(height: 16),
              Text(
                controller.config.server,
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
