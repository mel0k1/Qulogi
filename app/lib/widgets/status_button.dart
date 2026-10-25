import 'package:flutter/material.dart';

class StatusButton extends StatelessWidget {
  const StatusButton({
    super.key,
    required this.connected,
    required this.onTap,
  });

  final bool connected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Semantics(
      button: true,
      label: connected ? 'Отключить' : 'Подключить',
      child: InkWell(
        onTap: onTap,
        customBorder: const CircleBorder(),
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 350),
          curve: Curves.easeOutCubic,
          width: 172,
          height: 172,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: connected
                ? scheme.primaryContainer
                : scheme.surfaceContainerHighest,
            border: Border.all(
              color: connected ? scheme.primary : scheme.outlineVariant,
              width: 2,
            ),
          ),
          child: Icon(
            connected ? Icons.link_off : Icons.power_settings_new,
            size: 60,
            color: connected
                ? scheme.onPrimaryContainer
                : scheme.onSurfaceVariant,
          ),
        ),
      ),
    );
  }
}
