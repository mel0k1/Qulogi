import 'package:flutter/material.dart';

import '../state/engine_controller.dart';

class LogsScreen extends StatelessWidget {
  const LogsScreen({super.key, required this.controller});

  final EngineController controller;

  @override
  Widget build(BuildContext context) {
    if (controller.logs.isEmpty) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Text(
            'Журнал пуст. События движка появятся здесь после первого подключения.',
            textAlign: TextAlign.center,
            style: Theme.of(context)
                .textTheme
                .bodyMedium
                ?.copyWith(color: Theme.of(context).colorScheme.onSurfaceVariant),
          ),
        ),
      );
    }
    return Column(
      children: [
        Expanded(
          child: ListView.builder(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            itemCount: controller.logs.length,
            itemBuilder: (context, index) {
              return Padding(
                padding: const EdgeInsets.symmetric(vertical: 3),
                child: Text(
                  controller.logs[index],
                  style: Theme.of(context).textTheme.bodySmall,
                ),
              );
            },
          ),
        ),
        Padding(
          padding: const EdgeInsets.only(bottom: 12),
          child: TextButton.icon(
            onPressed: controller.clearLogs,
            icon: const Icon(Icons.delete_outline),
            label: const Text('Очистить'),
          ),
        ),
      ],
    );
  }
}
