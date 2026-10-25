import 'package:dynamic_color/dynamic_color.dart';
import 'package:flutter/material.dart';

import 'screens/home_screen.dart';
import 'theme.dart';

void main() {
  runApp(const QulogiApp());
}

class QulogiApp extends StatelessWidget {
  const QulogiApp({super.key});

  @override
  Widget build(BuildContext context) {
    return DynamicColorBuilder(
      builder: (lightDynamic, darkDynamic) {
        return MaterialApp(
          title: 'Qulogi',
          theme: buildTheme(Brightness.light, lightDynamic),
          darkTheme: buildTheme(Brightness.dark, darkDynamic),
          themeMode: ThemeMode.system,
          home: const HomeScreen(),
        );
      },
    );
  }
}
