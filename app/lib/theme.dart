import 'package:flutter/material.dart';

const seed = Color(0xFF23694D);

ThemeData buildTheme(Brightness brightness, ColorScheme? dynamic) {
  final scheme =
      dynamic ?? ColorScheme.fromSeed(seedColor: seed, brightness: brightness);
  return ThemeData(
    useMaterial3: true,
    // Material 3 Expressive: включается параметром useMaterial3Expressive
    // на свежих каналах Flutter; на стабильном он ещё не объявлен.
    colorScheme: scheme,
    brightness: brightness,
  );
}
