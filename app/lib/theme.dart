import 'package:flutter/material.dart';

const seed = Color(0xFF23694D);

ThemeData buildTheme(Brightness brightness, ColorScheme? dynamic) {
  final scheme =
      dynamic ?? ColorScheme.fromSeed(seedColor: seed, brightness: brightness);
  return ThemeData(
    useMaterial3: true,
    useMaterial3Expressive: true,
    colorScheme: scheme,
    brightness: brightness,
  );
}
