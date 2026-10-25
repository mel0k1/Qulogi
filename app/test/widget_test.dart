import 'package:flutter_test/flutter_test.dart';

import 'package:qulogi/main.dart';

void main() {
  testWidgets('home renders', (tester) async {
    await tester.pumpWidget(const QulogiApp());
    await tester.pump();
    expect(find.text('Qulogi'), findsOneWidget);
    expect(find.text('Отключено'), findsOneWidget);
    expect(find.text('Подключить'), findsOneWidget);
  });
}
