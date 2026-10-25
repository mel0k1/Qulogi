import 'package:flutter_test/flutter_test.dart';

import 'package:qulogi/main.dart';

void main() {
  testWidgets('home renders', (tester) async {
    await tester.pumpWidget(const QulogiApp());
    await tester.pump();
    expect(find.text('Qulogi'), findsOneWidget);
    expect(find.text('Отключено'), findsOneWidget);
    // the connect action is a circular icon button carrying a semantics label
    expect(find.byIcon(Icons.power_settings_new), findsOneWidget);
    expect(
      find.byWidgetPredicate(
        (w) => w is Semantics && w.properties.label == 'Подключить',
      ),
      findsOneWidget,
    );
  });
}
