import 'package:flutter_test/flutter_test.dart';
import 'package:mobile_hardening_kit_example/main.dart';

void main() {
  testWidgets('signal explorer explains signal-only behavior', (tester) async {
    await tester.pumpWidget(const HardeningExampleApp());

    expect(find.text('Mobile Hardening Kit'), findsOneWidget);
    expect(find.textContaining('heuristic signals'), findsOneWidget);
    expect(find.text('Protect sensitive display content'), findsOneWidget);
  });
}
