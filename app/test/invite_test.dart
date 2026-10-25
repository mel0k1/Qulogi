import 'package:flutter_test/flutter_test.dart';

import 'package:qulogi/services/relays.dart';

void main() {
  test('relay invite round trip', () {
    const link = 'qulogi://relay/owl-eu-1'
        '?type=qulogi-tls&addr=r1.example.net%3A443&sni=vkvideo.ru&psk=s3cr3t';
    final invite = parseInvite(link);
    expect(invite, isNotNull);
    expect(invite!.isCatalog, isFalse);
    final relay = invite.relay!;
    expect(relay.id, 'owl-eu-1');
    expect(relay.type, 'qulogi-tls');
    expect(relay.addr, 'r1.example.net:443');
    expect(relay.sni, 'vkvideo.ru');
    expect(relay.psk, 's3cr3t');

    final rebuilt = buildRelayInvite(relay);
    final reparsed = parseInvite(rebuilt)!;
    expect(reparsed.relay!.addr, 'r1.example.net:443');
    expect(reparsed.relay!.psk, 's3cr3t');
  });

  test('psk-less invite works', () {
    final invite = parseInvite(
        'qulogi://relay/x?type=qulogi-tcp&addr=host.example%3A443');
    expect(invite, isNotNull);
    expect(invite!.relay!.psk, isEmpty);
    expect(invite.relay!.type, 'qulogi-tcp');
  });

  test('catalog invite', () {
    final invite = parseInvite(
        'qulogi://catalog/?url=https%3A%2F%2Fmirror.example%2Fcatalog.json&name=Community');
    expect(invite, isNotNull);
    expect(invite!.isCatalog, isTrue);
    expect(invite.catalogUrl, 'https://mirror.example/catalog.json');
  });

  test('malformed invites are rejected', () {
    for (final bad in [
      '',
      'https://example.org/x',
      'qulogi://unknown/?a=1',
      'qulogi://relay/x?type=qulogi-tls',
      'qulogi://relay/x?addr=h:443',
      'qulogi://catalog/?url=ftp://x',
    ]) {
      expect(parseInvite(bad), isNull, reason: bad);
    }
  });

  test('discovery report parses probes and errors', () {
    final ok = DiscoveryReport.fromJson({
      'source': 'https:mirror',
      'verified': true,
      'from_cache': false,
      'probes': [
        {
          'relay_id': 'owl-1',
          'type': 'qulogi-tls',
          'addr': 'r1.example.net:443',
          'sni': 'vkvideo.ru',
          'rtt_ms': 42.7,
        }
      ],
    });
    expect(ok.error, isEmpty);
    expect(ok.verified, isTrue);
    expect(ok.relays.single.relayId, 'owl-1');
    expect(ok.relays.single.rttMs.round(), 43);

    final bad = DiscoveryReport.fromJson({'error': 'все зеркала недоступны'});
    expect(bad.error, isNotEmpty);
    expect(bad.relays, isEmpty);
  });
}
