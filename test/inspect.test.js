'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  normalizeDomain,
  isPrivateIp,
  guessEmailProvider,
  detectPlatform,
  analyzeHtml,
  parseRdap,
  parseWhois,
  daysUntil,
} = require('../lib/inspect');

test('normalizeDomain cleans URLs and accepts valid domains', () => {
  assert.equal(normalizeDomain('https://www.Clinica-Ejemplo.es/contacto?x=1'), 'clinica-ejemplo.es');
  assert.equal(normalizeDomain('example.com:8080'), 'example.com');
  assert.equal(normalizeDomain('ejemplo.es.'), 'ejemplo.es');
  assert.equal(normalizeDomain('  EXAMPLE.org  '), 'example.org');
  assert.equal(normalizeDomain('bücher.de'), 'xn--bcher-kva.de');
});

test('normalizeDomain rejects invalid input', () => {
  for (const bad of ['', 'localhost', '127.0.0.1', '::1', 'bad_domain.com', '-bad.com', 'a b.com', `${'a'.repeat(64)}.com`, 'x.123', 42, null]) {
    assert.equal(normalizeDomain(bad), null, `should reject ${String(bad)}`);
  }
});

test('isPrivateIp blocks internal ranges and allows public ones', () => {
  for (const ip of ['10.0.0.1', '192.168.1.1', '127.0.0.1', '169.254.169.254', '172.16.0.1', '100.64.0.1', '0.0.0.0', '::1', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1', 'not-an-ip']) {
    assert.equal(isPrivateIp(ip), true, `${ip} should be blocked`);
  }
  for (const ip of ['8.8.8.8', '172.32.0.1', '192.0.66.1', '2606:4700::1111']) {
    assert.equal(isPrivateIp(ip), false, `${ip} should be allowed`);
  }
});

test('guessEmailProvider recognises common providers', () => {
  assert.equal(guessEmailProvider([]), 'No email on this domain');
  assert.equal(guessEmailProvider(['aspmx.l.google.com']), 'Google Workspace / Gmail');
  assert.equal(guessEmailProvider(['example-com.mail.protection.outlook.com']), 'Microsoft 365');
  assert.equal(guessEmailProvider(['mail.miservidor.es']), 'Other / own server');
});

test('detectPlatform finds site builders', () => {
  assert.equal(detectPlatform('<link href="/wp-content/themes/x.css">', ''), 'WordPress');
  assert.equal(detectPlatform('<img src="https://static.wixstatic.com/a.png">', ''), 'Wix');
  assert.equal(detectPlatform('<html></html>', 'server: custom'), 'unknown / custom');
});

test('analyzeHtml reads the signals that matter for a pitch', () => {
  const html = `<html><head><title> Clínica &amp; Fisio </title>
    <meta name="viewport" content="width=device-width">
    <meta name="description" content="x"></head>
    <body><a href="tel:+34942000000">Llamar</a> <a href="https://wa.me/34600000000">WhatsApp</a>
    <a href="/cita">Pedir cita</a></body></html>`;
  const r = analyzeHtml(html);
  assert.equal(r.title, 'Clínica & Fisio');
  assert.equal(r.viewport, true);
  assert.equal(r.metaDescription, true);
  assert.equal(r.telLink, true);
  assert.equal(r.whatsapp, true);
  assert.equal(r.booking, true);
});

test('analyzeHtml does not treat "derechos reservados" as booking', () => {
  const r = analyzeHtml('<html><body>Todos los derechos reservados. Agenda de eventos.</body></html>');
  assert.equal(r.booking, false);
  assert.equal(r.viewport, false);
  assert.equal(r.telLink, false);
});

test('parseRdap extracts registrar and dates', () => {
  const r = parseRdap({
    status: ['client transfer prohibited'],
    events: [
      { eventAction: 'registration', eventDate: '2015-03-02T10:00:00Z' },
      { eventAction: 'expiration', eventDate: '2031-03-02T10:00:00Z' },
    ],
    entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Example Registrar S.L.']]] }],
  });
  assert.equal(r.registrar, 'Example Registrar S.L.');
  assert.equal(r.created, '2015-03-02');
  assert.equal(r.expires, '2031-03-02');
  assert.equal(r.source, 'RDAP');
  assert.equal(typeof r.daysToExpiry, 'number');
});

test('parseWhois extracts fields and returns null for empty answers', () => {
  const text = 'Domain Name: EXAMPLE.COM\nRegistrar: Example Inc.\nCreation Date: 1995-08-14T04:00:00Z\nRegistry Expiry Date: 2030-08-13T04:00:00Z\nDomain Status: ok\n';
  const r = parseWhois(text);
  assert.equal(r.registrar, 'Example Inc.');
  assert.equal(r.created, '1995-08-14');
  assert.equal(r.expires, '2030-08-13');
  assert.equal(parseWhois('No match for domain'), null);
});

test('daysUntil handles past, future and bad input', () => {
  assert.ok(daysUntil('2000-01-01') < 0);
  assert.ok(daysUntil('2999-01-01') > 0);
  assert.equal(daysUntil(''), null);
  assert.equal(daysUntil('soon'), null);
});
