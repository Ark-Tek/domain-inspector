'use strict';

/**
 * Core lookup logic for Domain Inspector.
 * No dependencies: only Node built-ins (Node 20+, global fetch).
 *
 * inspect(domain) gathers, in parallel where possible:
 *   registration (RDAP, WHOIS fallback), DNS + email provider, hosting (IPinfo),
 *   website signals, and Wayback Machine history.
 */

const dns = require('node:dns');
const net = require('node:net');
const { domainToASCII } = require('node:url');

const UA = 'Mozilla/5.0 (compatible; DomainInspector/0.1)';
const resolver = new dns.promises.Resolver({ timeout: 4000, tries: 2 });

/* -------------------------------------------------------------------------- */
/* Input validation                                                            */
/* -------------------------------------------------------------------------- */

/** Returns a clean ASCII domain such as "clinica.es", or null if invalid. */
function normalizeDomain(raw) {
  if (typeof raw !== 'string') return null;
  let d = raw.trim().toLowerCase();
  if (!d || d.length > 300) return null;

  d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, ''); // scheme
  d = d.split(/[/?#]/)[0]; // path, query, fragment
  d = d.replace(/^.*@/, ''); // user:pass@
  d = d.replace(/:\d+$/, ''); // port
  d = d.replace(/\.$/, ''); // trailing dot
  d = d.replace(/^www\./, '');
  d = domainToASCII(d); // IDN -> punycode, '' if invalid

  if (!d || d.length > 253 || net.isIP(d)) return null;

  const label = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
  const parts = d.split('.');
  if (parts.length < 2 || !parts.every((p) => label.test(p))) return null;
  if (!/^(?:[a-z]{2,}|xn--[a-z0-9-]+)$/.test(parts[parts.length - 1])) return null;
  return d;
}

/* -------------------------------------------------------------------------- */
/* SSRF guard: never fetch private / internal addresses                        */
/* -------------------------------------------------------------------------- */

function isPrivateIp(ip) {
  const version = net.isIP(ip);
  if (version === 4) {
    const [a, b, c] = ip.split('.').map(Number);
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0 && (c === 0 || c === 2)) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) ||
      a >= 224
    );
  }
  if (version === 6) {
    const x = ip.toLowerCase();
    if (x === '::' || x === '::1') return true;
    const mapped = x.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIp(mapped[1]);
    return /^f[cd]/.test(x) || /^fe[89ab]/.test(x);
  }
  return true; // not a valid IP: treat as unsafe
}

async function assertPublicHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) {
    if (isPrivateIp(host)) throw new Error('blocked address');
    return;
  }
  const addrs = await dns.promises.lookup(host, { all: true });
  if (!addrs.length || addrs.some((a) => isPrivateIp(a.address))) {
    throw new Error('blocked address');
  }
}

/* -------------------------------------------------------------------------- */
/* Small helpers                                                               */
/* -------------------------------------------------------------------------- */

function isoDate(text) {
  if (!text) return '';
  const m = String(text).match(/(\d{4})[-./](\d{2})[-./](\d{2})/);
  return m ? `${m[1]}-${m[2]}-${m[3]}` : String(text).trim();
}

function daysUntil(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso || '');
  if (!m) return null;
  const target = Date.UTC(+m[1], +m[2] - 1, +m[3]);
  const now = new Date();
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return Math.round((target - today) / 86400000);
}

function describeError(e) {
  if (!e) return 'unknown error';
  if (e.name === 'TimeoutError' || e.name === 'AbortError') return 'timed out';
  if (e.cause && e.cause.code) return String(e.cause.code);
  return e.message || 'failed';
}

/* -------------------------------------------------------------------------- */
/* Registration: RDAP first, WHOIS (port 43) as fallback                       */
/* -------------------------------------------------------------------------- */

function parseRdap(data) {
  const events = {};
  for (const e of data.events || []) events[e.eventAction] = e.eventDate;

  let registrar = '';
  for (const ent of data.entities || []) {
    if ((ent.roles || []).includes('registrar')) {
      const fn = ((ent.vcardArray || [])[1] || []).find((item) => item[0] === 'fn');
      if (fn) registrar = fn[3];
    }
  }
  const created = isoDate(events.registration);
  const expires = isoDate(events.expiration);
  return {
    registrar,
    created,
    expires,
    daysToExpiry: daysUntil(expires),
    status: (data.status || []).join(', '),
    source: 'RDAP',
  };
}

function parseWhois(text) {
  const grab = (patterns) => {
    for (const p of patterns) {
      const m = text.match(p);
      if (m) return m[1].trim();
    }
    return '';
  };
  const created = isoDate(
    grab([/^\s*(?:creation date|created|registered on|registration date|domain registration date)[^:\n]*:\s*(.+)$/im]),
  );
  const expires = isoDate(
    grab([
      /^\s*(?:registry expiry date|registrar registration expiration date|expiry date|expiration date|expires on|paid-till)[^:\n]*:\s*(.+)$/im,
    ]),
  );
  const registrar = grab([/^\s*registrar:\s*(.+)$/im, /^\s*sponsoring registrar:\s*(.+)$/im]);
  const status = grab([/^\s*(?:domain )?status:\s*(.+)$/im]);
  if (!created && !expires && !registrar) return null;
  return { registrar, created, expires, daysToExpiry: daysUntil(expires), status, source: 'WHOIS' };
}

async function lookupRdap(domain) {
  const r = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
    headers: { accept: 'application/rdap+json', 'user-agent': UA },
    signal: AbortSignal.timeout(8000),
  });
  if (!r.ok) return null;
  return parseRdap(await r.json());
}

function whoisQuery(server, query, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: server, port: 43 });
    let data = '';
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => socket.write(`${query}\r\n`));
    socket.on('data', (chunk) => {
      data += chunk.toString('utf8');
      if (data.length > 200000) socket.destroy();
    });
    socket.on('timeout', () => socket.destroy(new Error('timed out')));
    socket.on('error', reject);
    socket.on('close', () => resolve(data));
  });
}

async function lookupWhois(domain) {
  const tld = domain.split('.').pop();
  const iana = await whoisQuery('whois.iana.org', tld);
  const m = iana.match(/^whois:\s*(\S+)/im);
  if (!m || !/^[a-z0-9.-]+$/i.test(m[1])) return null;
  await assertPublicHost(m[1]);
  return parseWhois(await whoisQuery(m[1], domain));
}

async function lookupRegistration(domain) {
  try {
    const r = await lookupRdap(domain);
    if (r) return r;
  } catch {
    /* fall through to WHOIS */
  }
  try {
    const w = await lookupWhois(domain);
    if (w) return w;
  } catch {
    /* give up below */
  }
  throw new Error('no RDAP/WHOIS data available for this domain extension');
}

/* -------------------------------------------------------------------------- */
/* DNS and email provider                                                      */
/* -------------------------------------------------------------------------- */

const MX_PROVIDERS = [
  ['google', 'Google Workspace / Gmail'],
  ['outlook', 'Microsoft 365'],
  ['ionos', 'IONOS'],
  ['1and1', 'IONOS'],
  ['ovh', 'OVH'],
  ['zoho', 'Zoho'],
  ['secureserver', 'GoDaddy'],
  ['hostinger', 'Hostinger'],
  ['dinahosting', 'Dinahosting'],
  ['arsys', 'Arsys'],
  ['strato', 'Strato'],
  ['mimecast', 'Mimecast'],
  ['proton', 'Proton'],
];

function guessEmailProvider(mxHosts) {
  if (!mxHosts.length) return 'No email on this domain';
  const joined = mxHosts.join(' ').toLowerCase();
  for (const [key, name] of MX_PROVIDERS) if (joined.includes(key)) return name;
  return 'Other / own server';
}

async function lookupDns(domain) {
  const attempt = (fn) => fn().catch(() => []);
  const [a, aaaa, ns, mx, txt, dmarc] = await Promise.all([
    attempt(() => resolver.resolve4(domain)),
    attempt(() => resolver.resolve6(domain)),
    attempt(() => resolver.resolveNs(domain)),
    attempt(() => resolver.resolveMx(domain)),
    attempt(() => resolver.resolveTxt(domain)),
    attempt(() => resolver.resolveTxt(`_dmarc.${domain}`)),
  ]);

  let ipv4 = a;
  if (!a.length && !aaaa.length) ipv4 = await attempt(() => resolver.resolve4(`www.${domain}`));

  const mxSorted = mx
    .filter((m) => m.exchange)
    .sort((x, y) => x.priority - y.priority)
    .map((m) => ({ priority: m.priority, exchange: m.exchange.toLowerCase() }));

  const startsWith = (records, prefix) =>
    records.some((parts) => parts.join('').toLowerCase().startsWith(prefix));

  return {
    resolves: ipv4.length > 0 || aaaa.length > 0,
    a: ipv4,
    aaaa,
    ns: ns.map((n) => n.toLowerCase()).sort(),
    mx: mxSorted,
    emailProvider: guessEmailProvider(mxSorted.map((m) => m.exchange)),
    spf: startsWith(txt, 'v=spf1'),
    dmarc: startsWith(dmarc, 'v=dmarc1'),
  };
}

/* -------------------------------------------------------------------------- */
/* Hosting (IPinfo)                                                            */
/* -------------------------------------------------------------------------- */

async function lookupHosting(ip, token) {
  const url = `https://ipinfo.io/${encodeURIComponent(ip)}/json${token ? `?token=${encodeURIComponent(token)}` : ''}`;
  const r = await fetch(url, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(8000) });
  if (!r.ok) throw new Error(`IPinfo returned HTTP ${r.status}`);
  const d = await r.json();
  return {
    ip,
    org: d.org || d.as_name || '',
    country: d.country || d.country_code || '',
    city: d.city || '',
    hostname: d.hostname || '',
  };
}

/* -------------------------------------------------------------------------- */
/* Website signals                                                             */
/* -------------------------------------------------------------------------- */

const PLATFORM_SIGNATURES = [
  ['Wix', ['wixstatic.com', 'wix.com', 'x-wix-request-id']],
  ['Squarespace', ['squarespace.com', 'static1.squarespace']],
  ['Shopify', ['cdn.shopify.com', 'myshopify.com']],
  ['Webflow', ['webflow.com', 'data-wf-page']],
  ['Jimdo', ['jimdo.com', 'jimdofree', 'jimdosite']],
  ['GoDaddy Builder', ['wsimg.com', 'godaddysites.com']],
  ['WordPress', ['wp-content', 'wp-includes', 'wp-json']],
  ['PrestaShop', ['prestashop']],
  ['Joomla', ['/media/jui/', 'joomla']],
  ['Drupal', ['drupal']],
];

function detectPlatform(html, headersText) {
  const blob = `${html.slice(0, 200000)}\n${headersText}`.toLowerCase();
  for (const [name, sigs] of PLATFORM_SIGNATURES) {
    if (sigs.some((s) => blob.includes(s))) return name;
  }
  return 'unknown / custom';
}

// Word boundaries matter: "reserva" alone would match "reservados" in every
// Spanish footer ("todos los derechos reservados").
const BOOKING_RE =
  /\b(reservar|reserva online|reserva tu|reserva ya|pedir cita|pide cita|cita previa|cita online|booking|calendly|doctoralia|agendar|agenda tu)\b/;

function decodeEntities(s) {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&amp;/g, '&');
}

function analyzeHtml(html) {
  const low = html.toLowerCase();
  const t = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return {
    title: t ? decodeEntities(t[1]).replace(/\s+/g, ' ').trim().slice(0, 120) : '',
    viewport: /<meta[^>]+name=["']viewport["']/.test(low),
    metaDescription: /<meta[^>]+name=["']description["']/.test(low),
    telLink: /href=["']tel:/.test(low),
    whatsapp: /wa\.me\/|api\.whatsapp\.com|whatsapp:\/\//.test(low),
    booking: BOOKING_RE.test(low),
  };
}

async function readLimited(res, limit = 300000) {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  while (size < limit) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.length;
  }
  try {
    await reader.cancel();
  } catch {
    /* ignore */
  }
  return Buffer.concat(chunks).toString('utf8').slice(0, limit);
}

/** Fetches a URL, following redirects manually so every hop is checked. */
async function fetchFollowing(startUrl, timeoutMs, maxHops = 5) {
  const signal = AbortSignal.timeout(timeoutMs);
  const started = performance.now();
  const redirects = [];
  let url = startUrl;

  for (let hop = 0; hop <= maxHops; hop++) {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('unsupported protocol');
    if (u.port && u.port !== '80' && u.port !== '443') throw new Error('unsupported port');
    await assertPublicHost(u.hostname);

    const res = await fetch(u, {
      redirect: 'manual',
      signal,
      headers: {
        'user-agent': UA,
        accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
        'accept-language': 'es-ES,es;q=0.9,en;q=0.8',
      },
    });

    const location = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && location) {
      redirects.push({ url: u.href, status: res.status });
      try {
        await res.body?.cancel();
      } catch {
        /* ignore */
      }
      url = new URL(location, u).href;
      continue;
    }
    const html = await readLimited(res);
    return { res, html, finalUrl: u.href, redirects, seconds: (performance.now() - started) / 1000 };
  }
  throw new Error('too many redirects');
}

async function checkWebsite(domain) {
  let httpsError = '';
  for (const [scheme, timeoutMs] of [
    ['https', 10000],
    ['http', 6000],
  ]) {
    try {
      const page = await fetchFollowing(`${scheme}://${domain}`, timeoutMs);
      const headersText = [...page.res.headers].map(([k, v]) => `${k}: ${v}`).join('\n');
      return {
        reachable: true,
        status: page.res.status,
        finalUrl: page.finalUrl,
        https: page.finalUrl.startsWith('https://'),
        httpsError,
        loadSeconds: Math.round(page.seconds * 100) / 100,
        server: page.res.headers.get('server') || '',
        platform: detectPlatform(page.html, headersText),
        redirects: page.redirects,
        ...analyzeHtml(page.html),
      };
    } catch (e) {
      if (scheme === 'https') httpsError = describeError(e);
      else return { reachable: false, error: `HTTPS: ${httpsError}; HTTP: ${describeError(e)}` };
    }
  }
  return { reachable: false, error: 'unknown error' };
}

/* -------------------------------------------------------------------------- */
/* Wayback Machine                                                             */
/* -------------------------------------------------------------------------- */

async function lookupWayback(domain) {
  const base = 'https://web.archive.org/cdx/search/cdx';
  const query = async (limit) => {
    const url = `${base}?url=${encodeURIComponent(domain)}&output=json&fl=timestamp&filter=statuscode:200&limit=${limit}`;
    const r = await fetch(url, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(15000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const text = await r.text();
    const rows = text.trim() ? JSON.parse(text) : [];
    if (rows.length < 2) return null;
    const ts = String(rows[1][0]);
    return `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`;
  };
  const [first, last] = await Promise.all([query(1), query(-1)]);
  return { first, last, browseUrl: `https://web.archive.org/web/*/${domain}` };
}

/* -------------------------------------------------------------------------- */
/* Main entry point                                                            */
/* -------------------------------------------------------------------------- */

async function inspect(domain, { ipinfoToken } = {}) {
  const errors = [];
  const guard = async (label, fn, fallback) => {
    try {
      return await fn();
    } catch (e) {
      errors.push(`${label}: ${describeError(e)}`);
      return fallback;
    }
  };

  const emptyDns = { resolves: false, a: [], aaaa: [], ns: [], mx: [], emailProvider: '', spf: false, dmarc: false };

  const [registration, dnsInfo, website, wayback] = await Promise.all([
    guard('registration', () => lookupRegistration(domain), null),
    guard('dns', () => lookupDns(domain), emptyDns),
    guard('website', () => checkWebsite(domain), null),
    guard('wayback', () => lookupWayback(domain), null),
  ]);

  if (!dnsInfo.resolves) errors.push('dns: the domain does not resolve to an IP address');

  const ip = dnsInfo.a[0] || dnsInfo.aaaa[0] || null;
  const hosting = ip ? await guard('hosting', () => lookupHosting(ip, ipinfoToken), null) : null;

  return {
    domain,
    checkedAt: new Date().toISOString(),
    registration,
    dns: dnsInfo,
    hosting,
    website,
    wayback,
    errors,
  };
}

module.exports = {
  inspect,
  normalizeDomain,
  isPrivateIp,
  guessEmailProvider,
  detectPlatform,
  analyzeHtml,
  parseRdap,
  parseWhois,
  daysUntil,
};
