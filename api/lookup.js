'use strict';

const { inspect, normalizeDomain } = require('../lib/inspect');

/**
 * GET /api/lookup?domain=example.com
 * Returns registration, DNS, hosting, website and archive data as JSON.
 */
module.exports = async (req, res) => {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const raw = req.query && req.query.domain;
  const domain = normalizeDomain(Array.isArray(raw) ? raw[0] : raw);
  if (!domain) {
    res.status(400).json({ error: 'Invalid domain. Try something like clinicaejemplo.es' });
    return;
  }

  try {
    const result = await inspect(domain, { ipinfoToken: process.env.IPINFO_TOKEN });
    res.setHeader('Cache-Control', 'public, s-maxage=300, stale-while-revalidate=60');
    res.status(200).json(result);
  } catch (e) {
    res.status(500).json({ error: 'The lookup failed. Please try again.' });
  }
};
