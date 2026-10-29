# Domain Inspector

Enter a business's domain and see how its website, email, hosting and registration are set up. Built for spotting local businesses whose websites could be improved.

For each domain it shows:

- **Website**: HTTPS, mobile layout tag, load time, tap-to-call and WhatsApp links, online booking hints, meta description, and the platform it was built with (Wix, WordPress, Squarespace...).
- **Email**: provider (Google, Microsoft 365, IONOS...), mail servers, SPF and DMARC.
- **Hosting and DNS**: IP address, hosting provider, server location, nameservers.
- **Domain registration**: registrar, creation and expiry dates (RDAP, with a WHOIS fallback).
- **History**: first and latest copy saved by the Internet Archive.

Checks are marked Pass, Improve or Fail and summarised in a bar at the top. The page also links to the same domain on ICANN Lookup, who.is, whois.com, NSLookup.io, DomainTools, IPinfo and the Wayback Machine.

## Run it locally

Requires Node.js 20 or newer. There are no dependencies to install.

```bash
npm run dev
```

Open http://localhost:3000.

Optional: copy `.env.example` to `.env` and add a free [IPinfo token](https://ipinfo.io/signup). Without it, IPinfo limits how many lookups you can make.

Run the tests with `npm test`.

## Project layout

```
public/index.html   the web page (HTML, CSS and JavaScript in one file)
api/lookup.js       serverless endpoint: GET /api/lookup?domain=example.com
lib/inspect.js      all lookup logic (RDAP/WHOIS, DNS, IPinfo, website, Wayback)
dev-server.js       small local server, same handler as Vercel
test/               unit tests for the parsing and validation code
vercel.json         Vercel settings
```

## Put it on GitHub

1. Create an empty repository on GitHub (no README, no .gitignore, no license).
2. In this folder:

```bash
git remote add origin https://github.com/YOUR-USER/domain-inspector.git
git push -u origin main
```

## Deploy to Vercel

1. In Vercel, choose **Add New > Project** and import the GitHub repository.
2. Framework preset: **Other**. Leave the build command empty. The output directory is `public` (already set in `vercel.json`).
3. Optional: add the environment variable `IPINFO_TOKEN`.
4. Deploy. Every push to `main` redeploys automatically.

## Things to know

- **Load time is measured from the server**, not from a visitor's phone. Real visitors on mobile data will usually wait longer.
- **Website checks are text-based hints.** Booking, WhatsApp and platform detection search the page's HTML, so confirm anything important by opening the site.
- **Owner details are hidden** for most `.es` and EU domains. You will get registrar, dates and technical data only.
- **Some sites block automated visits** and answer with an error status even though they work in a browser.

## Security notes

The endpoint fetches websites chosen by whoever uses the page, so it is built defensively:

- Input is validated as a real domain name. IP addresses and `localhost` are rejected.
- Every request, including each redirect, is checked so that private, loopback and link-local addresses are never contacted.
- Pages are read up to 300 KB and the response contains only derived fields (status, load time, title, yes/no signals), never the page itself.

Known limit: the address check happens just before each request, so a hostile DNS server could in theory change its answer in between (DNS rebinding). For a public deployment, also turn on rate limiting in Vercel's firewall settings so strangers cannot use the tool to hammer other sites or use up your IPinfo quota.

## Ideas for next versions

- Check many domains at once and export a CSV (the Python script `domain_audit.py` already does this from the command line).
- Score each site and rank prospects.
- Save results per prospect with notes and contact status.
