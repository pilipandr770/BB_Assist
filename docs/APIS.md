# Free APIs Reference

All APIs used in passive recon. No paid APIs required.

## No API key required

### crt.sh
Certificate transparency logs — best free subdomain source.
```
GET https://crt.sh/?q=%.{domain}&output=json
Parse: response[].name_value (split on \n, strip wildcards)
Rate limit: generous, ~1 req/sec to be polite
```

### Wayback Machine CDX
Historical URL archive.
```
GET http://web.archive.org/cdx/search/cdx
  ?url=*.{domain}/*
  &output=json
  &fl=original
  &collapse=urlkey
  &limit=10000
Rate limit: ~1 req/sec
```

---

## Free tier with API key

### VirusTotal
Passive DNS, subdomain enumeration, URL/domain reputation.
- Free: 500 requests/day, 4/minute
- Sign up: https://www.virustotal.com/gui/join-us
```
GET https://www.virustotal.com/api/v3/domains/{domain}/subdomains
Header: x-apikey: {VIRUSTOTAL_API_KEY}
```

### URLScan.io
Historical scan results, DOM snapshots, tech detection.
- Free: ~100 searches/day
- Sign up: https://urlscan.io/user/signup
```
GET https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100
Header: API-Key: {URLSCAN_API_KEY}
```

### AlienVault OTX
Threat intelligence, passive DNS, malware associations.
- Free: unlimited (with account)
- Sign up: https://otx.alienvault.com/
```
GET https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns
Header: X-OTX-API-KEY: {OTX_API_KEY}
```

### IPInfo.io
IP geolocation, ASN, organization info.
- Free: 50,000 requests/month
- Sign up: https://ipinfo.io/signup (optional for higher limit)
```
GET https://ipinfo.io/{ip}/json
Header (optional): Authorization: Bearer {IPINFO_TOKEN}
```

---

## When to get paid APIs

Once bug bounty income starts:
1. **Shodan** (~$70/year) — best for exposed services, default creds, IoT
2. **SecurityTrails** — richer passive DNS, historical records
3. **Censys** — deep IP/cert scanning

Not needed at start — free APIs cover most recon needs.
