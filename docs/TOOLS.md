# Tools Reference

## Recon tools

### subfinder
Passive subdomain discovery using multiple sources (DNS records, certificate transparency, public APIs).
```bash
subfinder -d target.com -silent -o subdomains.txt
subfinder -dL domains.txt -silent -o subdomains.txt  # multiple domains
```

### dnsx
DNS validation — filters subdomain list to only those with valid DNS records.
```bash
dnsx -l subdomains.txt -silent -o live_subdomains.txt
```

### httpx
HTTP probing — checks which hosts respond over HTTP/S, collects tech stack info.
```bash
httpx -l live_subdomains.txt -silent -json -o hosts.json \
  -title -tech-detect -status-code -content-length -follow-redirects
```

### gau (getallurls)
Fetches known URLs from Wayback Machine, Common Crawl, OTX, URLScan.
```bash
gau target.com --blacklist png,jpg,gif,css,woff,svg,ico --o urls.txt
```

### katana
Fast web crawler with JavaScript rendering support.
```bash
katana -list live_hosts.txt -silent -jc -o crawled_urls.txt -depth 3
```

### nmap
Port and service detection. Use lightly — only when scope includes IP ranges.
```bash
nmap -sV -p 80,443,8080,8443,8888 target.com -oJ nmap.json
```

---

## Scanning tools

### nuclei ★ (most important)
Template-based vulnerability scanner. 9000+ templates.
Run only high-value tags for bug bounty (skip info/headers noise).
```bash
nuclei -l urls.txt \
  -tags rce,sqli,xss,ssrf,lfi,idor,auth-bypass,exposed-panel,default-creds,exposed-api,token-disclosure,jwt,graphql,xxe,ssti,open-redirect,cve \
  -severity low,medium,high,critical \
  -json -o nuclei.json \
  -silent -rate-limit 20
```

### ffuf
Fast directory/endpoint fuzzing.
```bash
ffuf -u https://target.com/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -mc 200,201,301,302,403 \
  -o ffuf.json -of json \
  -t 50 -rate 50 -silent
```

### arjun
HTTP parameter discovery — finds hidden GET/POST parameters.
```bash
arjun -u https://target.com/api/endpoint -oJ params.json --stable -q
```

---

## Validation tools

### dalfox
XSS scanner — use only on endpoints flagged as XSS candidates.
```bash
dalfox url "https://target.com/search?q=test" --silence --format json -o xss.json
```

### interactsh-client
OOB (Out-of-Band) interaction server for SSRF, XXE, blind injection detection.
```bash
# Start listener, get callback URL
interactsh-client -server oast.pro -token {token}
# Use {random}.oast.pro as the callback URL in payloads
```

### sqlmap
SQL injection detection and extraction. Use carefully — only read-only mode.
```bash
sqlmap -u "https://target.com/search?id=1" \
  --batch --level=1 --risk=1 \
  --technique=T \  # time-based only (safest)
  --output-dir=sqlmap_out
```

---

## Free passive APIs (no tool install needed)

### crt.sh
Certificate transparency subdomain enumeration.
```bash
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

### Wayback CDX
Historical URL discovery.
```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=json&fl=original&collapse=urlkey&limit=10000"
```
