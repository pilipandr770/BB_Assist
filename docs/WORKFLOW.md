# Workflow — Step by Step

## Full scan lifecycle

```
1. INPUT
   └── User pastes H1 program conditions into UI
       └── POST /api/programs → scope parsed by Claude

2. PLAN
   └── POST /api/programs/{id}/plan
       └── Claude generates ordered tool commands based on scope
       └── Plan shown in UI for review

3. APPROVE
   └── User reviews plan, removes anything they don't want
       └── User clicks "Start scan"
       └── POST /api/scans/start with approved plan

4. PASSIVE RECON (no direct target contact)
   └── crt.sh → subdomains from certificate transparency
   └── Wayback CDX → historical URLs
   └── VirusTotal passive DNS (if key available)
   └── URLScan lookup (if key available)
   └── OTX threat intel (if key available)

5. ACTIVE RECON (light touch on target)
   └── subfinder → more subdomains
   └── dnsx → validate which subdomains resolve
   └── httpx → probe live hosts, gather tech stack
   └── gau → fetch known URLs
   └── katana → crawl live hosts

6. SCANNING (targeted, scope-enforced)
   └── nuclei (curated tags only) → template-based vulns
   └── arjun → hidden parameter discovery
   └── ffuf → directory/endpoint fuzzing on interesting hosts

7. VALIDATION (only on promising findings)
   └── dalfox (if XSS candidates found)
   └── sqlmap --technique=T (if SQLi candidates found)
   └── interactsh (if SSRF/XXE/blind candidates found)

8. THREE-LAYER FILTER
   └── Layer 1: Is it in scope? Is it an excluded type?
   └── Layer 2: Claude assesses: is there real business impact?
   └── Layer 3: Did PoC confirm the finding?
   └── Only findings passing all 3 → report candidates

9. REPORT GENERATION
   └── Claude writes H1-ready markdown report
   └── Saved to workspace/{program}/reports/{finding_id}.md
   └── Shown in UI with copy button

10. MANUAL SUBMISSION
    └── User copies markdown
    └── User opens H1 program → submits report manually
    └── Triager gives feedback on H1 form
```

## What to do with triager feedback

If report is accepted → great, note what worked
If report is rejected with feedback → update finding in tool, adjust filter prompts
If marked "informative" → that finding type should be added to filter exclusions
