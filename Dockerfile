FROM python:3.12-slim

# Install system deps + Go + Ruby (for WPScan)
RUN apt-get update && apt-get install -y \
    curl wget git nmap masscan unzip python3-pip \
    ruby ruby-dev build-essential libcurl4-openssl-dev libxml2 libxml2-dev \
    libxslt1-dev libffi-dev \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libdrm2 libdbus-1-3 libxkbcommon0 libatspi2.0-0 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 \
    libpango-1.0-0 libcairo2 libx11-6 libx11-xcb1 libxcb1 \
    libxext6 libxshmfence1 libgtk-3-0 fonts-liberation fonts-unifont \
    && rm -rf /var/lib/apt/lists/*

# Install WPScan (WordPress vulnerability scanner)
RUN gem install wpscan --no-document 2>/dev/null || true

# Install Go (for Go security tools)
ENV GO_VERSION=1.22.3
RUN wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz
# IMPORTANT: Go bin MUST come before /usr/local/bin.
# pip installs a Python httpx CLI at /usr/local/bin/httpx which would otherwise
# shadow the ProjectDiscovery httpx scanner at /root/go/bin/httpx.
ENV PATH=/usr/local/go/bin:/root/go/bin:$PATH

# Download wordlists for ffuf/directory fuzzing.
# Using curated lists from SecLists — small enough to keep image lean,
# large enough to catch real findings (admin panels, .env files, backups).
RUN mkdir -p /wordlists && \
    wget -q -O /wordlists/common.txt \
      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" && \
    wget -q -O /wordlists/raft-dirs.txt \
      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" && \
    wget -q -O /wordlists/api-endpoints.txt \
      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt" && \
    wget -q -O /wordlists/subdomains-1m.txt \
      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" && \
    cat /wordlists/common.txt /wordlists/api-endpoints.txt | sort -u > /wordlists/web-combined.txt && \
    wc -l /wordlists/*.txt | tail -1

# Install Go security tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/tomnomnom/anew@latest && \
    go install -v github.com/tomnomnom/gf@latest && \
    go install -v github.com/tomnomnom/qsreplace@latest && \
    go install -v github.com/d3mondev/puredns/v2@latest && \
    go install -v github.com/haccer/subjack@latest && \
    go install -v github.com/zricethezav/gitleaks/v8/cmd/gitleaks@latest && \
    go install -v github.com/infosec-au/altdns@latest 2>/dev/null || true

# Install trufflehog (standalone binary, pinned version)
RUN wget -q -O /tmp/trufflehog.tar.gz \
    "https://github.com/trufflesecurity/trufflehog/releases/download/v3.88.3/trufflehog_3.88.3_linux_amd64.tar.gz" \
    && tar -C /usr/local/bin -xzf /tmp/trufflehog.tar.gz trufflehog \
    && chmod +x /usr/local/bin/trufflehog \
    && rm /tmp/trufflehog.tar.gz

# Install semgrep (Python-based SAST)
RUN pip3 install --no-cache-dir semgrep

# Download nuclei templates to a known path
RUN nuclei -update-templates -silent 2>/dev/null || true && \
    # Ensure templates exist at /root/nuclei-templates (fallback: clone from GitHub)
    (test -d /root/nuclei-templates && echo "Templates OK: $(find /root/nuclei-templates -name '*.yaml' | wc -l) files") || \
    (git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /root/nuclei-templates 2>/dev/null && \
     echo "Templates cloned: $(find /root/nuclei-templates -name '*.yaml' | wc -l) files")

# Install sqlmap (git clone — not on PyPI with full feature set)
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap && \
    chmod +x /opt/sqlmap/sqlmap.py

# Install gf patterns (1ndianl33t's extended collection)
# gf binary is already at /root/go/bin/gf (installed above)
# Patterns live at ~/.gf/ — covers: sqli, xss, ssrf, redirect, lfi, rce, idor, debug
RUN mkdir -p /root/.gf && \
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns 2>/dev/null && \
    cp /tmp/gf-patterns/*.json /root/.gf/ 2>/dev/null || true && \
    rm -rf /tmp/gf-patterns && \
    echo "gf patterns installed: $(ls /root/.gf/*.json 2>/dev/null | wc -l) files"

# Python dependencies
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN python -m playwright install chromium

# Copy backend source
COPY backend/ ./backend/

# Workspace for scan results
RUN mkdir -p /app/workspace

EXPOSE 8000
