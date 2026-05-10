FROM python:3.12-slim

# Install system deps + Go
RUN apt-get update && apt-get install -y \
    curl wget git nmap unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Go (for Go security tools)
ENV GO_VERSION=1.22.3
RUN wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

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
    go install -v github.com/tomnomnom/qsreplace@latest

# Download nuclei templates to a known path
RUN nuclei -update-templates -silent 2>/dev/null || true && \
    # Ensure templates exist at /root/nuclei-templates (fallback: clone from GitHub)
    (test -d /root/nuclei-templates && echo "Templates OK: $(find /root/nuclei-templates -name '*.yaml' | wc -l) files") || \
    (git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /root/nuclei-templates 2>/dev/null && \
     echo "Templates cloned: $(find /root/nuclei-templates -name '*.yaml' | wc -l) files")

# Python dependencies
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source
COPY backend/ ./backend/

# Workspace for scan results
RUN mkdir -p /app/workspace

EXPOSE 8000
