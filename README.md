# Footprint

A browser-based OSINT toolkit. The analysis engine is written in Rust and compiled to WebAssembly, so the whole thing is a static site that runs on GitHub Pages with no server, no API keys and no tracking.

**Live site:** `https://perceus64.github.io/osint-toolkit/` (after the first deploy)

## What it does

### A domain
Type a domain and get its public footprint:

- **Security posture** graded A–F: SPF (qualifier, multiple records, 10-lookup limit), DMARC policy and coverage, MTA-STS, CAA and DNSSEC.
- **Services in use**, fingerprinted from SPF includes, MX hosts, name servers and ~30 kinds of ownership-verification TXT tokens (Microsoft 365, Google Workspace, Atlassian, Zoom, Stripe…).
- **Hosting**: every A/AAAA address with reverse DNS and the owning network (ASN, prefix, country) via Team Cymru.
- **Registration** from RDAP: registrar, age, expiry, status locks, with notes for newly registered or unlocked domains.
- **Subdomains** from certificate-transparency logs (crt.sh): deduplicated, first/last seen, wildcard flags, names that look like admin/staging/VPN systems, a live "which still resolve" check and CSV export.

### A file
Drop any file. Nothing is uploaded; the bytes are handed straight to the WebAssembly engine.

- MD5 / SHA-1 / SHA-256 with one-click lookups on VirusTotal and MalwareBazaar.
- Real type from magic bytes, with a warning when the extension lies (`invoice.pdf` that is really an `.exe`).
- Shannon entropy, flagging packed or encrypted content.
- EXIF including GPS coordinates (with a map link), camera serial numbers and edit software.
- PDF info dictionary, incremental-save count, JavaScript/auto-action/attachment flags.
- XMP packets and Office/OpenDocument properties (author, last modified by, company, edit time), macros, external templates, and EXIF hidden in images embedded inside `.docx`.
- URLs, IPs, emails and hashes buried in the file's printable strings.
- **Download copy without metadata** for JPEG and PNG, without re-encoding pixels.

### Some text
Paste a threat report, email headers or logs. Indicators are refanged (`hxxp`, `[.]`, `(dot)`, `[at]`), extracted, deduplicated and grouped: URLs, domains, IPv4/IPv6 (with private/CGNAT/documentation ranges flagged), emails, MD5/SHA-1/SHA-256, CVE IDs. Each gets pivot links, an owner lookup for IPs, defanged copy and CSV export.

## How it works

```
browser (web/app.js)                    Rust → WebAssembly (src/)
─────────────────────                   ─────────────────────────
fetch DNS-over-HTTPS (Google, CF)  ──►  dns.rs    records, SPF/DMARC grading, service fingerprints
fetch RDAP (rdap.org)              ──►  rdap.rs   registrar, dates, locks
fetch crt.sh JSON                  ──►  certs.rs  subdomain inventory
fetch Team Cymru TXT over DoH      ──►  asn.rs    IP → ASN
read dropped file bytes            ──►  meta.rs   hashes, magic, entropy, EXIF, PDF, OOXML, strip
pasted text                        ──►  ioc.rs    refang, extract, classify, defang
```

Every source is keyless and CORS-enabled, which is what lets this live on a static host.

## Develop

```bash
# Rust unit + integration tests (native, no wasm needed)
cargo test

# Inspect a file from the command line with the same engine
cargo run --example inspect -- path/to/photo.jpg

# Build the WebAssembly engine and serve the site
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
wasm-pack build --release --target web --out-dir web/pkg --no-typescript
python3 -m http.server -d web 8080   # then open http://localhost:8080
```

## Deploy to GitHub Pages

1. Push this repo to GitHub (`main` branch).
2. In the repo, open **Settings → Pages** and set **Source** to **GitHub Actions**.
3. Every push to `main` runs the tests, builds the wasm engine and publishes `web/`.

## Use responsibly

Everything here reads public information, but intent matters. Map and assess domains and files you own or are authorised to look at.

## License

MIT
