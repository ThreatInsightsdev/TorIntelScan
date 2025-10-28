# TorIntelScan
TorIntel Scan - a research-oriented TOR reconnaissance and evidence-capture tool.

Single-file Python scanner and crawler for .onion sites.
Features: page scraping, fingerprinting, header leak detection, SSRF/LFI checks (opt-in), port scanning over Tor, Bitcoin reconnaissance, clearnet enrichment (ASN/WHOIS), mirror/clone detection, evidentiary capture (Playwright + WARC), and crawler/discovery mode.


############
Requirements
############

Python 3.10+ recommended.

Install dependencies (example):

python -m venv .venv
source .venv/bin/activate      # on Windows: .venv\Scripts\activate
pip install -r requirements.txt


######
Usage
#####

Basic single-scan (default output torintel_output.jsonl):

python3 torintel_scan_full.py --url http://exampleonionaddress.onion

Scan + evidence capture (screenshots + DOM; auto case dir):

python3 torintel_scan_full.py \
  --url http://exampleonionaddress.onion \
  --evidence \
  --warc


Enable active SSRF/LFI tests (use with caution, may trigger instability):

python3 torintel_scan_full.py --url http://exampleonionaddress.onion --active-tests


Enable live Bitcoin recon for scraped BTC addresses (public APIs):

python3 torintel_scan_full.py --url http://exampleonionaddress.onion --btc-recon --btc-provider blockstream


Crawl mode (seed file with onion URLs, one per line):

python3 torintel_scan_full.py --crawl --seed-file seeds.txt --max-depth 2 --delay 1.0 --discovered-out discovered_onions.txt


Mirror detection (simhash + favicon) — enable with --mirror-detect and optionally set --index-file to your corpus index path.

Breach/enrichment options:

python3 torintel_scan_full.py --url http://exampleonionaddress.onion --breach-check --hibp-key YOUR_HIBP_KEY --enrich-clearnet --pdns-provider securitytrails --pdns-key YOUR_KEY

CLI Flags (summary)

--url : single .onion URL to scan (required unless using --crawl)

--output : JSONL output file (default torintel_output.jsonl)

--btc-recon : enable BTC live recon via public APIs

--btc-provider : blockstream or sochain (default blockstream)

--btc-cache : path to store BTC cache

--active-tests : enable SSRF/LFI checks (active testing — use with caution)

--crawl : enable crawler/discovery mode

--seed-file : path to newline-separated onion seeds

--max-depth : crawler max depth (default 1)

--delay : seconds between requests (default 1.0)

--discovered-out : file to append newly discovered onion links

--evidence : enable Playwright screenshot/DOM capture

--case-dir : directory for evidence bundle (auto-generated if omitted)

--warc : save WARC (requires warcio)

--enrich-clearnet : run ASN/WHOIS enrichment for clearnet pivots

--pdns-provider : securitytrails (requires API key)

--pdns-key : PDNS API key

--breach-check : lookup scraped emails in HIBP (requires --hibp-key)

--hibp-key : HaveIBeenPwned API key

--mirror-detect : detect clones using simhash + favicon

--index-file : path to corpus index (for mirror detection)


######################
Ethics, legal & safety
######################

Only target systems for which you have explicit permission, or which are permitted for lawful research by your organisation/mandate.

Active testing (SSRF/LFI payloads) can cause harm — use only in controlled/lawful contexts.

Be aware of local laws around accessing, collecting, and storing certain types of content

This tool can produce sensitive intelligence; treat it accordingly.

Respect applicable laws and your organisation’s policies. Evidence capture should follow chain-of-custody requirements if you intend to use it in formal investigations.

####
FAQ
####

Q: Is this tool law-enforcement ready?
A: Short answer is NO - It contains many investigative features (evidence capture, checksums etc ). Law-enforcement agencies often require validated capture tooling and documented procedures. It would need additional hardening, secure storage, and legal review to be used in formal prosecutions.

Q: Can it de-anonymize hidden services?
A: Not magically NO. .onion addresses are self-authenticating identifiers that do not map directly to public IPs. The script looks for operational mistakes (clearnet embeds, IP leaks, misconfigurations, headers like X-Real-IP, etc.) that can provide investigative leads. De-anonymization often requires access to hosting infrastructure, cooperation from Tor nodes or legal processes.

Q: How to find new onion sites without search engines?
A: Scraping public indexes, monitoring forums & paste sites for links, crawling from seed lists, and harvesting leaked indexes. The script’s --crawl plus updated seed lists helps automate discovery.
