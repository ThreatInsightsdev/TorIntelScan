# TorIntelScan

pip install -r requirements.txt
python -m spacy download en_core_web_sm
playwright install




python3 torscanner1.py --url address.onion --enrich-clearnet  --mirror-detect --index-file corpus_index.json  --output torintel_output.jsonl  --evidence --case-dir case_example --warc  --queue-wait 300 --queue-log queue_log.jsonl  --wait-selector "main,#content" --max-wait 300 --timeline --snapshot-every 10



Notes:

--wait-selector "main,#content" accepts CSS selectors (comma-separated); the script will wait for any selector to appear (via Playwright) or for wait-keywords to match page content.

--max-wait is in seconds (so --max-wait 300 = 300 seconds = 5 minutes).

--queue-wait is included for compatibility but --max-wait is what governs maximum waiting time.

Playwright is optional. If not installed, screenshot/DOM capture will be skipped gracefully.

Make sure Tor is running locally and reachable at 127.0.0.1:9050. For NEWNYM support you need Tor control auth (and stem).


# FAQ


Q: Is this tool law-enforcement ready?
A: Short answer is NO - It contains many investigative features (evidence capture, checksums etc ). Law-enforcement agencies often require validated capture tooling and documented procedures. It would need additional hardening, secure storage, and legal review to be used in formal prosecutions.

Q: Can it de-anonymize hidden services?
A: Not magically NO. .onion addresses are self-authenticating identifiers that do not map directly to public IPs. The script looks for operational mistakes (clearnet embeds, IP leaks, misconfigurations, headers like X-Real-IP, etc.) that can provide investigative leads. De-anonymization often requires access to hosting infrastructure, cooperation from Tor nodes or legal processes.

Q: How to find new onion sites without search engines?
A: Scraping public indexes, monitoring forums & paste sites for links, crawling from seed lists, and harvesting leaked indexes. The script’s --crawl plus updated seed lists helps automate discovery.


A few things left to do. Probably a URL diretory scanner needs implementing, some node/graph analysis and a database would be a good idea. 
