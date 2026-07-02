# 🚀 ReconPilot
**Automated Bug Bounty Vulnerability Scanner**

ReconPilot is a high-performance, modular reconnaissance and vulnerability scanning pipeline designed for modern bug bounty hunting. It automates the entire process from subdomain enumeration to final vulnerability reporting, allowing you to focus on manual exploitation.

---

## 🛠 Features
- **Fast & Scalable:** Multi-threaded architecture utilizing `concurrent.futures` and `subprocess` for optimal performance.
- **Automated Pipeline:** 10-phase pipeline: Recon → Crawling → Filtering → Parameter Extraction → Scanning.
- **Smart Filtering:** Automatically removes noise (static files, out-of-scope domains) to reduce false positives.
- **Safe Execution:** Implements secure subprocess handling to prevent command injection vulnerabilities.
- **Structured Reporting:** Generates results in JSON, TXT, and CSV formats for each target.
- **Modularity:** Easy to integrate new tools or adjust configurations.

---

## 📦 Installation (Kali Linux)

**1. Install Required Tools**
```bash
# Required tools
sudo apt update
sudo apt install -y subfinder httpx-toolkit nuclei

# Optional tools (for better coverage)
sudo apt install -y assetfinder
go install -v [github.com/tomnomnom/waybackurls@latest](https://github.com/tomnomnom/waybackurls@latest)
go install -v [github.com/lc/gau/v2/cmd/gau@latest](https://github.com/lc/gau/v2/cmd/gau@latest)
go install -v [github.com/projectdiscovery/katana/cmd/katana@latest](https://github.com/projectdiscovery/katana/cmd/katana@latest)
go install -v [github.com/maurosoria/dirsearch@latest](https://github.com/maurosoria/dirsearch@latest)
```
2. Clone Repository
Bash
```
git clone [https://github.com/n9othing/Scanner.git](https://github.com/n9othing/Scanner.git)
cd Scanner
```
🚀 Usage

Basic Usage
Bash
```
# Single domain
python3 scanner.py example.com
```
```
# Multiple domains
python3 scanner.py example.com test.com api.example.com
```
```
# Domains from a file
python3 scanner.py -l domains.txt
```
Common Flags
Bash
```
# Only crawl, skip vulnerability scanning
python3 scanner.py example.com --crawl-only
```
```
# Skip subdomain enumeration
python3 scanner.py -l alive_hosts.txt --skip-subfinder
```
# High-severity only, fast scan
python3 scanner.py example.com --severity high,critical --concurrency 50
```
# Resume a previously interrupted scan
python3 scanner.py example.com --resume
```
```
# Custom threads and rate limit
python3 scanner.py example.com -t 100 --rate-limit 200
```
# Custom output directory
python3 scanner.py example.com -o /tmp/my_scan
```
Telegram Notifications (Optional)
Bash
```
```
export TELEGRAM_BOT_TOKEN="your-bot-token"
export TELEGRAM_CHAT_ID="your-chat-id"
python3 scanner.py example.com
```
📂 Output Structure
After running, results are saved to output/ directory:
Plaintext
```
output/
  [example.com/](https://example.com/)
      subdomains.txt        ← All discovered subdomains
      alive_subdomains.txt  ← Live hosts only
      all_urls.txt          ← All collected URLs
      filtered_urls.txt     ← Filtered, in-scope URLs
      params.txt            ← URLs with query parameters
      alive_params.txt      ← Verified alive param URLs
      findings.json         ← Vulnerability findings (JSON)
      findings.txt          ← Vulnerability findings (readable)
      findings.csv          ← Vulnerability findings (spreadsheet)
      scanner.log           ← Full debug log
```
🛡 Disclaimer

This tool is for educational purposes and authorized security testing only. The developer is not responsible for any misuse or illegal activities conducted with this scanner. Always ensure you have explicit permission to test a target.
🤝 Contribution

Contributions are welcome! If you find a bug or have a feature request, please open an issue or submit a pull request.

Developed with ❤️ by Hama Dev
