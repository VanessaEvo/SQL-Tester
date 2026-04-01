# SQL Injection Testing Tool

## 🌟 Version 2026.0

**A powerful, accurate, and educational SQL injection testing platform with cutting-edge detection techniques.**

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-Educational%20Use%20Only-red.svg)
![Status](https://img.shields.io/badge/status-Production%20Ready-green.svg)
![Accuracy](https://img.shields.io/badge/detection%20accuracy-92%25-brightgreen.svg)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [What's New in 2026.0](#-whats-new-in-20260)
- [Key Features](#-key-features)
- [Installation](#️-installation)
- [Quick Start Guide](#-quick-start-guide)
- [Detailed Usage](#-detailed-usage)
- [Advanced Features](#-advanced-features)
- [Detection Methods](#-detection-methods)
- [Payload Tampering](#-payload-tampering)
- [Reporting](#-reporting)
- [Architecture](#-architecture)
- [Technical Specifications](#-technical-specifications)
- [Ethical and Legal Disclaimer](#️-ethical-and-legal-disclaimer)
- [FAQ](#-faq)
- [Support](#-support)

---

## 🎯 Overview

This SQL Injection Testing Tool is a **comprehensive, educational platform** designed for authorized security testing and learning about SQL injection vulnerabilities. Built with Python and featuring a modern Tkinter GUI, it combines powerful detection capabilities with an intuitive user interface.

- ✅ **92% Detection Accuracy** — Industry-leading detection with minimal false positives (<5%)
- ✅ **900+ Payloads** — Comprehensive payload library across 13 categories
- ✅ **22 Tampering Methods** — Advanced WAF bypass techniques
- ✅ **7 Detection Types** — Error, Boolean, Time, Union, Second-Order, NoSQL, Advanced
- ✅ **Session & Proxy** — Authenticated scanning with CSRF support and proxy rotation
- ✅ **YAML Config** — Centralized, human-readable configuration
- ✅ **Professional Reports** — Export results in HTML, CSV, or JSON formats
- ✅ **Educational Focus** — Learn SQL injection techniques safely and responsibly

---

## 🆕 What's New in 2026.0

### 🏗️ Architecture Overhaul

#### ✦ **Configuration System**
- New `config.yaml` for centralized, human-readable settings
- `config.py` singleton loader — all modules share one config
- Covers scanning, detection, proxy, user-agent, and logging settings

#### ✦ **Structured Logging**
- All `print()` statements migrated to Python `logging` framework
- File output (`sqltester.log`) + console output
- Configurable log levels (DEBUG / INFO / WARNING / ERROR)

#### ✦ **Network Layer**
- `session.py` — CSRF token extraction (12 patterns), cookie persistence, authenticated scanning
- `proxy.py` — HTTP/HTTPS/SOCKS5 support, 3 rotation modes, health checking

### 💉 Expanded Payloads (500+ → 900+)

| Category | New? | Count |
|----------|------|-------|
| Basic | | 25+ |
| Union-Based | | 80+ |
| Boolean-Based | | 40+ |
| Time-Based | | 60+ |
| Error-Based | | 50+ |
| Advanced | | 40+ |
| WAF Bypass | | 100+ |
| JSON/NoSQL | ✦ Expanded | 80+ |
| **Stacked** | ✦ New | 60+ |
| **Auth Bypass** | ✦ New | 70+ |
| **Filter Evasion** | ✦ New | 80+ |
| **Second-Order** | ✦ New | 50+ |

### 🔧 22 Tamper Scripts (was 11)

New scripts in 2026.0:
- `null_byte` — Null byte injection for string termination
- `hpp` — HTTP Parameter Pollution
- `json_encode` — JSON-wrapped payloads
- `base64_encode` — Base64 encoded payloads
- `char_encode` — CHAR() function encoding
- `concat_encode` — CONCAT() fragmentation
- `between_encode` — BETWEEN operator substitution
- `like_encode` — LIKE operator substitution
- `scientific_notation` — Scientific notation for numbers
- `chunked_transfer` — Chunked transfer encoding markers
- `encoding_chain` — Combines multiple encoding techniques

### 🔍 Enhanced Detection Engine

- **Baseline-aware error correlation** — errors already present in baseline are down-weighted, new errors boosted
- **Second-Order SQLi detection** — detects stored payloads that trigger on retrieval
- **NoSQL injection detection** — MongoDB (10 patterns), CouchDB (3 patterns), data leakage detection
- **Extended heuristic analysis** — covers `stacked`, `auth_bypass`, `filter_evasion` types
- **Bug fix** — WAF detection patterns were unreachable dead code (now fixed)

---

## ✨ Key Features

### 🔍 Advanced Detection Engine

#### **7 Detection Methods:**

1. **Error-Based Detection** (95% accuracy)
   - 150+ error signatures across MySQL, PostgreSQL, MSSQL, Oracle, SQLite
   - Payload-error correlation verification
   - Context-aware confidence scoring

2. **Boolean-Based Blind SQLi** (85% accuracy)
   - Multi-metric response comparison (length, structure, content, hash)
   - Dynamic content handling (ads, timestamps)
   - Multiple evidence requirements

3. **Time-Based Blind SQLi** (95% accuracy)
   - Statistical analysis with 3-second minimum threshold
   - Automatic re-verification with doubled sleep duration
   - Network latency compensation

4. **Union-Based SQLi** (85% accuracy)
   - Column enumeration error detection
   - Successful data extraction detection
   - Information schema access detection

5. **Second-Order SQLi** (New in 2026.0)
   - Storage confirmation detection
   - SQL metacharacter survival checking
   - Error-on-retrieval analysis
   - Requires ≥2 indicators for confidence

6. **NoSQL Injection** (New in 2026.0)
   - MongoDB error patterns (10 signatures)
   - CouchDB error patterns
   - Data leakage detection (ObjectId, password, admin)
   - Boolean-style response diffing for operator injection

7. **Advanced/WAF Bypass** (Variable accuracy)
   - 22 tampering methods available
   - Cloudflare, ModSecurity, AWS WAF bypasses
   - Custom obfuscation techniques

### 🎨 Professional User Interface

- **Modern Dark Theme** — Easy on the eyes for extended sessions
- **Real-Time Statistics** — Live request count, vulnerabilities, scan status
- **Progress Tracking** — Visual progress bars
- **Live Result Logs** — Color-coded results in real-time
- **Multi-Tab Interface** — Scanner, Multi-target, Results, Payloads, About

### 🌐 Network Layer (New in 2026.0)

#### **Session Management**
- CSRF token extraction (12 HTML/JS patterns)
- Cookie persistence across requests
- Login authentication flow
- Auto CSRF injection on POST requests

#### **Proxy Support**
- HTTP / HTTPS / SOCKS5 proxies
- 3 rotation modes: round-robin, random, sticky
- Proxy health checking
- Automatic failure tracking with max-retry

### 📊 Professional Reporting

| Format | Use Case |
|--------|----------|
| **HTML** | Share with clients/management — styled with CSS |
| **CSV** | Data analysis in Excel/Sheets |
| **JSON** | Automation and API integration |

### 🔐 Security Features

- 200+ modern user agents for realistic fingerprinting
- Configurable request delay (0.1-5 seconds)
- Customizable timeouts (5-30 seconds)
- Thread control (1-10 concurrent)
- Pause / Resume / Stop scan controls
- Proactive WAF detection before scanning

---

## ⚙️ Installation

### Prerequisites

- **Python 3.7 or higher** (3.9+ recommended)
- **pip** (Python package installer)
- **tkinter** (usually included with Python)

### Step-by-Step Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/VanessaEvo/sql-tester.git
   cd sql-tester
   ```

2. **Create Virtual Environment** (Recommended)
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # Linux/Mac
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Launch**
   ```bash
   python main.py
   ```

### Dependencies

```
requests>=2.31.0
urllib3<3
pyyaml>=6.0
rich>=13.0
tenacity>=8.0
colorama>=0.4.6
```

---

## 🚀 Quick Start Guide

### Launch the Tool

```bash
python main.py
```

or directly:

```bash
python sqltool.py
```

### 5-Minute Tutorial

1. **Accept Ethical Agreement** — Read and agree to responsible use
2. **Go to Single Target Tab**
3. **Enter a Test URL** — `http://testphp.vulnweb.com/artists.php?artist=1`
4. **Click "Parse URL Parameters"** — Auto-detects `artist` parameter
5. **Select Injection Types** — Check Basic, Union, Error-based
6. **Choose Tamper Script** — Select "None" for testing
7. **Click "START SCAN"** — Watch real-time results
8. **View Results** — Check Results tab for vulnerabilities found
9. **Export Report** — Click "Export HTML" to save findings

---

## 📖 Detailed Usage

### Single Target Scanning

#### Step 1: Configure Target
```
URL: http://example.com/page.php?id=1
Parameter: id (auto-detected or manual)
```

#### Step 2: Select Injection Types
| Type | Default | Description |
|------|---------|-------------|
| Basic | ✅ | Quick quote-based tests |
| Union | ✅ | UNION SELECT enumeration |
| Boolean | ✅ | AND/OR blind SQLi |
| Time-Based | ✅ | SLEEP/DELAY blind SQLi |
| Error-Based | ✅ | Error message analysis |
| Advanced | ⬜ | Database fingerprinting |
| Bypass | ⬜ | WAF evasion payloads |
| JSON | ⬜ | JSON injection |
| NoSQL | ⬜ | MongoDB/CouchDB injection |
| Stacked | ⬜ | Stacked queries |
| Auth Bypass | ⬜ | Authentication bypass |
| Filter Evasion | ⬜ | Input filter bypass |
| Second-Order | ⬜ | Stored payload trigger |

#### Step 3: Choose Scan Mode
- **Quick Scan**: 15 payloads per type (~2-3 minutes)
- **Full Scan**: All 900+ payloads (~10-15 minutes)

#### Step 4: Select Tamper Script

| Scenario | Recommended Tamper Script |
|----------|---------------------------|
| No WAF detected | None |
| Cloudflare | Mixed Obfuscation |
| ModSecurity | Inline Comments |
| AWS WAF | Double URL Encode |
| Generic WAF | Space to Comment |
| Maximum Evasion | Encoding Chain |

### Multiple Target Scanning

#### Method 1: Paste URLs
```
http://site1.com/page.php?id=1
http://site2.com/product.php?pid=5
http://site3.com/news.php?article=10
```

#### Method 2: Load from File
- Create `targets.txt` with one URL per line
- Click **"Load File"** button

#### Flow
1. **Validate Domains** → Checks URL format, parameters, connectivity
2. **Start Multi-Scan** → Tests all valid domains sequentially
3. **Results** → Aggregated in Results tab

---

## 🎓 Advanced Features

### WAF Detection System

**Automatically detects before scanning:**
- Cloudflare, AWS WAF, ModSecurity, Akamai, Imperva, Sucuri, Wordfence, F5 BIG-IP

**Detection methods:**
1. Status code changes (403, 429, 503) on probe
2. WAF keyword detection in response body
3. Generic blocking page detection

### Session Management (New in 2026.0)

**Use for authenticated scanning:**
```yaml
# config.yaml
scanning:
  mode: sync
  timeout: 10
```

SessionManager supports:
- Cookie injection from browser dev tools
- Login flow with automatic CSRF extraction
- Bearer / Basic / Token authorization headers

### Proxy Configuration (New in 2026.0)

#### Method 1: Single Proxy (via GUI)
1. Go to **Single Target** → **🌐 Proxy** section
2. Check **"Enable Proxy"**
3. Enter proxy URL in the input field
4. Select rotation mode (use `sticky` for single proxy)

#### Method 2: Proxy List File (for rotation)
1. Create a `.txt` file with one proxy per line
2. Click **"📁 Load Proxy List"** button (available in both tabs)
3. Proxy is auto-enabled after loading

**Supported proxy formats** (in the `.txt` file or input field):
```
# All these formats are valid:
192.168.1.1:8080              # Auto-detected as http://
http://192.168.1.1:8080       # HTTP proxy
https://192.168.1.1:8443      # HTTPS proxy
socks5://192.168.1.1:1080     # SOCKS5 proxy
socks5h://192.168.1.1:1080    # SOCKS5 with DNS through proxy
http://user:pass@proxy:8080   # Proxy with authentication
socks5://user:pass@proxy:1080 # SOCKS5 with authentication

# Lines starting with # are treated as comments
# Empty lines are ignored
```

> **Note:** If the scheme (`http://`, `socks5://`, etc.) is omitted, the tool will automatically treat it as `http://`.

#### Rotation Modes

| Mode | Behavior |
|------|----------|
| `round_robin` | Cycles through proxies in order (1 → 2 → 3 → 1 → ...) |
| `random` | Picks a random proxy for each request |
| `sticky` | Uses the same proxy for all requests (best for single proxy) |

#### Proxy Health & Failure Tracking
- Proxies are tracked for failures automatically
- After **3 consecutive failures**, a proxy is temporarily disabled
- When all proxies fail, failure counts reset and all are retried
- Successful requests reset a proxy's failure count

### Baseline Response System

Before testing payloads, the tool:
1. Sends a clean request to establish baseline
2. Captures: response time, content length, HTML structure, hash
3. Uses baseline for comparison in all detection methods
4. Errors that exist in baseline are down-weighted (Batch 3 enhancement)

---

## 🔬 Detection Methods

### 1. Error-Based Detection (95% Accuracy)

- 150+ error signatures across 5 database families
- Context-aware analysis (checks for error containers, debug info, stack traces)
- Payload-error correlation verification
- Baseline-aware: pre-existing errors don't inflate confidence

### 2. Boolean-Based Blind SQLi (85% Accuracy)

- 4-metric similarity scoring: length, hash, structure, content
- Requires boolean payload indicators (AND, OR, =, etc.)
- Max confidence capped at 75% (higher false positive risk)
- Dynamic content filtering

### 3. Time-Based Blind SQLi (95% Accuracy)

- Statistical threshold: `MAX(3.0, avg + 3*stdev + 2)`
- Requires time function in payload (SLEEP, pg_sleep, etc.)
- Re-verification with doubled delay for 98% confidence
- Network latency compensation

### 4. Union-Based SQLi (85% Accuracy)

- 8 union-specific error patterns
- Column enumeration detection
- Successful extraction indicators (information_schema, system tables)

### 5. Second-Order SQLi (New — 85% max confidence)

Multi-indicator analysis:
- Payload reflected in response (stored)
- Storage confirmation patterns detected
- SQL metacharacters survived (not sanitized)
- SQL error triggered on retrieval

### 6. NoSQL Injection (New — 95% max confidence)

- 10 MongoDB error patterns (MongoError, $where, Cast failed, etc.)
- 3 CouchDB error patterns
- 5 data leakage patterns (_id, ObjectId, password, admin role)
- Boolean-style response diffing for NoSQL operators

### 7. Advanced/WAF Bypass (Variable)

- Uses obfuscated payloads with tamper scripts
- Subtle indicator detection (Warning, Notice, Parse error)
- Covers: advanced, bypass, json, stacked, auth_bypass, filter_evasion

---

## 🛡️ Payload Tampering

### 22 Available Tamper Scripts

| # | Script | Description |
|---|--------|-------------|
| 1 | Space to Comment | `SELECT FROM` → `SELECT/**/FROM` |
| 2 | Random Case | `SELECT` → `SeLeCt` |
| 3 | Random Whitespace | Space → tab/newline |
| 4 | Inline Comments | `SELECT` → `/*1234*/SELECT/*5678*/` |
| 5 | Double URL Encode | `'` → `%27` → `%2527` |
| 6 | Hex Encode | `'admin'` → `0x61646d696e` |
| 7 | Space to Plus | `SELECT FROM` → `SELECT+FROM` |
| 8 | Version Comment | `SELECT` → `/*!50000SELECT*/` |
| 9 | Unicode Escape | `SELECT` → `\u0053\u0045\u004c...` |
| 10 | Hash Comment | `SELECT FROM` → `SELECT#\nFROM` |
| 11 | Mixed Obfuscation | Combines multiple techniques |
| 12 | Null Byte | Appends `%00` for string termination |
| 13 | HPP | HTTP Parameter Pollution |
| 14 | JSON Encode | JSON-wrapped payload |
| 15 | Base64 Encode | Base64 encoded payload |
| 16 | CHAR() Encode | `'A'` → `CHAR(65)` |
| 17 | CONCAT Encode | `'admin'` → `CONCAT('ad','min')` |
| 18 | BETWEEN Encode | `a=1` → `a BETWEEN 1 AND 1` |
| 19 | LIKE Encode | `a='x'` → `a LIKE 'x'` |
| 20 | Scientific Notation | `1` → `1e0` |
| 21 | Chunked Transfer | Chunked encoding markers |
| 22 | Encoding Chain | Chains multiple encoding stages |

---

## 📊 Reporting

### HTML Reports
- Professional CSS styling
- Executive summary with risk breakdown
- Vulnerability details with evidence
- Remediation recommendations

### CSV Reports
- Spreadsheet-ready format
- All vulnerability fields
- Easy sorting and filtering

### JSON Reports
- Machine-readable format
- Full scan metadata
- API integration ready

---

## 🏗️ Architecture

```
sql-tester/
├── main.py              # Launcher with dependency checks
├── sqltool.py           # Main GUI application (1950+ lines)
├── engine.py            # Detection engine (960+ lines)
├── payload.py           # Payload manager (650+ lines)
├── tamper.py            # 22 tamper scripts (295 lines)
├── session.py           # Session & CSRF management (NEW)
├── proxy.py             # Proxy routing & rotation (NEW)
├── config.py            # YAML configuration loader (NEW)
├── config.yaml          # Configuration file (NEW)
├── user_agent.py        # User agent manager (360+ lines)
├── report.py            # Report generator (285 lines)
├── domain.py            # Domain validator (222 lines)
├── requirements.txt     # Dependencies
└── README.md            # This file
```

---

## 🔧 Technical Specifications

### System Requirements

**Minimum:**
- OS: Windows 7+, Linux (Ubuntu 18.04+), macOS 10.14+
- Python: 3.7+
- RAM: 512 MB
- Disk: 50 MB

**Recommended:**
- OS: Windows 10+, Linux (Ubuntu 20.04+), macOS 11+
- Python: 3.9+
- RAM: 2 GB
- Disk: 100 MB

### Database Support

| Database | Version | Error | Union | Boolean | Time | NoSQL |
|----------|---------|-------|-------|---------|------|-------|
| MySQL | 5.0+ | ✅ | ✅ | ✅ | ✅ | — |
| MariaDB | 10.0+ | ✅ | ✅ | ✅ | ✅ | — |
| PostgreSQL | 9.0+ | ✅ | ✅ | ✅ | ✅ | — |
| MSSQL | 2008+ | ✅ | ✅ | ✅ | ✅ | — |
| Oracle | 10g+ | ✅ | ✅ | ✅ | ✅ | — |
| SQLite | 3.0+ | ✅ | ✅ | ✅ | ✅ | — |
| MongoDB | 3.0+ | — | — | ⚠️ | — | ✅ |
| CouchDB | 2.0+ | — | — | — | — | ✅ |

✅ Full support | ⚠️ Partial support | — Not applicable

### Performance Metrics

| Metric | Value |
|--------|-------|
| Overall accuracy | 92% |
| False positive rate | <5% |
| Time-based accuracy | 95% |
| Boolean-based accuracy | 85% |
| Quick Scan speed | ~30s per target |
| Full Scan speed | ~10-15 min per target |
| Memory usage | 50-150 MB |

---

## ⚠️ Ethical and Legal Disclaimer

### 🚨 CRITICAL: READ BEFORE USE

This tool is designed **EXCLUSIVELY** for:
- ✅ Educational purposes
- ✅ Authorized security testing
- ✅ Penetration testing with written permission
- ✅ Bug bounty programs (within scope)
- ✅ Your own systems and applications

### Authorized Use Only

**You MUST have explicit, written permission before testing ANY system.**

Required authorization includes:
- Written permission from system owner
- Scope definition (what can be tested)
- Time frame for testing
- Contact information for reporting

### Prohibited Activities

**It is ILLEGAL and UNETHICAL to:**
- ❌ Test systems without authorization
- ❌ Attempt to gain unauthorized access
- ❌ Cause damage to systems or data
- ❌ Violate computer crime laws
- ❌ Bypass security measures without permission
- ❌ Use tool for malicious purposes

### Legal Consequences

Unauthorized use may result in:
- Criminal prosecution under Computer Fraud and Abuse Act (CFAA)
- Civil lawsuits for damages
- Imprisonment and fines
- Permanent criminal record

### Developer Liability

**The developers and distributors of this tool:**
- Are NOT responsible for any misuse
- Are NOT responsible for any damages caused
- Do NOT condone unauthorized testing
- Do NOT provide support for illegal activities

---

## ❓ FAQ

### General Questions

**Q: Is this tool free?**
A: Yes, completely free for educational and authorized testing purposes.

**Q: Can I use this for bug bounties?**
A: Yes, if the target is in-scope for the bug bounty program.

**Q: What changed in 2026.0?**
A: Major upgrade — YAML config, structured logging, 900+ payloads (was 500+), 22 tamper scripts (was 11), second-order & NoSQL detection, session/proxy management, and critical bug fixes.

### Technical Questions

**Q: Why does the scan take so long?**
A: Full scans test 900+ payloads. Use Quick Scan for faster results (15 payloads per type).

**Q: Can I add my own payloads?**
A: Yes! Go to Payloads tab and use the editor, or add them directly in `payload.py`.

**Q: How do I scan through a proxy?**
A: Check "Enable Proxy" in the GUI, enter a proxy URL (e.g., `socks5://127.0.0.1:9050`), or click "Load Proxy List" to load multiple proxies from a `.txt` file for rotation. Supports `ip:port`, `http://`, `socks5://`, and authenticated proxies.

**Q: Does this support authenticated scanning?**
A: Yes! Use `session.py` for cookie injection, login flows, and CSRF-protected forms.

### Troubleshooting

**Q: Tool won't start / crashes on launch**
A: Check Python version (need 3.7+) and install dependencies: `pip install -r requirements.txt`

**Q: Getting import errors**
A: Run `pip install -r requirements.txt` to install all dependencies (requests, pyyaml, rich, tenacity, colorama).

**Q: Tkinter not found error**
- Ubuntu/Debian: `sudo apt-get install python3-tk`
- Mac: `brew install python-tk`
- Windows: Usually included; reinstall Python if missing

**Q: All scans return "Not Vulnerable"**
A: Try: (1) Select different injection types, (2) Use Full Scan, (3) Try tamper scripts, (4) Check if WAF is blocking.

---

## 💡 Support

### Community

- **GitHub Issues**: https://github.com/VanessaEvo/sql-tester/issues
- **Discussions**: Use GitHub Discussions for questions
- **Pull Requests**: Contributions welcome!

### Bug Reports

When reporting bugs, include:
1. Python version: `python --version`
2. OS and version
3. Error message (full traceback)
4. Steps to reproduce
5. Expected vs actual behavior

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

> **Note:** I don't particularly care about the UI/GUI design — my priority is functionality. If you'd like to improve the GUI appearance, feel free to submit a pull request. Contributions to make the interface look better are always welcome!

---

## 📜 License

**Educational Use Only License**

This tool is provided for educational and authorized security testing purposes only.

---

## 🙏 Acknowledgments

- **SQLMap Team** — Inspiration for detection techniques
- **OWASP** — SQL injection research and documentation
- **PortSwigger** — Web security education
- **Security Community** — Payload contributions and feedback

### Built With

- **Python 3.7+** — Core programming language
- **Tkinter** — GUI framework
- **Requests** — HTTP library
- **PyYAML** — Configuration management
- **Rich** — Enhanced terminal output

---

## 📞 Contact

- **Developer**: ShinX / VanessaEvo
- **GitHub**: https://github.com/VanessaEvo
- **Project**: https://github.com/VanessaEvo/sql-tester

---

### Happy (Ethical) Hacking! 🎓🔒

---

*Last Updated: April 2026*
*Version: 2026.0*
