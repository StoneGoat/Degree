# JAWS - Just Another WebScanner

&#x20;

Just Another WebScanner (JAWS) is a proof‑of‑concept framework developed as part of a bachelor’s degree project at Linnaeus University. It automates web vulnerability assessment by chaining traditional scanners (ZAP, Nikto, Nmap) and feeding their output into a cybersecurity‑tuned Large Language Model to generate clear, actionable vulnerability reports tailored to different levels of technical expertise.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
  - [Web Interface](#web-interface)
  - [Command‑Line](#command‑line)
- [Configuration](#configuration)
- [Report Structure](#report-structure)
- [Contributing](#contributing)
- [License](#license)
- [Authors & Acknowledgements](#authors--acknowledgements)

---

## Features

- **Comprehensive Scanning Pipeline**: DNS lookup (pydig), network map (Nmap), web server audit (Nikto), and web app pen‑testing (ZAP).
- **AI‑Enhanced Analysis**: Uses the `Llama-3-WhiteRabbitNeo-8B-v2.0` model (fine‑tuned for DevSecOps) via Hugging Face’s Transformers.
- **Expertise‑Based Reports**: Generates three levels of detail—Manager, Developer, and CyberSec—for tailored remediation guidance.
- **Interactive & Downloadable Reports**: Live Markdown in the UI, plus PDF export with embedded charts (severity distribution, vulnerability trends).
- **Performance Optimizations**: Concurrent scanner execution and grouped LLM prompts reduce end‑to‑end run time (\~17m).

---

## Architecture

1. **DNS & Network Discovery**
   - pydig → A/TXT records
   - Nmap → Open ports, service versions
2. **Web Server Scanning**
   - Nikto → Dangerous files, misconfigurations
3. **Web App Scanning**
   - ZAP (via API) → Passive & active vulnerability detection
4. **Data Aggregation**
   - XML normalization (`xml.etree.ElementTree`, `xml.dom.minidom`)
5. **LLM Analysis**
   - FastAPI service + Transformers
   - Structured prompts → Markdown output → Regex→ JSON
6. **Reporting**
   - Markdown in UI
   - PDF conversion (`markdown-pdf`) + Matplotlib charts

---

## Installation

```bash
git clone git@github.com:StoneGoat/jaws.git
cd jaws
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```


---

## Usage

### Web Interface

1. Set up AI API using this guide: https://huggingface.co/docs/transformers/en/quicktour 
2. Run zap-proxy and LLM API, add API to .env file
##### Example .env
ZAP_API_KEY = '*key*'  
ZAP_PROXY = 'http://localhost:8080'   
RESULTS_DIR = 'scan_results'    
GRAPHS_OUTPUT_DPI = 75    
STATUS_FILENAME = 'status.md'    
VULNERABILITY_FILENAME = 'vulnerability.md'   
CHAT_API_URL = "http://127.0.0.1:9000/chat"

3. Run frontend.py in terminal
4. Open `http://localhost:5000`, enter a target URL, choose an expertise level, and submit.
---

## Report Structure

Every generated report includes:

- **Executive Summary**: High‑level risk overview, business impact.
- **Visualizations**: Severity breakdown, vulnerability trend charts, category pie charts.
- **Technical Findings**: Issue descriptions, code snippets, example fixes.
- **Deep Dive** (CyberSec): Exploit paths, CVE references, security best practices.
---

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0). See [LICENSE](LICENSE) for details.

---

## Authors & Acknowledgements

- **Casper Andersson**
- **Noah Smedberg**


*Developed as part of the 2DV50E Bachelor Degree Project in Network Security, Linnaeus University (VT25).*

