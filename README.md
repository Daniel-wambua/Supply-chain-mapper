<p align="center">
  <img src="banner.svg" alt="Supply Chain Mapper Logo" width="800">
  <h2 align="center">Supply Chain Dependency Vulnerability Mapper</h2>
  <p align="center">
    <i>Secure your supply chain with real-time vulnerability mapping and risk scoring.</i>
  </p>
</p>

---

## 🚀 Overview

**Supply Chain Mapper (S.C.M)** is a production-ready, single-file security tool designed to map project dependencies and identify known vulnerabilities. It provides a comprehensive view of your project's security posture by integrating directly with authoritative vulnerability databases and calculating mathematical risk scores.

### ✨ Key Features
- **🔍 Multi-Ecosystem Extraction**: Native support for Python (`requirements.txt`, `pyproject.toml`), JavaScript (`package.json`), Rust (`Cargo.toml`), Java (`pom.xml`), Go (`go.mod`), and Ruby (`Gemfile`).
- **🛡️ Real-time Security Intelligence**: Direct integration with **OSV.dev** and **NVD API** for live vulnerability lookups and CVSS scoring.
- **🧬 Transitive Dependency Mapping**: Automatically resolves sub-dependencies for Python (PyPI) and JavaScript (npm).
- **📊 Mathematical Risk Scoring**: Advanced scoring engine based on CVSS, vulnerability age, and exploitability ranges.
- **🌐 Interactive Web Dashboard**: Modern, glassmorphism-styled Flask interface with dependency tree visualization.
- **💻 Professional CLI**: Fast, terminal-based scanning with detailed progress tracking and formatted tables.

---

## 🛠️ Installation

S.C.M requires **Python 3.10+** and only three external libraries.

```bash
pip install requests rich flask
```

---

## 📖 Usage

### Web Dashboard Mode
Start the local server and navigate to `http://localhost:5000` to upload and analyze your manifest files.
```bash
python dependency_mapper.py
```

### CLI Mode
Perform high-speed scans directly from your terminal.
```bash
python dependency_mapper.py scan requirements-vulnerable.txt
```

---

## 📈 Real-World Result Example

Below is a live scan output from the included `requirements-vulnerable.txt` test file:

```text
                   Scan Results: requirements-vulnerable.txt                    
┏━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Package   ┃ Version   ┃ Ecosystem ┃ Vulns ┃ Max Score ┃ CVEs      ┃ Status   ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━┩
│ urllib3   │ 2.0.7     │ PyPI      │     5 │      10.0 │ CVE-2023… │ VULNERA… │
│ requests  │ 2.31.0    │ PyPI      │     3 │       8.9 │ CVE-2023… │ VULNERA… │
│ Pillow    │ 10.1.0    │ PyPI      │     4 │       9.1 │ CVE-2023… │ VULNERA… │
│ Django    │ 4.2.7     │ PyPI      │    55 │      10.0 │ CVE-2024… │ VULNERA… │
│ Werkzeug  │ 3.0.1     │ PyPI      │     6 │       8.9 │ CVE-2024… │ VULNERA… │
│ Jinja2    │ 3.1.2     │ PyPI      │     5 │       9.8 │ CVE-2024… │ VULNERA… │
│ numpy     │ 1.24.3    │ PyPI      │     0 │       0.0 │ -         │ CLEAN    │
│ setuptoo… │ 68.0.0    │ PyPI      │     3 │      10.0 │ CVE-2024… │ VULNERA… │
│ idna      │ 3.4       │ PyPI      │     2 │       8.5 │ CVE-2024… │ VULNERA… │
│ certifi   │ 2023.7.22 │ PyPI      │     2 │       8.5 │ CVE-2024… │ VULNERA… │
└───────────┴───────────┴───────────┴───────┴───────────┴───────────┴──────────┘

Summary: 10 dependencies scanned, 9 vulnerabilities found, 5 critical
```

---

## 🏗️ Architecture & Constraints

- **Single-File Power**: The entire engine is contained in [dependency_mapper.py](file:///home/havoc/Documents/S.C.M/dependency_mapper.py).
- **No Database**: Uses high-speed in-memory caching for API responses.
- **Zero Bloat**: No Docker, no configuration files, and no external build tools required.
- **Resilient**: Implements graceful degradation for API timeouts and offline services.

---

## ⚖️ License
This project is open-source and intended for security research and production dependency mapping.
