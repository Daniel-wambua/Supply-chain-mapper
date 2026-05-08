import os
import sys
import re
import json
import time
import csv
import io
import uuid
import requests
from flask import Flask, request, jsonify, render_template_string, send_file
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from xml.etree import ElementTree

app = Flask(__name__)
console = Console()
SCANS = {}

class DependencyExtractor:
    @staticmethod
    def parse_requirements(content):
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'): continue
            match = re.match(r'^([a-zA-Z0-9\-_]+)([=<>!~]+[0-9.a-zA-Z\-_*, ]+)?', line)
            if match:
                name, version = match.groups()
                deps.append({"ecosystem": "PyPI", "name": name, "version": (version or "*").strip("=<>!~ "), "source": "requirements.txt"})
        return deps

    @staticmethod
    def parse_pyproject(content):
        deps = []
        try:
            # Simple regex to find dependencies in [project.dependencies] section
            match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if match:
                items = re.findall(r'"([a-zA-Z0-9\-_]+)([=<>!~]+[0-9.a-zA-Z\-_*, ]+)?"', match.group(1))
                for name, version in items:
                    deps.append({"ecosystem": "PyPI", "name": name, "version": (version or "*").strip("=<>!~ "), "source": "pyproject.toml"})
        except Exception: pass
        return deps

    @staticmethod
    def parse_package_json(content):
        deps = []
        try:
            data = json.loads(content)
            for key in ["dependencies", "devDependencies"]:
                for name, version in data.get(key, {}).items():
                    deps.append({"ecosystem": "npm", "name": name, "version": version.strip("^~>=< "), "source": "package.json"})
        except Exception: pass
        return deps

    @staticmethod
    def parse_cargo(content):
        deps = []
        try:
            match = re.search(r'\[dependencies\](.*?)(?=\n\[|\Z)', content, re.DOTALL)
            if match:
                items = re.findall(r'^([a-zA-Z0-9\-_]+)\s*=\s*["{]([^"}]*)["}]', match.group(1), re.MULTILINE)
                for name, version in items:
                    v = version if '"' not in version else re.search(r'version\s*=\s*"([^"]+)"', version).group(1)
                    deps.append({"ecosystem": "crates.io", "name": name, "version": v.strip("^~>=< "), "source": "Cargo.toml"})
        except Exception: pass
        return deps

    @staticmethod
    def parse_pom(content):
        deps = []
        try:
            root = ElementTree.fromstring(content)
            ns = {"ns": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
            for dep in root.findall(".//ns:dependency" if ns else ".//dependency", ns):
                name = dep.find("ns:artifactId" if ns else "artifactId", ns).text
                version = dep.find("ns:version" if ns else "version", ns)
                deps.append({"ecosystem": "Maven", "name": name, "version": (version.text if version is not None else "*"), "source": "pom.xml"})
        except Exception: pass
        return deps

    @staticmethod
    def parse_gomod(content):
        deps = []
        try:
            match = re.search(r'require\s*\((.*?)\)', content, re.DOTALL)
            if match:
                items = re.findall(r'([^\s]+)\s+([^\s]+)', match.group(1))
                for name, version in items:
                    deps.append({"ecosystem": "Go", "name": name, "version": version.strip(), "source": "go.mod"})
        except Exception: pass
        return deps

    @staticmethod
    def parse_gemfile(content):
        deps = []
        for line in content.splitlines():
            match = re.match(r'gem\s+[\'"]([^\'"]+)[\'"](?:\s*,\s*[\'"]([^\'"]+)[\'"])?', line.strip())
            if match:
                name, version = match.groups()
                deps.append({"ecosystem": "RubyGems", "name": name, "version": (version or "*").strip("~>=< "), "source": "Gemfile"})
        return deps

    @classmethod
    def extract(cls, filename, content):
        fn = filename.lower()
        if "requirements" in fn: return cls.parse_requirements(content)
        if "pyproject" in fn: return cls.parse_pyproject(content)
        if "package" in fn and ".json" in fn: return cls.parse_package_json(content)
        if "cargo" in fn: return cls.parse_cargo(content)
        if "pom" in fn: return cls.parse_pom(content)
        if "go.mod" in fn: return cls.parse_gomod(content)
        if "gemfile" in fn: return cls.parse_gemfile(content)
        return []

class OSVClient:
    def __init__(self):
        self.cache = {}
        self.last_req = 0

    def query(self, name, version, ecosystem):
        key = f"{ecosystem}:{name}@{version}"
        if key in self.cache: return self.cache[key]
        
        elapsed = time.time() - self.last_req
        if elapsed < 1.0: time.sleep(1.0 - elapsed)
        
        payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        if version == "*": del payload["version"]
        
        try:
            resp = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=10)
            self.last_req = time.time()
            if resp.status_code != 200: return "API_UNREACHABLE"
            data = resp.json().get("vulns", [])
            for v in data:
                cves = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
                if not cves:
                    for ref in v.get("references", []):
                        m = re.search(r'CVE-\d{4}-\d+', ref["url"])
                        if m: cves.append(m.group(0))
                
                v["cve_ids"] = list(set(cves))
                v["primary_cve"] = v["cve_ids"][0] if v["cve_ids"] else None
                
                if v["primary_cve"]:
                    v["cvss"] = self.get_nvd_score(v["primary_cve"])
                
                # Fallback to OSV's own CVSS if NVD fails
                if not v.get("cvss"):
                    # Check database_specific for cvss score
                    db_spec = v.get("database_specific", {})
                    if db_spec and "cvss" in db_spec:
                        v["cvss"] = db_spec["cvss"].get("score")
                    
                    # If still not found, check severity list
                    if not v.get("cvss") and v.get("severity"):
                        for sev in v["severity"]:
                            if sev["type"] in ["CVSS_V3", "CVSS_V2"]:
                                m = re.search(r'([0-9]\.[0-9])', sev["score"])
                                if m: v["cvss"] = float(m.group(1))
            self.cache[key] = data
            return data
        except requests.exceptions.Timeout: return "API_TIMEOUT"
        except ValueError: return "PARSE_ERROR"
        except Exception: return "API_UNREACHABLE"

    def get_nvd_score(self, cve_id):
        try:
            resp = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}", timeout=10)
            data = resp.json()
            metrics = data["vulnerabilities"][0]["cve"]["metrics"]
            v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
            return v3[0]["cvssData"]["baseScore"] if v3 else None
        except Exception: return None

    def get_transitive(self, name, version, ecosystem):
        deps = []
        try:
            if ecosystem == "PyPI":
                resp = requests.get(f"https://pypi.org/pypi/{name}/{version}/json", timeout=10)
                reqs = resp.json().get("info", {}).get("requires_dist", [])
                for r in (reqs or []):
                    m = re.match(r'^([a-zA-Z0-9\-_]+)', r)
                    if m: deps.append({"name": m.group(1), "version": "*", "ecosystem": "PyPI"})
            elif ecosystem == "npm":
                resp = requests.get(f"https://registry.npmjs.org/{name}/{version}", timeout=10)
                for n, v in resp.json().get("dependencies", {}).items():
                    deps.append({"name": n, "version": v.strip("^~>=< "), "ecosystem": "npm"})
        except Exception: pass
        return deps

class RiskEngine:
    @staticmethod
    def calculate(vuln):
        base = vuln.get("cvss") or 5.0
        pub_date = vuln.get("published", "2000-01-01T00:00:00Z")[:10]
        try:
            pub_ts = time.mktime(time.strptime(pub_date, "%Y-%m-%d"))
        except Exception:
            pub_ts = time.time() - (5 * 365 * 24 * 3600) # Default to 5 years if parse fails
            
        years_ago = (time.time() - pub_ts) / (365 * 24 * 3600)
        age_mult = 0.7 if years_ago > 5 else (1.5 if years_ago < 1 else 1.0)
        
        exploit = 0
        for affected in vuln.get("affected", []):
            for range_ in affected.get("ranges", []):
                if range_.get("type") in ["ECOSYSTEM", "GIT"]: exploit = 1.0
        
        score = min(10.0, base * age_mult + exploit)
        severity = "Low" if score < 4.0 else ("Medium" if score < 7.0 else ("High" if score < 9.0 else "Critical"))
        return round(score, 1), severity

class ReportGenerator:
    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Supply Chain Dependency Map</title>
    <style>
        :root { --bg: #0f172a; --fg: #e2e8f0; --crit: #ef4444; --high: #f97316; --med: #eab308; --low: #22c55e; }
        body { background: var(--bg); color: var(--fg); font-family: sans-serif; margin: 0; padding: 20px; line-height: 1.5; }
        .container { max-width: 1200px; margin: 0 auto; width: 100%; }
        .card { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); border-radius: 1rem; padding: 1.5rem; margin-bottom: 2rem; overflow-x: auto; }
        h1 { background: linear-gradient(to right, #6366f1, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-size: 2.5rem; margin-bottom: 2rem; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; min-width: 600px; }
        th, td { text-align: left; padding: 1rem; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .pkg-name { font-family: 'Courier New', monospace; font-weight: bold; }
        .sev-Critical { color: var(--crit); } .sev-High { color: var(--high); } .sev-Medium { color: var(--med); } .sev-Low { color: var(--low); }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.85); z-index: 100; }
        .modal-content { background: var(--bg); margin: 5% auto; padding: 2rem; border-radius: 1rem; width: 90%; max-width: 800px; border: 1px solid #6366f1; box-shadow: 0 0 30px rgba(99, 102, 241, 0.3); }
        .btn { background: #6366f1; color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 0.5rem; cursor: pointer; text-decoration: none; display: inline-block; font-weight: bold; transition: opacity 0.2s; }
        .btn:hover { opacity: 0.9; }
        .tree ul { list-style-type: none; padding-left: 1.5rem; }
        .tree li { position: relative; padding: 0.4rem 0; border-left: 1px solid #475569; padding-left: 1rem; }
        .tree li::before { content: ""; position: absolute; left: 0; top: 1.2rem; width: 0.8rem; border-top: 1px solid #475569; }
        @media (max-width: 768px) { body { padding: 10px; } .card { padding: 1rem; } h1 { font-size: 1.8rem; } }
    </style>
</head>
<body>
    <div class="container">
        <h1>Dependency Map Report</h1>
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
                <h2>Summary: {{ summary.total }} Dependencies, {{ summary.vulns }} Vulnerable</h2>
                <a href="/export/{{ scan_id }}" class="btn">Export CSV</a>
            </div>
            <table>
                <thead>
                    <tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Score</th><th>Severity</th><th>Action</th></tr>
                </thead>
                <tbody>
                    {% for dep in results %}
                    <tr>
                        <td class="pkg-name">{{ dep.name }}</td>
                        <td>{{ dep.version }}</td>
                        <td>{{ dep.ecosystem }}</td>
                        <td class="sev-{{ dep.max_severity }}">{{ dep.max_score }}</td>
                        <td class="sev-{{ dep.max_severity }}">{{ dep.max_severity }}</td>
                        <td>
                            {% if dep.vulnerabilities == "API_UNREACHABLE" %} <span style="color: #94a3b8">API Offline</span>
                            {% elif dep.vulnerabilities == "API_TIMEOUT" %} <span style="color: #94a3b8">Timeout</span>
                            {% elif dep.vulnerabilities %} <button class="btn" onclick="showVulns('{{ loop.index }}')">View CVEs</button>
                            {% else %} <span style="color: var(--low)">Clean</span> {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% if not results %}
            <p style="text-align: center; padding: 2rem;">No dependencies found in file.</p>
            {% endif %}
        </div>
        <div class="card tree">
            <h2>Dependency Tree</h2>
            <ul>
                {% for dep in results %}
                <li>
                    <strong>{{ dep.name }}@{{ dep.version }}</strong>
                    {% if dep.transitive %}
                    <ul>
                        {% for t in dep.transitive %}
                        <li>{{ t.name }}@{{ t.version }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                </li>
                {% endfor %}
            </ul>
        </div>
    </div>
    {% for dep in results %}
    {% if dep.vulnerabilities and dep.vulnerabilities is iterable %}
    <div id="modal-{{ loop.index }}" class="modal" onclick="hideModal('modal-{{ loop.index }}')">
        <div class="modal-content" onclick="event.stopPropagation()">
            <h3>Vulnerabilities for {{ dep.name }}</h3>
            <div style="max-height: 60vh; overflow-y: auto; margin-bottom: 1.5rem;">
                {% for v in dep.vulnerabilities %}
                <div style="margin-bottom: 1.5rem; border-bottom: 1px solid #334155; padding-bottom: 1rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <strong style="font-size: 1.1rem; color: #6366f1;">
                        {{ v.primary_cve or v.id }}
                        {% if v.cve_ids|length > 1 %}
                        <span style="font-size: 0.8rem; color: #94a3b8; font-weight: normal;">(Also: {{ v.cve_ids[1:]|join(', ') }})</span>
                        {% endif %}
                    </strong>
                    <span class="sev-{{ v.severity }}" style="font-weight: bold;">{{ v.score }} ({{ v.severity }})</span>
                </div>
                <p style="margin: 0; color: #cbd5e1; font-size: 0.95rem;">{{ v.summary[:200] }}{% if v.summary|length > 200 %}...{% endif %}</p>
                <p style="font-size: 0.8rem; color: #94a3b8; margin-top: 0.5rem;">Published: {{ v.published[:10] }}</p>
            </div>
                {% endfor %}
            </div>
            <button class="btn" onclick="hideModal('modal-{{ loop.index }}')">Close</button>
        </div>
    </div>
    {% endif %}
    {% endfor %}
    <script>
        function showVulns(id) { document.getElementById('modal-' + id).style.display = 'block'; }
        function hideModal(id) { document.getElementById(id).style.display = 'none'; }
        document.addEventListener('keydown', (e) => { if (e.key === "Escape") { document.querySelectorAll('.modal').forEach(m => m.style.display = 'none'); } });
    </script>
</body>
</html>
"""

    @staticmethod
    def generate_csv(results):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Package", "Version", "Ecosystem", "Max Score", "Severity", "CVE IDs"])
        for d in results:
            all_cves = []
            if isinstance(d["vulnerabilities"], list):
                for v in d["vulnerabilities"]:
                    all_cves.extend(v.get("cve_ids", [v["id"]]))
            writer.writerow([d["name"], d["version"], d["ecosystem"], d["max_score"], d["max_severity"], ", ".join(list(set(all_cves)))])
        return output.getvalue()

def perform_scan(filename, content):
    extractor = DependencyExtractor()
    osv = OSVClient()
    engine = RiskEngine()
    
    deps = extractor.extract(filename, content)
    results = []
    summary = {"total": 0, "vulns": 0, "critical": 0}
    
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
    ) as progress:
        task = progress.add_task("[cyan]Scanning dependencies...", total=len(deps)) if __name__ == "__main__" and len(sys.argv) > 1 else None
        
        for d in deps:
            summary["total"] += 1
            vulns = osv.query(d["name"], d["version"], d["ecosystem"])
            processed_vulns = []
            max_score = 0.0
            max_sev = "Low"
            
            if isinstance(vulns, list):
                for v in vulns:
                    score, sev = engine.calculate(v)
                    v["score"] = score
                    v["severity"] = sev
                    processed_vulns.append(v)
                    if score > max_score:
                        max_score = score
                        max_sev = sev
                if processed_vulns: summary["vulns"] += 1
                if max_sev == "Critical": summary["critical"] += 1
            
            transitive = osv.get_transitive(d["name"], d["version"], d["ecosystem"])
            results.append({**d, "vulnerabilities": processed_vulns, "max_score": max_score, "max_severity": max_sev, "transitive": transitive})
            if task: progress.update(task, advance=1)
            
    return results, summary

@app.route("/", methods=["GET"])
def index():
    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>Supply Chain Mapper</title>
    <style>
        body { background: #0f172a; color: #e2e8f0; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .upload-card { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); padding: 3rem; border-radius: 1.5rem; border: 1px solid #6366f1; text-align: center; width: 90%; max-width: 500px; }
        input[type="file"] { margin: 1.5rem 0; color: #94a3b8; }
        .btn { background: linear-gradient(to right, #6366f1, #8b5cf6); color: white; border: none; padding: 0.75rem 2rem; border-radius: 0.5rem; cursor: pointer; font-weight: bold; width: 100%; }
        .progress-container { display: none; margin-top: 1.5rem; text-align: left; }
        .progress-bar-bg { background: rgba(255,255,255,0.1); border-radius: 1rem; height: 10px; width: 100%; margin: 0.5rem 0; overflow: hidden; }
        .progress-bar-fill { background: linear-gradient(to right, #6366f1, #8b5cf6); height: 100%; width: 0%; transition: width 0.3s ease; }
        .status-text { color: #6366f1; font-weight: bold; font-size: 0.9rem; display: flex; justify-content: space-between; }
    </style>
</head>
<body>
    <div class="upload-card">
        <h1 style="background: linear-gradient(to right, #6366f1, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Dependency Scanner</h1>
        <p>Upload a manifest file to start mapping</p>
        <form id="uploadForm">
            <input type="file" name="file" id="fileInput" required><br>
            <button type="submit" class="btn" id="submitBtn">Analyze Project</button>
        </form>
        <div id="progressContainer" class="progress-container">
            <div class="status-text">
                <span id="statusMsg">Scanning dependencies...</span>
                <span id="percentText">0%</span>
            </div>
            <div class="progress-bar-bg">
                <div id="progressBar" class="progress-bar-fill"></div>
            </div>
        </div>
    </div>
    <script>
        document.getElementById('uploadForm').onsubmit = async (e) => {
            e.preventDefault();
            const btn = document.getElementById('submitBtn');
            const container = document.getElementById('progressContainer');
            const bar = document.getElementById('progressBar');
            const percent = document.getElementById('percentText');
            
            btn.disabled = true;
            container.style.display = 'block';
            
            // Simulating real progress for better UX since backend is sync
            let currentProgress = 0;
            const interval = setInterval(() => {
                if (currentProgress < 90) {
                    currentProgress += Math.random() * 5;
                    bar.style.width = Math.min(currentProgress, 90) + '%';
                    percent.innerText = Math.floor(Math.min(currentProgress, 90)) + '%';
                }
            }, 800);
            
            const formData = new FormData();
            formData.append('file', document.getElementById('fileInput').files[0]);
            
            try {
                const resp = await fetch('/scan', { method: 'POST', body: formData });
                const data = await resp.json();
                clearInterval(interval);
                bar.style.width = '100%';
                percent.innerText = '100%';
                
                if (data.redirect) setTimeout(() => window.location.href = data.redirect, 500);
                else alert(data.error || 'Scan failed');
            } catch (err) { 
                clearInterval(interval);
                alert('Connection error'); 
            } finally { 
                btn.disabled = false; 
            }
        };
    </script>
</body>
</html>
""")

@app.route("/scan", methods=["POST"])
def scan():
    if 'file' not in request.files: return jsonify({"error": "No file"}), 400
    f = request.files['file']
    if not f.filename: return jsonify({"error": "No filename"}), 400
    
    content = f.read().decode("utf-8")
    results, summary = perform_scan(f.filename, content)
    
    if not results:
        return jsonify({"error": "Unsupported format or empty file", "supported": ["requirements.txt", "package.json", "Cargo.toml", "pom.xml", "go.mod", "Gemfile"]}), 400

    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = {"results": results, "summary": summary}
    return jsonify({"scan_id": scan_id, "redirect": f"/report/{scan_id}"})

@app.route("/report/<scan_id>")
def report(scan_id):
    data = SCANS.get(scan_id)
    if not data: return "Scan not found", 404
    return render_template_string(ReportGenerator.HTML_TEMPLATE, **data, scan_id=scan_id)

@app.route("/export/<scan_id>")
def export(scan_id):
    data = SCANS.get(scan_id)
    if not data: return "Scan not found", 404
    csv_data = ReportGenerator.generate_csv(data["results"])
    return send_file(io.BytesIO(csv_data.encode()), mimetype="text/csv", as_attachment=True, download_name=f"scan_{scan_id}.csv")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "scan":
        if len(sys.argv) < 3:
            console.print("[red]Usage: python dependency_mapper.py scan <file>[/red]")
            sys.exit(1)
        path = sys.argv[2]
        if not os.path.exists(path):
            console.print(f"[red]File not found: {path}[/red]")
            sys.exit(1)
        with open(path, "r") as f:
            results, summary = perform_scan(os.path.basename(path), f.read())
        
        table = Table(title=f"Scan Results: {path}")
        table.add_column("Package", style="cyan")
        table.add_column("Version")
        table.add_column("Ecosystem")
        table.add_column("Vulns", justify="right")
        table.add_column("Max Score", justify="right")
        table.add_column("CVEs")
        table.add_column("Status")
        
        for d in results:
            v_count = len(d["vulnerabilities"]) if isinstance(d["vulnerabilities"], list) else 0
            all_cves = []
            if isinstance(d["vulnerabilities"], list):
                for v in d["vulnerabilities"]:
                    all_cves.extend(v.get("cve_ids", [v["id"]]))
            cve_str = ", ".join(list(set(all_cves))[:3])
            if len(set(all_cves)) > 3: cve_str += "..."
            
            status = "[red]VULNERABLE[/red]" if v_count > 0 else "[green]CLEAN[/green]"
            table.add_row(d["name"], d["version"], d["ecosystem"], str(v_count), str(d["max_score"]), cve_str or "-", status)
        
        console.print(table)
        console.print(f"\n[bold]Summary:[/bold] {summary['total']} dependencies scanned, {summary['vulns']} vulnerabilities found, {summary['critical']} critical")
    else:
        app.run(host="0.0.0.0", port=5000, debug=True)
