import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import datetime
class VulnScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Web Vulnerability Scanner")
        self.root.geometry("850x700")
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.payloads = {
            "SQL Injection": ["' OR 1=1 --", "' OR '1'='1", "admin' --"],
            "XSS": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        }
        self.security_headers = {
            "X-Frame-Options": {
                "severity": "MEDIUM",
                "cwe": "CWE-1021",
                "impact": "Clickjacking attacks. Attackers can embed your site in an iframe and trick users into clicking hidden buttons.",
                "fix": "Add header: X-Frame-Options: DENY or SAMEORIGIN"
            },
            "Content-Security-Policy": {
                "severity": "HIGH",
                "cwe": "CWE-79",
                "impact": "Cross-Site Scripting (XSS) and data injection attacks.",
                "fix": "Implement a strict Content-Security-Policy header."
            },
            "Strict-Transport-Security": {
                "severity": "MEDIUM",
                "cwe": "CWE-319",
                "impact": "Man-in-the-Middle (MitM) attacks and SSL stripping.",
                "fix": "Add header: Strict-Transport-Security: max-age=31536000"
            },
            "X-Content-Type-Options": {
                "severity": "LOW",
                "cwe": "CWE-16",
                "impact": "MIME-sniffing attacks where the browser interprets files incorrectly.",
                "fix": "Add header: X-Content-Type-Options: nosniff"
            }
        }
        self.findings = [] 
        self.setup_ui()
    def setup_ui(self):
        header_frame = tk.Frame(self.root, bg="#2c3e50", pady=10)
        header_frame.pack(fill=tk.X)
        tk.Label(header_frame, text="Advanced Web Vulnerability Scanner", 
                 font=("Arial", 16, "bold"), bg="#2c3e50", fg="white").pack()
        input_frame = tk.Frame(self.root, pady=10)
        input_frame.pack(fill=tk.X, padx=10)
        tk.Label(input_frame, text="Target URL:", font=("Arial", 10)).pack(side=tk.LEFT)
        self.url_entry = tk.Entry(input_frame, width=45, font=("Arial", 10))
        self.url_entry.pack(side=tk.LEFT, padx=5)
        self.scan_btn = tk.Button(input_frame, text="Start Scan", 
                                  bg="#3498db", fg="white", font=("Arial", 10, "bold"),
                                  command=self.start_scan_thread)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        self.export_btn = tk.Button(input_frame, text="Export Report", 
                                    bg="#27ae60", fg="white", font=("Arial", 10, "bold"),
                                    command=self.export_report, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, length=800, mode='indeterminate')
        self.progress.pack(pady=5)
        tk.Label(self.root, text="Detailed Scan Results:", font=("Arial", 10, "bold"), anchor="w").pack(fill=tk.X, padx=10)
        self.log_area = scrolledtext.ScrolledText(self.root, width=100, height=30, font=("Consolas", 9))
        self.log_area.pack(padx=10, pady=5)
        self.log_area.config(state=tk.DISABLED)
    def log(self, message):
        self.root.after(0, lambda: self._insert_log(message))
    def _insert_log(self, message):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)
    def start_scan_thread(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        self.scan_btn.config(state=tk.DISABLED)
        self.export_btn.config(state=tk.DISABLED)
        self.progress.start()
        self.log_area.config(state=tk.NORMAL)
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state=tk.DISABLED)
        self.findings = [] 
        threading.Thread(target=self.scan_website, args=(url,), daemon=True).start()
    def scan_website(self, url):
        self.log(f"[*] Starting scan on: {url}")
        self.log(f"[*] Scan Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if not url.startswith("http"):
            url = "http://" + url
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            self.log(f"[+] Target is reachable. Status Code: {response.status_code}")
        except Exception as e:
            self.log(f"[-] Failed to connect to {url}. Error: {e}")
            self.finish_scan()
            return
        self.check_headers(response, url)
        self.log("\n[*] Extracting forms...")
        forms = self.get_forms(url)
        self.log(f"[+] Found {len(forms)} form(s).")
        if len(forms) == 0:
            self.log("[!] No forms found. Scanning URL parameters instead.")
            self.scan_url_parameters(url, response)
            self.finish_scan()
            return
        for i, form in enumerate(forms):
            self.log(f"\n[*] Testing Form #{i+1}")
            action = form.get("action")
            method = form.get("method", "get").upper()
            self.log(f"  Form Action: {action} | Method: {method}")
            for vuln_type, payload_list in self.payloads.items():
                for payload in payload_list:
                    self.log(f"  [>] Testing {vuln_type} payload: {payload[:20]}...")
                    res = self.submit_form(form, url, payload)
                    if res is None:
                        continue
                    if vuln_type == "SQL Injection":
                        sql_errors = ["sql syntax", "mysql_fetch", "ora-", "sqlite3", "postgresql", "mysql"]
                        if any(error in res.text.lower() for error in sql_errors):
                            self.report_vulnerability("SQL Injection", "CRITICAL", "CWE-89", 
                                url, action, payload, 
                                "Database errors were detected in the response. This indicates the input is being concatenated directly into SQL queries.",
                                "Attackers can bypass authentication, steal, modify, or delete sensitive data from the database.",
                                "Use Prepared Statements (Parameterized Queries). Never concatenate user input directly into SQL strings.")  
                    elif vuln_type == "XSS":
                        if payload in res.text:
                            self.report_vulnerability("Reflected Cross-Site Scripting (XSS)", "HIGH", "CWE-79",
                                url, action, payload,
                                "The injected payload was reflected back in the HTML response without sanitization.",
                                "Attackers can execute malicious JavaScript in the victim's browser to steal cookies, session tokens, or deface the website.",
                                "Sanitize and encode all user inputs before reflecting them in HTML. Implement a Content-Security-Policy.")
        self.log("\n[+] Scan Complete!")
        self.finish_scan()
    def check_headers(self, response, url):
        self.log("\n[*] Checking Security Headers...")
        missing = []
        for header, details in self.security_headers.items():
            if header not in response.headers:
                missing.append(header)
                self.report_vulnerability(
                    f"Missing Security Header: {header}", details["severity"], details["cwe"],
                    url, "HTTP Response Headers", "N/A",
                    details["impact"],
                    f"The {header} header is missing from the server response.",
                    details["fix"]
                )
        
        if not missing:
            self.log("  [+] All basic security headers are present.")
            self.findings.append({"type": "Information", "title": "All basic security headers present.", "severity": "INFO"})
    def report_vulnerability(self, title, severity, cwe, url, param, payload, impact, evidence, remediation):
        """Format a detailed finding and add to GUI + report list."""
        finding = {
            "type": "Vulnerability",
            "title": title,
            "severity": severity,
            "cwe": cwe,
            "url": url,
            "parameter": param,
            "payload": payload,
            "impact": impact,
            "evidence": evidence,
            "remediation": remediation
        }
        self.findings.append(finding)
        report_str = f"""
==================================================
[!] VULNERABILITY FOUND
==================================================
Title       : {title}
Severity    : {severity}
CWE ID      : {cwe}
URL         : {url}
Parameter   : {param}
Payload     : {payload}
--------------------------------------------------
IMPACT      : {impact}
EVIDENCE    : {evidence}
REMEDIATION : {remediation}
STATUS      : VULNERABLE (Not Compromised Yet)
==================================================
"""
        self.log(report_str)
    def get_forms(self, url):
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.find_all("form")
        except Exception:
            return []

    def submit_form(self, form, url, payload):
        action = form.get("action")
        method = form.get("method", "get").lower()
        post_url = urljoin(url, action)
        inputs = form.find_all("input")
        data = {}
        for i in inputs:
            name = i.get("name")
            if name:
                data[name] = payload
        try:
            if method == "post":
                return requests.post(post_url, data=data, headers=self.headers, timeout=15)
            else:
                return requests.get(post_url, params=data, headers=self.headers, timeout=15)
        except Exception:
            return None
    def scan_url_parameters(self, url, response):
        """Scan URL parameters if no forms exist."""
        if "?" in url:
            self.log("[*] Testing URL parameters...")
            for vuln_type, payload_list in self.payloads.items():
                for payload in payload_list:
                    test_url = url + payload
                    try:
                        res = requests.get(test_url, headers=self.headers, timeout=10)
                        if payload in res.text:
                            self.report_vulnerability(f"Reflected {vuln_type}", "HIGH", "CWE-79",
                                url, "URL Parameter", payload,
                                "Payload reflected in the URL response.",
                                f"The payload {payload} was reflected in the response text.",
                                "Sanitize and encode URL parameters.")
                    except:
                        pass
    def export_report(self):
        """Export the findings to a text file."""
        if not self.findings:
            messagebox.showinfo("No Data", "No vulnerabilities found to export.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", 
                                                 filetypes=[("Text Files", "*.txt")],
                                                 initialfile="Vulnerability_Report.txt")
        if file_path:
            with open(file_path, "w") as f:
                f.write("="*60 + "\n")
                f.write("   WEB VULNERABILITY SCAN REPORT\n")
                f.write(f"   Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"   Target: {self.url_entry.get()}\n")
                f.write("="*60 + "\n\n")
                for finding in self.findings:
                    f.write(f"Title       : {finding['title']}\n")
                    f.write(f"Severity    : {finding['severity']}\n")
                    if finding['type'] == "Vulnerability":
                        f.write(f"CWE ID      : {finding['cwe']}\n")
                        f.write(f"Parameter   : {finding['parameter']}\n")
                        f.write(f"Payload     : {finding['payload']}\n")
                        f.write(f"Impact      : {finding['impact']}\n")
                        f.write(f"Evidence    : {finding['evidence']}\n")
                        f.write(f"Remediation : {finding['remediation']}\n")
                    f.write("-" * 60 + "\n")
            messagebox.showinfo("Success", f"Report saved successfully to:\n{file_path}")
    def finish_scan(self):
        self.root.after(0, lambda: self.scan_btn.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.export_btn.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.progress.stop())
if __name__ == "__main__":
    root = tk.Tk()
    app = VulnScannerApp(root)
    root.mainloop()
