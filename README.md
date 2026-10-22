# Automated Web Vulnerability Scanner (Python)

## 📌 Project Overview
This is a GUI-based web vulnerability scanner built using Python. It is designed to perform basic security auditing on web applications by checking for missing HTTP security headers, SQL Injection (SQLi), and Cross-Site Scripting (XSS). 

The tool generates a detailed, professional vulnerability report with CWE IDs, severity levels, impact, and remediation steps.

## 🛠️ Technologies Used
*   **Language:** Python 3.x
*   **GUI Library:** Tkinter
*   **HTTP Requests:** `requests`
*   **HTML Parsing:** `BeautifulSoup4`
*   **Concurrency:** `threading` (to keep the GUI responsive during scans)

## 🚀 Features
1.  **Header Analysis:** Checks for missing security headers like `Content-Security-Policy` and `X-Frame-Options`.
2.  **Payload Injection:** Automatically extracts forms and tests them with SQLi and XSS payloads.
3.  **Detailed Reporting:** Categorizes findings by severity and provides CWE IDs.
4.  **Export Function:** Allows the user to save the scan results as a `.txt` file.

## ⚙️ Installation & Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
