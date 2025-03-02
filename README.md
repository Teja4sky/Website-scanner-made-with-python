# Web Vulnerability Scanner (Python)

## 🛡️ Overview
The **Web Vulnerability Scanner** is a **Python-based security tool** designed to analyze websites for vulnerabilities, including **SQL Injection (SQLi), Cross-Site Scripting (XSS), and Open Ports**. This tool is built for **ethical hackers, security researchers, and developers** to help improve web security by identifying potential weaknesses.

## 🚀 Features
- ✅ **Website Information Gathering**
  - Finds **IP address, DNS details, hosting provider, ISP, and ASN**
- ✅ **Open Port Scanning**
  - Checks important ports (e.g., **80, 443, 3306, 8080**)
- ✅ **SQL Injection Detection**
  - Scans for **basic SQL Injection vulnerabilities**
- ✅ **Cross-Site Scripting (XSS) Detection**
  - Checks for **XSS vulnerabilities**
- ✅ **Web Server Security Headers Analysis**
- ✅ **Saves Scan Results**
  - Outputs results in **TXT format** with the website hostname

## 📌 Installation & Usage

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/Web-Vulnerability-Scanner.git
cd Web-Vulnerability-Scanner
```

### 2️⃣ Install Dependencies
```bash
pip install requests
```

### 3️⃣ Run the Scanner
```bash
python scanner.py
```

### 4️⃣ Enter the Website URL
The scanner will analyze the website and generate a **report**.

## 📂 Output Example (`scan_report_example.com.txt`)

### 🔥 Hacking Probability Percentage
The scanner calculates an estimated **vulnerability percentage** based on open ports, security headers, and detected vulnerabilities using a weighted scoring system.

📊 **Hacking Probability:**
- **5% - 20% (Very Low Risk):** Secure website with proper headers and no critical vulnerabilities.
- **21% - 50% (Low to Moderate Risk):** Some open ports and minor security misconfigurations.
- **51% - 80% (High Risk):** Website has exploitable vulnerabilities like SQLi or XSS.
- **81% - 100% (Critical Risk):** Highly vulnerable with multiple security flaws and open attack surfaces.
The scanner calculates an estimated **vulnerability percentage** based on open ports, security headers, and detected vulnerabilities.

📊 **Hacking Probability: 35%** (Low Risk) (Example)
```
🔹 Target Domain: example.com
🔹 Target IP Address: 93.184.216.34
🔹 Reverse DNS: example.com.edgekey.net
🔹 ISP: Akamai Technologies
🔹 ASN: AS20940 Akamai International B.V.
🔹 Hosting Provider: Akamai

🔍 Open Ports: 80, 443, 8080

🔍 SQL Injection Vulnerability: ❌ No
🔍 XSS Vulnerability: ❌ No

[🔍] Web Server Security Headers:
  Server: cloudflare
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  X-Frame-Options: SAMEORIGIN
```

## 🔧 Future Enhancements
- ✅ **PDF Report Generation** (Planned)
- ✅ **GUI (Graphical User Interface)** (Planned)
- ✅ **More Advanced Vulnerability Scanning** (Planned)

## 📜 Disclaimer
⚠️ **This tool is for educational and ethical hacking purposes only.**
⚠️ Do **not** scan websites without **proper authorization**.
⚠️ Use responsibly and comply with **legal policies**.

---
**🌟 Feel free to contribute and improve this tool!**
🔗 **GitHub:** [Your Repo Link Here]

