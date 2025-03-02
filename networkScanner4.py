import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import requests
import os
import json
import re
import threading
import webbrowser
from datetime import datetime

# Common Open Ports
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]

# Global headers for requests to minimize unique fingerprints
REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36'
}

def scan_open_ports(target_ip, stop_event=None):
    """Scan common ports to check if they are open."""
    open_ports = []
    for port in COMMON_PORTS:
        if stop_event and stop_event.is_set():
            break
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex((target_ip, port)) == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def check_sql_injection(target_url, stop_event=None):
    """Check if the website is vulnerable to SQL Injection."""
    payloads = ["'", "\"", " OR 1=1 --", " OR '1'='1' --", "' OR '1'='1' --"]
    vulnerable = False

    for payload in payloads:
        if stop_event and stop_event.is_set():
            return False
        test_url = f"{target_url}/?id={payload}"
        try:
            response = requests.get(test_url, timeout=5, headers=REQUEST_HEADERS)
            if any(err in response.text.lower() for err in ["sql syntax", "mysql_fetch_array", "warning: mysql"]):
                vulnerable = True
                break
        except:
            pass

    return vulnerable

def check_xss(target_url, stop_event=None):
    """Check if the website is vulnerable to Cross-Site Scripting (XSS)."""
    if stop_event and stop_event.is_set():
        return False
    xss_payload = "<script>alert('XSS')</script>"
    test_url = f"{target_url}/?q={xss_payload}"
    
    try:
        response = requests.get(test_url, timeout=5, headers=REQUEST_HEADERS)
        if xss_payload in response.text:
            return True
    except:
        pass
    
    return False

def calculate_hackability_percentage(results):
    """Calculate a hackability percentage based on scan results."""
    total_score = 0
    max_score = 100
    
    # SQL Injection vulnerability (30%)
    if results["SQL Injection Vulnerable"]:
        total_score += 30
    
    # XSS vulnerability (25%)
    if results["XSS Vulnerable"]:
        total_score += 25
    
    # Open ports assessment (up to 20%)
    critical_ports = [21, 22, 23, 3306, 3389]  # FTP, SSH, Telnet, MySQL, RDP
    http_ports = [80, 443, 8080, 8443]
    
    port_score = 0
    for port in results["Open Ports"]:
        if port in critical_ports:
            port_score += 4  # 4% per critical port
        elif port in http_ports:
            port_score += 1  # 1% for standard web ports
        else:
            port_score += 2  # 2% for other ports
    port_score = min(20, port_score)
    
    # Security headers assessment (up to 25%)
    security_headers = results["Security Headers"]
    important_headers = ["strict-transport-security", "content-security-policy", "x-frame-options"]
    
    headers_score = 25
    for header in important_headers:
        if any(h.lower() == header for h in security_headers.keys()):
            headers_score -= 8  # Subtract 8% for each security header present
    
    # Information disclosure (up to 10%)
    info_disclosure = 0
    if "server" in [h.lower() for h in security_headers.keys()]:
        info_disclosure += 5
    if "x-powered-by" in [h.lower() for h in security_headers.keys()]:
        info_disclosure += 5
    
    final_score = min(100, total_score + port_score + max(0, headers_score) + info_disclosure)
    return final_score

def get_risk_level(percentage):
    """Convert percentage to risk level."""
    if percentage < 20:
        return "Very Low"
    elif percentage < 40:
        return "Low"
    elif percentage < 60:
        return "Medium"
    elif percentage < 80:
        return "High"
    else:
        return "Critical"

def get_hosting_provider(target_url, log_widget, progress_var, status_label, stop_event=None):
    """Fetch hosting, security, and vulnerability details."""
    try:
        # Disclaimer
        log_widget.config(state=tk.NORMAL)
        log_widget.insert(tk.END, "[!] Disclaimer: Use responsibly. Only scan networks you have permission to test.\n\n", "warning")
        log_widget.see(tk.END)
        log_widget.config(state=tk.DISABLED)
        
        target_domain = target_url.replace("http://", "").replace("https://", "").split("/")[0]
        log_widget.config(state=tk.NORMAL)
        log_widget.insert(tk.END, f"[🔍] Starting scan on {target_domain}...\n", "info")
        log_widget.see(tk.END)
        log_widget.config(state=tk.DISABLED)
        
        progress_var.set(10)
        status_label.config(text="Resolving domain...")
        if stop_event and stop_event.is_set():
            raise Exception("Scan stopped by user.")
        
        target_ip = socket.gethostbyname(target_domain)
        log_widget.config(state=tk.NORMAL)
        log_widget.insert(tk.END, f"[✓] IP address: {target_ip}\n", "success")
        log_widget.see(tk.END)
        log_widget.config(state=tk.DISABLED)
        
        progress_var.set(20)
        status_label.config(text="Performing reverse DNS lookup...")
        if stop_event and stop_event.is_set():
            raise Exception("Scan stopped by user.")

        try:
            reverse_dns = socket.gethostbyaddr(target_ip)[0]
        except socket.herror:
            reverse_dns = "Unknown"
        
        log_widget.config(state=tk.NORMAL)
        log_widget.insert(tk.END, f"[✓] Reverse DNS: {reverse_dns}\n", "success")
        log_widget.see(tk.END)
        log_widget.config(state=tk.DISABLED)
        
        progress_var.set(30)
        status_label.config(text="Fetching ISP and hosting information...")
        if stop_event and stop_event.is_set():
            raise Exception("Scan stopped by user.")

        asn_info = isp = hosting_provider = "Unknown"
        try:
            response = requests.get(f"https://ipinfo.io/{target_ip}/json", timeout=5, headers=REQUEST_HEADERS)
            data = response.json()
            asn_info = data.get("org", "Unknown")
            isp = data.get("isp", "Unknown") if "isp" in data else asn_info
            hosting_provider = " ".join(asn_info.split(" ")[1:]) if "AS" in asn_info else asn_info
        except Exception as e:
            log_widget.config(state=tk.NORMAL)
            log_widget.insert(tk.END, f"[!] Warning: Couldn't fetch IP info: {str(e)}\n", "warning")
            log_widget.see(tk.END)
            log_widget.config(state=tk.DISABLED)
        
        progress_var.set(40)
        status_label.config(text="Scanning ports...")
        if stop_event and stop_event.is_set():
            raise Exception("Scan stopped by user.")

        log_widget.config(state=tk.NORMAL)
        log_widget.insert(tk.END, f"[🔍] Scanning common ports...\n", "info")
        log_widget.see(tk.END)
        log_widget.config(state=tk.DISABLED)
        
        open_ports = scan_open_ports(target_ip, stop_event=stop_event)
        log_widget.config(state=tk.NORMAL)
        if open_ports:
            log_widget.insert(tk.END, f"[✓] Open ports: {', '.join(map(str, open_ports))}\n", "success")
        else:
            log_widget.insert(tk.END, "[✓] No common open ports detected\n", "success")
        log_widget.see(tk.END)
        log_widget.config(state=tk.DISABLED)
        
        progress_var.set(60)
        status_label.config(text="Checking SQL injection vulnerability...")
        if stop_event and stop_event.is_set():
            raise Exception("Scan stopped by user.")

        log_widget.config(state=tk.NORMAL)
        log_widget.insert(tk.END, "[🔍] Testing SQL injection vulnerabilities...\n", "info")
        log_widget.see(tk.END)
        log_widget.config(state=tk.DISABLED)
        
        sql_vulnerable = check_sql_injection(target_url, stop_event=stop_event)
        log_widget.config(state=tk.NORMAL)
        if sql_vulnerable:
            log_widget.insert(tk.END, "[❗] SQL Injection vulnerability DETECTED!\n", "critical")
        else:
            log_widget.insert(tk.END, "[✓] No SQL Injection vulnerability detected\n", "success")
        log_widget.see(tk.END)
        log_widget.config(state=tk.DISABLED)
        
        progress_var.set(70)
        status_label.config(text="Checking XSS vulnerability...")
        if stop_event and stop_event.is_set():
            raise Exception("Scan stopped by user.")

        log_widget.config(state=tk.NORMAL)
        log_widget.insert(tk.END, "[🔍] Testing XSS vulnerabilities...\n", "info")
        log_widget.see(tk.END)
        log_widget.config(state=tk.DISABLED)
        
        xss_vulnerable = check_xss(target_url, stop_event=stop_event)
        log_widget.config(state=tk.NORMAL)
        if xss_vulnerable:
            log_widget.insert(tk.END, "[❗] XSS vulnerability DETECTED!\n", "critical")
        else:
            log_widget.insert(tk.END, "[✓] No XSS vulnerability detected\n", "success")
        log_widget.see(tk.END)
        log_widget.config(state=tk.DISABLED)
        
        progress_var.set(80)
        status_label.config(text="Checking security headers...")
        if stop_event and stop_event.is_set():
            raise Exception("Scan stopped by user.")

        security_headers = {}
        try:
            headers = requests.get(target_url, timeout=5, headers=REQUEST_HEADERS).headers
            security_headers = {key: headers[key] for key in headers if key.lower() in 
                                ["server", "x-powered-by", "strict-transport-security", "content-security-policy", "x-frame-options"]}
        except Exception as e:
            log_widget.config(state=tk.NORMAL)
            log_widget.insert(tk.END, f"[!] Warning: Couldn't fetch security headers: {str(e)}\n", "warning")
            log_widget.see(tk.END)
            log_widget.config(state=tk.DISABLED)
        
        log_widget.config(state=tk.NORMAL)
        log_widget.insert(tk.END, "[✓] Security headers retrieved\n", "success")
        log_widget.see(tk.END)
        log_widget.config(state=tk.DISABLED)
        
        results = {
            "Target Domain": target_domain,
            "IP Address": target_ip,
            "Reverse DNS": reverse_dns,
            "ISP": isp,
            "ASN": asn_info,
            "Hosting Provider": hosting_provider,
            "Open Ports": open_ports,
            "SQL Injection Vulnerable": sql_vulnerable,
            "XSS Vulnerable": xss_vulnerable,
            "Security Headers": security_headers,
        }
        
        progress_var.set(90)
        status_label.config(text="Calculating hackability percentage...")
        if stop_event and stop_event.is_set():
            raise Exception("Scan stopped by user.")
            
        hackability_percentage = calculate_hackability_percentage(results)
        risk_level = get_risk_level(hackability_percentage)
        
        results["Hackability Percentage"] = hackability_percentage
        results["Risk Level"] = risk_level
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{target_domain}_{timestamp}.txt"
        
        with open(filename, "w", encoding="utf-8") as file:
            file.write(f"=== WEBSITE VULNERABILITY SCAN REPORT ===\n")
            file.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            file.write(f"🔹 Target Domain: {target_domain}\n")
            file.write(f"🔹 Target IP Address: {target_ip}\n")
            file.write(f"🔹 Reverse DNS: {reverse_dns}\n")
            file.write(f"🔹 ISP: {isp}\n")
            file.write(f"🔹 ASN: {asn_info}\n")
            file.write(f"🔹 Hosting Provider: {hosting_provider}\n")
            file.write(f"\n🔍 Open Ports: {', '.join(map(str, open_ports)) if open_ports else 'No open ports detected'}\n")
            file.write(f"\n🔍 SQL Injection Vulnerability: {'✅ Yes' if sql_vulnerable else '❌ No'}\n")
            file.write(f"🔍 XSS Vulnerability: {'✅ Yes' if xss_vulnerable else '❌ No'}\n")
            file.write("\n[🔍] Web Server Security Headers:\n")
            for key, value in security_headers.items():
                file.write(f"  {key}: {value}\n")
            file.write(f"\n=== HACKABILITY ASSESSMENT ===\n")
            file.write(f"Overall Hackability: {hackability_percentage}%\n")
            file.write(f"Risk Level: {risk_level}\n")
            file.write(f"\nContributing Factors:\n")
            if sql_vulnerable:
                file.write(f"- SQL Injection vulnerability significantly increases risk (30%)\n")
            if xss_vulnerable:
                file.write(f"- XSS vulnerability significantly increases risk (25%)\n")
            if open_ports:
                file.write(f"- Open ports may increase attack surface (up to 20%)\n")
            missing_headers = [h for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"] 
                              if not any(k.lower() == h.lower() for k in security_headers.keys())]
            if missing_headers:
                file.write(f"- Missing security headers: {', '.join(missing_headers)}\n")
            info_headers = [h for h in ["Server", "X-Powered-By"] 
                          if any(k.lower() == h.lower() for k in security_headers.keys())]
            if info_headers:
                file.write(f"- Information disclosure through headers: {', '.join(info_headers)}\n")

        results["Report File"] = filename
        
        log_widget.config(state=tk.NORMAL)
        log_widget.insert(tk.END, f"\n[✅] Scan completed! Report saved as: {filename}\n", "success")
        log_widget.insert(tk.END, "\n=== HACKABILITY ASSESSMENT ===\n", "header")
        if hackability_percentage >= 80:
            log_widget.insert(tk.END, f"⚠️ CRITICAL RISK: {hackability_percentage}% ⚠️\n", "critical")
        elif hackability_percentage >= 60:
            log_widget.insert(tk.END, f"⚠️ HIGH RISK: {hackability_percentage}% ⚠️\n", "critical")
        elif hackability_percentage >= 40:
            log_widget.insert(tk.END, f"⚠️ MEDIUM RISK: {hackability_percentage}% ⚠️\n", "warning")
        elif hackability_percentage >= 20:
            log_widget.insert(tk.END, f"⚠️ LOW RISK: {hackability_percentage}% ⚠️\n", "info")
        else:
            log_widget.insert(tk.END, f"✅ VERY LOW RISK: {hackability_percentage}% ✅\n", "success")
        
        log_widget.insert(tk.END, "[", "info")
        gauge_length = 50
        filled_length = int(gauge_length * hackability_percentage / 100)
        if hackability_percentage < 20:
            log_widget.insert(tk.END, filled_length * "█", "success")
        elif hackability_percentage < 40:
            log_widget.insert(tk.END, filled_length * "█", "info")
        elif hackability_percentage < 60:
            log_widget.insert(tk.END, filled_length * "█", "warning")
        else:
            log_widget.insert(tk.END, filled_length * "█", "critical")
        log_widget.insert(tk.END, (gauge_length - filled_length) * "░", "info")
        log_widget.insert(tk.END, "] ", "info")
        log_widget.insert(tk.END, f"{hackability_percentage}%\n\n", "header")
        
        log_widget.insert(tk.END, "Key Factors:\n", "info")
        if sql_vulnerable:
            log_widget.insert(tk.END, "• SQL Injection vulnerability detected (+30%)\n", "critical")
        if xss_vulnerable:
            log_widget.insert(tk.END, "• XSS vulnerability detected (+25%)\n", "critical")
        if open_ports:
            critical_ports_found = [p for p in open_ports if p in [21, 22, 23, 3306, 3389]]
            if critical_ports_found:
                log_widget.insert(tk.END, f"• Sensitive ports open: {', '.join(map(str, critical_ports_found))} (+{len(critical_ports_found)*4}%)\n", "critical")
            else:
                log_widget.insert(tk.END, f"• {len(open_ports)} open ports detected\n", "warning")
        if missing_headers:
            log_widget.insert(tk.END, f"• Missing security headers: {', '.join(missing_headers)}\n", "warning")
        if info_headers:
            log_widget.insert(tk.END, f"• Information disclosure through headers: {', '.join(info_headers)}\n", "warning")
            
        log_widget.insert(tk.END, "\n=== SCAN SUMMARY ===\n", "header")
        if sql_vulnerable or xss_vulnerable:
            log_widget.insert(tk.END, "⚠️ VULNERABILITIES DETECTED ⚠️\n", "critical")
        else:
            log_widget.insert(tk.END, "✅ No major vulnerabilities detected\n", "success")
        log_widget.insert(tk.END, f"Domain: {target_domain} ({target_ip})\n", "info")
        log_widget.insert(tk.END, f"Open Ports: {', '.join(map(str, open_ports)) if open_ports else 'None'}\n", "info")
        log_widget.insert(tk.END, f"SQL Injection: {'Vulnerable!' if sql_vulnerable else 'Not Vulnerable'}\n", "critical" if sql_vulnerable else "success")
        log_widget.insert(tk.END, f"XSS: {'Vulnerable!' if xss_vulnerable else 'Not Vulnerable'}\n", "critical" if xss_vulnerable else "success")
        log_widget.see(tk.END)
        log_widget.config(state=tk.DISABLED)
        
        progress_var.set(100)
        status_label.config(text="Scan completed!")
        return results
        
    except Exception as e:
        log_widget.config(state=tk.NORMAL)
        log_widget.insert(tk.END, f"\n[❗] Error: {str(e)}\n", "error")
        log_widget.see(tk.END)
        log_widget.config(state=tk.DISABLED)
        progress_var.set(0)
        status_label.config(text="Scan stopped.")
        return None

class WebVulnerabilityScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Website Vulnerability Scanner")
        self.root.geometry("800x600")
        self.root.minsize(700, 500)
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Arial", 10))
        self.style.configure("TLabel", font=("Arial", 10))
        self.style.configure("TFrame", background="#f0f0f0")
        
        # Create main frame
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # URL input section
        self.url_frame = ttk.Frame(self.main_frame)
        self.url_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(self.url_frame, text="Website URL:").pack(side=tk.LEFT, padx=5)
        
        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(self.url_frame, textvariable=self.url_var, width=50)
        self.url_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        self.scan_button = ttk.Button(self.url_frame, text="Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress_frame = ttk.Frame(self.main_frame)
        self.progress_frame.pack(fill=tk.X, pady=5)
        
        self.progress_var = tk.IntVar()
        self.progress_bar = ttk.Progressbar(self.progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=5)
        
        self.status_label = ttk.Label(self.progress_frame, text="Ready")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Log area
        self.log_frame = ttk.Frame(self.main_frame)
        self.log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.log_label = ttk.Label(self.log_frame, text="Scan Log:")
        self.log_label.pack(anchor=tk.W)
        
        self.log_text = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5)
        self.log_text.config(state=tk.DISABLED)
        
        # Configure text tags
        self.log_text.tag_configure("info", foreground="blue")
        self.log_text.tag_configure("success", foreground="green")
        self.log_text.tag_configure("warning", foreground="orange")
        self.log_text.tag_configure("error", foreground="red")
        self.log_text.tag_configure("critical", foreground="red", font=("Arial", 10, "bold"))
        self.log_text.tag_configure("header", foreground="purple", font=("Arial", 11, "bold"))
        
        # Button frame
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.pack(fill=tk.X, pady=10)
        
        self.save_button = ttk.Button(self.button_frame, text="Save Report", command=self.open_report, state=tk.DISABLED)
        self.save_button.pack(side=tk.RIGHT, padx=5)
        
        self.clear_button = ttk.Button(self.button_frame, text="Clear Log", command=self.clear_log)
        self.clear_button.pack(side=tk.RIGHT, padx=5)
        
        self.stop_button = ttk.Button(self.button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.RIGHT, padx=5)
        
        # Initialize variables
        self.scan_result = None
        self.current_report_file = None
        self.stop_scan_event = threading.Event()
        
        # Add welcome message & disclaimer
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, "=== Website Vulnerability Scanner ===\n", "header")
        self.log_text.insert(tk.END, "Warning: Use this tool responsibly. Only scan websites/networks you have explicit permission to test.\n\n", "warning")
        self.log_text.insert(tk.END, "Enter a website URL to begin scanning for vulnerabilities.\n\n", "info")
        self.log_text.insert(tk.END, "This tool will check for:\n", "info")
        self.log_text.insert(tk.END, "• Open ports\n", "info")
        self.log_text.insert(tk.END, "• SQL injection vulnerabilities\n", "info")
        self.log_text.insert(tk.END, "• XSS vulnerabilities\n", "info")
        self.log_text.insert(tk.END, "• Security headers\n", "info")
        self.log_text.insert(tk.END, "• Overall hackability percentage\n\n", "info")
        self.log_text.insert(tk.END, "Ready to scan.\n", "success")
        self.log_text.config(state=tk.DISABLED)
    
    def start_scan(self):
        url = self.url_var.get().strip()
        
        # Validate URL
        if not url:
            messagebox.showerror("Error", "Please enter a website URL")
            return
        
        if not url.startswith("http"):
            messagebox.showerror("Error", "Please enter a valid website URL (starting with http:// or https://)")
            return
        
        # Clear previous log and reset stop event
        self.clear_log()
        self.stop_scan_event.clear()
        
        # Enable the stop button and disable scan button during scan
        self.scan_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress_var.set(0)
        self.status_label.config(text="Initializing scan...")
        
        # Create and start scan thread
        scan_thread = threading.Thread(target=self.run_scan, args=(url,))
        scan_thread.daemon = True
        scan_thread.start()
    
    def run_scan(self, url):
        self.scan_result = get_hosting_provider(url, self.log_text, self.progress_var, self.status_label, stop_event=self.stop_scan_event)
        self.root.after(100, self.on_scan_complete)
    
    def on_scan_complete(self):
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        if self.scan_result and "Report File" in self.scan_result:
            self.current_report_file = self.scan_result["Report File"]
            self.save_button.config(state=tk.NORMAL)
    
    def stop_scan(self):
        self.stop_scan_event.set()
        self.status_label.config(text="Stopping scan...")
    
    def open_report(self):
        if self.current_report_file and os.path.exists(self.current_report_file):
            try:
                if os.name == 'nt':
                    os.startfile(self.current_report_file)
                else:
                    opener = 'open' if os.name == 'darwin' else 'xdg-open'
                    os.system(f'{opener} "{self.current_report_file}"')
            except Exception as e:
                messagebox.showerror("Error", f"Could not open report file: {str(e)}")
        else:
            messagebox.showerror("Error", "No report file available")
    
    def clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = WebVulnerabilityScannerGUI(root)
    root.mainloop()
