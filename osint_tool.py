import argparse
import socket
import datetime
from urllib.parse import urlparse
import requests
import whois
import tldextract
import matplotlib.pyplot as plt
from colorama import init, Fore, Style

init(autoreset=True)

class OSINTAnalyzer:
    def __init__(self, url):
        self.raw_url = url
        self.url = self._normalize_url(url)
        self.parsed_url = urlparse(self.url)

        # FIXED DOMAIN EXTRACTION
        self.domain = self.parsed_url.netloc or self.parsed_url.path.split('/')[0]
        self.domain = self.domain.replace("www.", "")

        self.extracted = tldextract.extract(self.url)
        self.root_domain = f"{self.extracted.domain}.{self.extracted.suffix}"

        self.results = {
            "protocol": self.parsed_url.scheme,
            "ip_address": None,
            "domain_age_days": None,
            "http_status": None,
            "redirects": 0
        }

        self.risk_score = 0
        self.risk_factors = []

    def _normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url
        return url

    def check_protocol(self):
        if self.results["protocol"] == "http":
            self.risk_score += 15
            self.risk_factors.append(("HTTP (Not Secure)", 15))
        else:
            self.risk_factors.append(("HTTPS Secure", 0))

    def resolve_ip(self):
        try:
            ip = socket.gethostbyname(self.domain)
            self.results["ip_address"] = ip
            self.risk_factors.append(("IP Resolved", 0))
        except:
            self.risk_score += 50
            self.risk_factors.append(("IP Resolve Failed", 50))

    def check_whois(self):
        try:
            w = whois.whois(self.root_domain)
            creation_date = w.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if isinstance(creation_date, datetime.datetime):
                age_days = (datetime.datetime.now() - creation_date).days
                self.results["domain_age_days"] = age_days

                if age_days < 30:
                    self.risk_score += 40
                    self.risk_factors.append(("New Domain (<30 days)", 40))
                elif age_days < 180:
                    self.risk_score += 20
                    self.risk_factors.append(("Young Domain (<180 days)", 20))
                else:
                    self.risk_factors.append(("Old Domain", 0))
            else:
                self.risk_score += 15
                self.risk_factors.append(("WHOIS Missing", 15))

        except:
            self.risk_score += 20
            self.risk_factors.append(("WHOIS Failed", 20))

    def check_http(self):
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(
                self.url,
                headers=headers,
                timeout=10,
                allow_redirects=True,
                verify=False
            )

            self.results["http_status"] = response.status_code
            self.results["redirects"] = len(response.history)

            # Redirect fix
            if self.results["protocol"] == "http" and response.url.startswith("https://"):
                self.risk_score -= 15
                self.risk_factors.append(("Redirected to HTTPS", 0))

            if response.status_code >= 400:
                self.risk_score += 20
                self.risk_factors.append((f"HTTP Error {response.status_code}", 20))
            else:
                self.risk_factors.append(("HTTP OK", 0))

            if self.results["redirects"] > 2:
                self.risk_score += 10
                self.risk_factors.append(("Too Many Redirects", 10))

        except:
            self.risk_score += 30
            self.risk_factors.append(("HTTP Failed", 30))

    def get_risk_category(self):
        if self.risk_score <= 30:
            return "Safe", Fore.GREEN
        elif self.risk_score <= 70:
            return "Risky", Fore.YELLOW
        else:
            return "Dangerous", Fore.RED

    def generate_exact_report(self):
        txt_filename = f"{self.domain}_report.txt"
        with open(txt_filename, "w") as f:
            f.write(f"OSINT Exact Risk Report for {self.domain}\n")
            f.write("="*40 + "\n")
            f.write(f"URL: {self.url}\n")
            f.write(f"IP Address: {self.results['ip_address']}\n")
            f.write(f"Domain Age: {self.results['domain_age_days']} days\n")
            f.write(f"HTTP Status: {self.results['http_status']}\n")
            f.write(f"Redirects: {self.results['redirects']}\n")
            f.write("="*40 + "\n")
            f.write("Risk Factors Breakdown:\n")
            for factor, score in self.risk_factors:
                f.write(f" - {factor}: {score}\n")
            f.write("="*40 + "\n")
            category, _ = self.get_risk_category()
            f.write(f"Total Risk Score: {self.risk_score}\n")
            f.write(f"Verdict: {category}\n")
            
        print(Fore.CYAN + f"[+] Exact text report saved as {txt_filename}")

        factors = [f[0] for f in self.risk_factors if f[1] > 0]
        scores = [f[1] for f in self.risk_factors if f[1] > 0]

        if scores:
            plt.figure(figsize=(8, 6))
            plt.pie(scores, labels=factors, autopct='%1.1f%%', startangle=140)
            plt.title(f"Risk Factors Breakdown for {self.domain}")
            png_filename = f"{self.domain}_exact_report.png"
            plt.savefig(png_filename)
            plt.close()
            print(Fore.CYAN + f"[+] Exact graphical report saved as {png_filename}")

    def run(self):
        print(Fore.CYAN + f"\n[*] Analyzing: {self.url}")

        self.check_protocol()
        self.resolve_ip()
        self.check_whois()
        self.check_http()

        print("="*40)
        print(Style.BRIGHT + "RESULT")
        print("="*40)
        print(f"Domain: {self.domain}")
        print(f"IP: {self.results['ip_address']}")
        print(f"Age: {self.results['domain_age_days']} days")
        print(f"HTTP: {self.results['http_status']}")

        category, color = self.get_risk_category()
        print(f"Risk Score: {self.risk_score}")
        print(f"Verdict: {color}{category}")
        print("="*40)
        
        self.generate_exact_report()


# 🔥 COMPARISON GRAPH
def generate_comparison_graph(results):
    domains = [r[0] for r in results]
    scores = [r[1] for r in results]

    colors = ['green' if s <= 30 else 'yellow' if s <= 70 else 'red' for s in scores]

    plt.figure()
    plt.bar(domains, scores, color=colors)
    plt.xlabel("Domains")
    plt.ylabel("Risk Score")
    plt.title("OSINT Risk Comparison")

    plt.savefig("comparison_report.png")
    plt.show()

    print(Fore.CYAN + "[+] Comparison graph saved as comparison_report.png")


# ✅ MAIN
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSINT URL Analyzer")
    parser.add_argument("urls", nargs='*', help="Enter multiple URLs")

    args = parser.parse_args()

    if not args.urls:
        user_input = input("Enter URLs (comma separated): ")
        args.urls = [u.strip() for u in user_input.split(",")]

    all_results = []

    for url in args.urls:
        analyzer = OSINTAnalyzer(url)
        analyzer.run()
        all_results.append((analyzer.domain, analyzer.risk_score))

    # 🔥 Final comparison graph
    generate_comparison_graph(all_results)