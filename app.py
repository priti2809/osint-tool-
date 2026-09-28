import datetime
import socket
from urllib.parse import urlparse
import requests
import whois
import tldextract
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

class OSINTAnalyzer:
    def __init__(self, url):
        self.raw_url = url
        self.url = self._normalize_url(url)
        self.parsed_url = urlparse(self.url)
        
        # Domain extraction
        self.domain = self.parsed_url.netloc or self.parsed_url.path.split('/')[0]
        self.domain = self.domain.replace("www.", "")
        
        self.extracted = tldextract.extract(self.url)
        self.root_domain = f"{self.extracted.domain}.{self.extracted.suffix}"
        
        self.results = {
            "protocol": self.parsed_url.scheme.upper(),
            "ip_address": "Not Resolved",
            "domain_age_days": None,
            "domain_age_readable": "Unknown",
            "http_status": "Unreachable",
            "redirects": 0,
            "ssl_valid": False
        }
        
        self.risk_score = 0
        self.factors = []

    def _normalize_url(self, url):
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            return 'https://' + url  # default to https for check
        return url

    def check_protocol(self):
        if self.parsed_url.scheme == "http":
            self.risk_score += 15
            self.factors.append({
                "name": "Security Protocol Compliance",
                "description": "Connection uses insecure HTTP protocol instead of encrypted HTTPS.",
                "score_impact": 15,
                "status": "warning"
            })
        else:
            self.factors.append({
                "name": "Security Protocol Compliance",
                "description": "Connection uses encrypted HTTPS protocol.",
                "score_impact": 0,
                "status": "pass"
            })

    def resolve_ip(self):
        try:
            ip = socket.gethostbyname(self.domain)
            self.results["ip_address"] = ip
            self.factors.append({
                "name": "DNS Node Availability",
                "description": f"Domain resolved successfully to IP Address: {ip}.",
                "score_impact": 0,
                "status": "pass"
            })
            return True
        except socket.gaierror:
            self.risk_score += 50
            self.factors.append({
                "name": "DNS Node Availability",
                "description": "Domain failed to resolve to a valid IP address. The domain may be inactive or configured maliciously.",
                "score_impact": 50,
                "status": "warning"
            })
            return False

    def check_whois(self):
        try:
            w = whois.whois(self.root_domain)
            creation_date = w.creation_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if isinstance(creation_date, datetime.datetime):
                age_days = (datetime.datetime.now() - creation_date).days
                self.results["domain_age_days"] = age_days
                
                # Format readable age
                years = age_days // 365
                months = (age_days % 365) // 30
                if years > 0:
                    age_str = f"{years} year{'s' if years > 1 else ''}, {months} month{'s' if months != 1 else ''}"
                else:
                    age_str = f"{age_days} day{'s' if age_days > 1 else ''}"
                self.results["domain_age_readable"] = age_str
                
                if age_days < 30:
                    self.risk_score += 40
                    self.factors.append({
                        "name": "Domain Registration History",
                        "description": f"Domain is newly registered ({age_str} ago). Newly registered domains are statistically higher risk.",
                        "score_impact": 40,
                        "status": "warning"
                    })
                elif age_days < 180:
                    self.risk_score += 20
                    self.factors.append({
                        "name": "Domain Registration History",
                        "description": f"Domain is relatively new ({age_str} ago).",
                        "score_impact": 20,
                        "status": "warning"
                    })
                else:
                    self.factors.append({
                        "name": "Domain Registration History",
                        "description": f"Domain has established history ({age_str} old).",
                        "score_impact": 0,
                        "status": "pass"
                    })
            else:
                self.risk_score += 15
                self.factors.append({
                    "name": "Domain Registration History",
                    "description": "Registry creation details are missing from public records.",
                    "score_impact": 15,
                    "status": "warning"
                })
        except Exception:
            self.risk_score += 15
            self.factors.append({
                "name": "Domain Registration History",
                "description": "Domain registry details could not be retrieved.",
                "score_impact": 15,
                "status": "warning"
            })

    def check_http(self):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            # We disable SSL verification to check the domain response even if certificate is self-signed/expired
            response = requests.get(
                self.url,
                headers=headers,
                timeout=8,
                allow_redirects=True,
                verify=False
            )
            
            self.results["http_status"] = response.status_code
            self.results["redirects"] = len(response.history)
            
            # Check redirect to HTTPS
            if self.parsed_url.scheme == "http" and response.url.startswith("https://"):
                self.risk_score -= 10  # Mitigation
                self.factors.append({
                    "name": "Enforced Traffic Encryption",
                    "description": "HTTP traffic redirected automatically to secure HTTPS.",
                    "score_impact": -10,
                    "status": "pass"
                })
            
            # Check response status
            if response.status_code >= 400:
                self.risk_score += 20
                self.factors.append({
                    "name": "Service Handshake Response",
                    "description": f"Target server returned error code {response.status_code}.",
                    "score_impact": 20,
                    "status": "warning"
                })
            else:
                self.factors.append({
                    "name": "Service Handshake Response",
                    "description": f"Target server answered successfully with response code {response.status_code}.",
                    "score_impact": 0,
                    "status": "pass"
                })
            
            # Check redirection depth
            if self.results["redirects"] > 2:
                self.risk_score += 15
                self.factors.append({
                    "name": "Redirection Integrity Check",
                    "description": f"Domain redirected {self.results['redirects']} times. Excessive redirection is common in phishing sites.",
                    "score_impact": 15,
                    "status": "warning"
                })
            else:
                self.factors.append({
                    "name": "Redirection Integrity Check",
                    "description": "Domain redirects are within standard secure limits.",
                    "score_impact": 0,
                    "status": "pass"
                })
                
        except requests.exceptions.SSLError:
            self.risk_score += 35
            self.factors.append({
                "name": "Cryptographic Handshake Check",
                "description": "SSL/TLS handshake failed. The domain's SSL certificate is invalid, expired, or untrusted.",
                "score_impact": 35,
                "status": "warning"
            })
        except requests.exceptions.RequestException:
            self.risk_score += 30
            self.factors.append({
                "name": "Service Handshake Response",
                "description": "Could not connect to the remote web server. Service is down or blocking requests.",
                "score_impact": 30,
                "status": "warning"
            })

    def run_analysis(self):
        self.check_protocol()
        resolved = self.resolve_ip()
        self.check_whois()
        
        if resolved:
            self.check_http()
        else:
            self.results["http_status"] = "N/A (DNS Failure)"
            self.factors.append({
                "name": "Service Handshake Response",
                "description": "Connection skipped due to DNS resolution failure.",
                "score_impact": 0,
                "status": "warning"
            })

        # Final score bounding
        self.risk_score = max(0, min(self.risk_score, 100))
        
        # Categorize
        if self.risk_score <= 30:
            verdict = "Safe"
        elif self.risk_score <= 70:
            verdict = "Risky"
        else:
            verdict = "Dangerous"
            
        return {
            "domain": self.domain,
            "ip": self.results["ip_address"],
            "age_readable": self.results["domain_age_readable"],
            "http_status": self.results["http_status"],
            "redirects": self.results["redirects"],
            "protocol": self.results["protocol"],
            "risk_score": self.risk_score,
            "verdict": verdict,
            "factors": self.factors
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze')
def analyze():
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
        
    try:
        analyzer = OSINTAnalyzer(url)
        report = analyzer.run_analysis()
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": f"Internal scan failure: {str(e)}"}), 500

if __name__ == '__main__':
    # Disable SSL warning printouts in terminal
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    print("Aegis OSINT Server Starting on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)
