import socket, time, re, json
from urllib import request, error, parse

class OSINT:
    def __init__(self, json_path="Tools/data.json"):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.PLATFORMS = data.get("PLATFORMS", {})
        except Exception as e:
            print(f"❌ Errore nel caricamento del file JSON: {e}")
            self.PLATFORMS = {}
            
    def _check_profile_exists(self, url, username):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        try:
            req = request.Request(url, headers=headers, method='GET')
            with request.urlopen(req, timeout=8) as resp:
                if resp.getcode() == 200:
                    content = resp.read(8192).decode('utf-8', errors='ignore').lower()
                    
                    if "facebook.com" in url:
                        if "page not found" in content or "content not found" in content:
                            return False
                        if username.lower() in content:
                            return True
                    
                    elif "instagram.com" in url:
                        if "sorry, this page isn't available" in content:
                            return False
                        if "og:title" in content and username.lower() in content:
                            return True
                    
                    elif "twitter.com" in url:
                        if "this account doesn't exist" in content:
                            return False
                        if f"@{username.lower()}" in content:
                            return True
                    
                    elif "github.com" in url:
                        if "not found" in content and "this is not the web page you are looking for" in content:
                            return False
                        return True
                    
                    elif "linkedin.com" in url:
                        if "this profile is not available" in content or "page not found" in content:
                            return False
                        return True
                    
                    return True
                    
        except error.HTTPError as e:
            if e.code == 404:
                return False
            return None
        except Exception:
            return None
        
        return False

    def username(self, username):
        if not username:
            return "Please enter a valid username"
        
        print(f"Searching '{username}' on {len(self.PLATFORMS)} platforms...")
        print("-" * 50)
        
        found = []
        
        for name, template in self.PLATFORMS.items():
            url = template.format(parse.quote(username))
            exists = self._check_profile_exists(url, username)
            
            if exists is True:
                found.append(f"FOUND {name}: {url}")
                print(f"FOUND {name}")
            elif exists is False:
                print(f"NOT FOUND {name}")
            else:
                print(f"UNKNOWN {name} (blocked/error)")
            
            time.sleep(0.5)
        
        print("-" * 50)
        
        if found:
            return "\n".join([f"Profiles found for '{username}':"] + found)
        else:
            return f"No profiles found for '{username}'"

    def email(self, email):
        if not re.match(r"^[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+$", email):
            return "Invalid email format"
        
        domain = email.split("@")[1]
        result = [f"Email analysis: {email}", f"Domain: {domain}"]
        
        try:
            mx_records = socket.getaddrinfo(f"mail.{domain}", None)
            result.append("Email server probably configured")
        except:
            result.append("Cannot verify email server")
        
        return "\n".join(result)

    def phone(self, phone):
        digits = re.sub(r"[^\d+]", "", phone)
        if 7 <= len(digits) <= 15:
            return f"Valid phone number: {digits}"
        else:
            return f"Invalid phone number: {phone}"

    def whois(self, domain):
        try:
            whois_servers = [
                "whois.iana.org",
                "whois.internic.net",
                "whois.verisign-grs.com",
                "whois.crsnic.net",
                "whois.publicinterestregistry.net",
                "whois.afilias.net",
                "whois.nic.io",
                "whois.registry.in",
                "whois.nic.uk",
                "whois.denic.de",
                "whois.dns.be",
                "whois.registro.br",
                "whois.nic.fr",
                "whois.ripn.net",
                "whois.nic.ch",
                "whois.jprs.jp",
                "whois.kr",
                "whois.cnnic.cn",
                "whois.aunic.net",
                "whois.domain-registry.nl"
            ]
            
            info_lines = []
            info_lines.append(f"WHOIS lookup for: {domain}")
            info_lines.append("=" * 50)
            
            for server in whois_servers:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    sock.connect((server, 43))
                    
                    query = domain + "\r\n"
                    sock.send(query.encode())
                    
                    response = b""
                    while True:
                        data = sock.recv(4096)
                        if not data:
                            break
                        response += data
                    
                    sock.close()
                    
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    if "not found" not in response_text.lower() and "no match" not in response_text.lower():
                        lines = response_text.split('\n')
                        
                        for line in lines:
                            line = line.strip()
                            if any(keyword in line.lower() for keyword in [
                                'registrant', 'creation date', 'created', 'expiration', 
                                'expiry', 'updated', 'registrar', 'name server', 'nserver',
                                'organization', 'org:', 'owner', 'admin', 'tech', 'domain',
                                'status:', 'whois server'
                            ]):
                                if line and not line.startswith('%') and not line.startswith('#'):
                                    info_lines.append(line)
                        
                        if len(info_lines) > 10:
                            break
                            
                except (socket.timeout, socket.error, ConnectionRefusedError):
                    continue
            
            if len(info_lines) <= 2:
                info_lines.append("No WHOIS information found")
            
            return "\n".join(info_lines[:50])
            
        except Exception as e:
            return f"WHOIS lookup failed: {str(e)}"