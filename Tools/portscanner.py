import socket, time, threading, json
from concurrent.futures import ThreadPoolExecutor, as_completed

class PortScanner:
    def __init__(self, json_path="Tools/data.json", max_threads=500):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.SERVICE_PORTS = data.get("SERVICE_PORTS", {})
        except Exception as e:
            print(f"❌ Errore nel caricamento del file JSON: {e}")
            self.SERVICE_PORTS = {}
        
        self.max_threads = max_threads
        self.results = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()

    def resolve_host(self, target):
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            raise Exception(f"Could not resolve host: {target}")

    def scan_port(self, target_ip, port, timeout=1):
        if self.stop_event.is_set():
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            
            if result == 0:
                service = self.SERVICE_PORTS.get(str(port), "unknown")
                
                with self.lock:
                    self.results.append({
                        "port": port,
                        "state": "open",
                        "service": service
                    })
                return port
            sock.close()
        except Exception:
            pass
        return None

    def run_scan(self, target, ports, timeout=1):
        self.results = []
        self.stop_event.clear()
        
        try:
            target_ip = self.resolve_host(target)
        except Exception as e:
            return {"error": str(e)}
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self.scan_port, target_ip, port, timeout): port 
                for port in ports
            }
            
            for future in as_completed(futures):
                if self.stop_event.is_set():
                    executor.shutdown(wait=False)
                    break
        
        duration = time.time() - start_time
        self.results.sort(key=lambda x: x["port"])
        
        return {
            "target": target,
            "ip": target_ip,
            "duration": duration,
            "open": self.results
        }

    def quick_scan(self, target, threads=200, timeout=0.6):
        quick_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 995, 3306, 3389, 5900, 8080]
        return self.run_scan(target, quick_ports, timeout)

    def scan(self, target, port_range=None, threads=400, timeout=1.0):
        if port_range:
            ports = self._parse_range(port_range)
        else:
            ports = [int(p) for p in self.SERVICE_PORTS.keys()]
        self.max_threads = threads
        return self.run_scan(target, ports, timeout)

    def stealth_scan(self, target, port_range=None, threads=300, timeout=0.6):
        if port_range:
            ports = self._parse_range(port_range)
        else:
            ports = [int(p) for p in list(self.SERVICE_PORTS.keys())[:100]]
        self.max_threads = threads
        return self.run_scan(target, ports, timeout)

    def service_scan(self, target, ports=None, threads=200, timeout=1.0):
        scan_ports = ports or [int(p) for p in self.SERVICE_PORTS.keys()]
        self.max_threads = threads
        return self.run_scan(target, scan_ports, timeout)

    def aggressive_scan(self, target, threads=500, timeout=0.8):
        ports = [int(p) for p in self.SERVICE_PORTS.keys()] + list(range(1, 1025))
        ports = sorted(set(p for p in ports if 1 <= p <= 65535))
        self.max_threads = threads
        return self.run_scan(target, ports, timeout)

    def full_scan(self, target, threads=600, timeout=0.3):
        ports = list(range(1, 65536))
        self.max_threads = threads
        return self.run_scan(target, ports, timeout)

    def _parse_range(self, port_range):
        if isinstance(port_range, tuple) and len(port_range) == 2:
            start, end = port_range
            return list(range(start, end + 1))
        elif isinstance(port_range, str) and '-' in port_range:
            start, end = port_range.split('-')
            return list(range(int(start), int(end) + 1))
        else:
            return [int(port_range)]

    def stop_scan(self):
        self.stop_event.set()

    def format_results(self, scan_result):
        if "error" in scan_result:
            return f"Error: {scan_result['error']}"
        
        target = scan_result.get("target", "")
        ip = scan_result.get("ip", "")
        duration = scan_result.get("duration", 0)
        open_ports = scan_result.get("open", [])
        
        lines = []
        lines.append(f"Scan report for {target} ({ip})")
        lines.append(f"Scan duration: {duration:.2f}s")
        lines.append(f"Open ports: {len(open_ports)}")
        lines.append("")
        
        if open_ports:
            lines.append("PORT\tSTATE\tSERVICE")
            lines.append("----\t-----\t-------")
            for port_info in open_ports:
                port = port_info["port"]
                service = port_info["service"]
                lines.append(f"{port}/tcp\topen\t{service}")
        else:
            lines.append("No open ports found")
        
        return "\n".join(lines)