from Tools import Cracker, WebScanner, OSINT, PortScanner
import os, sys, time, shlex

def setup_tools():
    try:
        cracker = Cracker()
        scanner = PortScanner()
        osint = OSINT()
        webscanner = WebScanner()
        return cracker, scanner, osint, webscanner
    except Exception as e:
        print(f"Error initializing tools: {e}")
        sys.exit(1)

cracker, scanner, osint, webscanner = setup_tools()

banner = """
    ███████╗███████╗
    ██╔════╝╚══███╔╝
    █████╗    ███╔╝ 
    ██╔══╝   ███╔╝  
    ███████╗███████╗
    ╚══════╝╚══════╝
    
    By: iamkhin
"""

def osintmenu():
    while True:
        print("\n" + "="*50)
        print("OSINT MENU")
        print("="*50)
        print("1. Username Search")
        print("2. Email Analysis")
        print("3. Phone Verification")
        print("4. WHOIS Lookup")
        print("5. Back to Main Menu")
        
        choice = input("\nSelect option: ").strip()
        
        if choice == '1':
            username = input("Enter username: ").strip()
            if username:
                print("\nSearching...")
                result = osint.username(username)
                print(f"\n{result}")
            else:
                print("Invalid username")
                
        elif choice == '2':
            email = input("Enter email: ").strip()
            if email:
                result = osint.email(email)
                print(f"\n{result}")
            else:
                print("Invalid email")
                
        elif choice == '3':
            phone = input("Enter phone number: ").strip()
            if phone:
                result = osint.phone(phone)
                print(f"\n{result}")
            else:
                print("Invalid phone number")
                
        elif choice == '4':
            domain = input("Enter domain: ").strip()
            if domain:
                print("\nRetrieving WHOIS information...")
                result = osint.whois(domain)
                print(f"\n{result}")
            else:
                print("Invalid domain")
                
        elif choice == '5':
            return
        else:
            print("Invalid choice")

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def parse_scan_input(raw):
    parts = raw.split()
    if not parts:
        return None, []
    if parts[0].lower() == "scan":
        parts = parts[1:]
    target = parts[0] if parts else None
    options = parts[1:] if len(parts) > 1 else []
    return target, options

def build_port_range_from_options(options):
    if "-p" in options:
        try:
            pidx = options.index("-p")
            prange = options[pidx+1]
            if "-" in prange:
                start_port, end_port = map(int, prange.split("-", 1))
            else:
                start_port = end_port = int(prange)
            return (start_port, end_port)
        except Exception:
            return None
    return None

def run_scan_command(target, options):
    scan_type = None
    port_range = build_port_range_from_options(options)
    
    if "-T" in options:
        scan_type = "quick"
    elif "-F" in options:
        scan_type = "full"
    elif "-S" in options:
        scan_type = "stealth"
    elif "-V" in options:
        scan_type = "service"
    elif "-A" in options:
        scan_type = "aggressive"
    
    if scan_type == "quick":
        return scanner.quick_scan(target)
    elif scan_type == "full":
        return scanner.full_scan(target)
    elif scan_type == "stealth":
        return scanner.stealth_scan(target, port_range=port_range)
    elif scan_type == "service":
        return scanner.service_scan(target)
    elif scan_type == "aggressive":
        return scanner.aggressive_scan(target)
    elif port_range:
        return scanner.scan(target, port_range=port_range)
    else:
        return scanner.quick_scan(target)

def display_web_results(results):
    critical = [r for r in results if r['severity'] == 'CRITICAL']
    high = [r for r in results if r['severity'] == 'HIGH']
    medium = [r for r in results if r['severity'] == 'MEDIUM']
    low = [r for r in results if r['severity'] == 'LOW']
    info = [r for r in results if r['severity'] == 'INFO']
    
    if critical:
        print("\n🔴 CRITICAL VULNERABILITIES:")
        for vuln in critical:
            print(f"  {vuln['type']}")
            print(f"    URL: {vuln['url']}")
            if 'parameter' in vuln:
                print(f"    Parameter: {vuln['parameter']}")
            if 'payload' in vuln:
                print(f"    Payload: {vuln['payload']}")
            print(f"    Impact: {vuln['impact']}")
            print()
    
    if high:
        print("\n🟠 HIGH VULNERABILITIES:")
        for vuln in high:
            print(f"  {vuln['type']}")
            print(f"    URL: {vuln['url']}")
            if 'parameter' in vuln:
                print(f"    Parameter: {vuln['parameter']}")
            if 'payload' in vuln:
                print(f"    Payload: {vuln['payload']}")
            if 'status' in vuln:
                print(f"    Status: {vuln['status']}")
            print(f"    Impact: {vuln['impact']}")
            print()
    
    if medium:
        print("\n🟡 MEDIUM VULNERABILITIES:")
        for vuln in medium:
            print(f"  {vuln['type']}")
            print(f"    URL: {vuln['url']}")
            if 'status' in vuln:
                print(f"    Status: {vuln['status']}")
            if 'missing' in vuln:
                print(f"    Missing Headers: {', '.join(vuln['missing'])}")
            if 'service' in vuln:
                print(f"    Service: {vuln['service']}")
            print(f"    Impact: {vuln['impact']}")
            print()
    
    if low:
        print("\n🔵 LOW VULNERABILITIES:")
        for vuln in low:
            print(f"  {vuln['type']}")
            print(f"    Service: {vuln['service']}")
            print(f"    Host: {vuln['host']}")
            print(f"    Impact: {vuln['impact']}")
            print()
    
    if info:
        print("\nℹ️  INFORMATION:")
        for vuln in info:
            print(f"  {vuln['type']}")
            print(f"    URL: {vuln['url']}")
            print(f"    Impact: {vuln['impact']}")
            print()
    
    print(f"Total vulnerabilities found: {len(results)}")
    print(f"Critical: {len(critical)}, High: {len(high)}, Medium: {len(medium)}, Low: {len(low)}, Info: {len(info)}")

def scanner_menu():
    while True:
        print("\n" + "="*50)
        print("SCANNER")
        print("="*50)
        print("Supported commands:")
        print("  scan <target> -T          Quick scan")
        print("  scan <target> -F          Full scan")
        print("  scan <target> -S          Stealth scan")
        print("  scan <target> -V          Service scan")
        print("  scan <target> -A          Aggressive scan")
        print("  scan <target> -p 20-80    Custom port range")
        print("  webscan <url>             Web vulnerability scan")
        print("  back                       Return to main menu")
        
        raw = input("\nscan> ").strip()
        
        if raw.lower() == 'back':
            return
            
        if not raw:
            continue

        if raw.lower().startswith("webscan "):
            target = raw[8:].strip()
            if target:
                try:
                    print(f"\nStarting web vulnerability scan for: {target}")
                    results = webscanner.full_scan(target)
                    print("\n" + "="*50)
                    print("WEB VULNERABILITY SCAN RESULTS")
                    print("="*50)
                    display_web_results(results)
                    print("="*50)
                    input("\nPress Enter to continue...")
                except Exception as e:
                    print(f"Error during web scan: {str(e)}")
                    input("\nPress Enter to continue...")
            else:
                print("Usage: webscan <url>")
            continue
            
        target, options = parse_scan_input(raw)
        
        if not target:
            print("Usage: scan <target> [options]")
            continue
            
        try:
            print(f"\nScanning {target}...")
            results = run_scan_command(target, options)
            print("\n" + "="*50)
            print(scanner.format_results(results))
            print("="*50)
            input("\nPress Enter to continue...")
            
        except PermissionError:
            print("Error: This scan requires administrator/root privileges")
            input("\nPress Enter to continue...")
        except Exception as e:
            print(f"Error during scan: {str(e)}")
            input("\nPress Enter to continue...")

def cracker_menu():
    print("\n" + "="*50)
    print("PASSWORD CRACKER")
    print("="*50)
    print("Supported services: ftp, ssh, telnet, smtp, http, mysql, mssql, rdp, vnc, smb, redis, postgres, webdav, zip")
    print("Usage: crack <service> <target> <username> <wordlist> [threads] [-d|-b]")
    print("  -d : Dictionary attack (default)")
    print("  -b : Brute force attack")
    print("Type 'back' to return to main menu")
    
    while True:
        cmd = input("\ncrack> ").strip()
        
        if cmd.lower() == 'back':
            return
            
        if not cmd.startswith("crack "):
            print("Usage: crack <service> <target> <username> <wordlist> [threads] [-d|-b]")
            continue
            
        try:
            args = shlex.split(cmd)
        except Exception as e:
            print(f"Error parsing command: {e}")
            continue
            
        if len(args) < 5:
            print("Usage: crack <service> <target> <username> <wordlist> [threads] [-d|-b]")
            continue
            
        service = args[1]
        target = args[2]
        username = args[3]
        wordlist = args[4]
        threads = 4
        attack_type = "dict"
        min_len = 1
        max_len = 4
        
        i = 5
        while i < len(args):
            if args[i].isdigit():
                threads = int(args[i])
            elif args[i] == "-d":
                attack_type = "dict"
            elif args[i] == "-b":
                attack_type = "bruteforce"
                if i + 2 < len(args) and args[i+1].isdigit() and args[i+2].isdigit():
                    min_len = int(args[i+1])
                    max_len = int(args[i+2])
                    i += 2
            i += 1
        
        if attack_type == "dict":
            if not os.path.exists(wordlist):
                print(f"Error: Wordlist file not found: {wordlist}")
                input("\nPress Enter to continue...")
                continue
        
        if service == "zip" and attack_type == "dict":
            if not os.path.exists(target):
                print(f"Error: ZIP file not found: {target}")
                input("\nPress Enter to continue...")
                clear()
                continue
        
        try:
            cracker_instance = Cracker(target, username, wordlist, threads)
            if attack_type == "bruteforce":
                print(f"\nStarting {service} brute force attack on {target} (length {min_len}-{max_len})...")
            else:
                print(f"\nStarting {service} dictionary attack on {target}...")
            result = cracker_instance.start_attack(service, attack_type, min_len, max_len)
            print(f"\n{result}")
        except Exception as e:
            print(f"Error: {e}")
        input("\nPress Enter to continue...")

def menu():
    while True:
        clear()
        print(banner)
        print("1. OSINT Tools")
        print("2. Port Scanner")
        print("3. Password Cracker")
        print("4. Web Scanner")
        print("5. Exit")
    
        choice = input("\nSelect option: ").strip()
        
        if choice == '1':
            clear()
            osintmenu()
        elif choice == '2':
            clear()
            scanner_menu()
        elif choice == '3':
            clear()
            cracker_menu()
        elif choice == '4':
            sys.exit(0)
        elif choice.startswith("scan "):
            try:
                target, options = parse_scan_input(choice)
                if not target:
                    print("Usage: scan <target> [options]")
                    input("\nPress Enter to continue...")
                    continue
                    
                print(f"\nScanning {target}...")
                results = run_scan_command(target, options)
                print("\n" + scanner.format_results(results))
                input("\nPress Enter to continue...")
                
            except Exception as e:
                print(f"Error: {e}")
                input("\nPress Enter to continue...")
                
        elif choice.startswith("crack "):
            try:
                args = shlex.split(choice)
            except Exception as e:
                print(f"Error parsing command: {e}")
                input("\nPress Enter to continue...")
                continue
                
            if len(args) < 5:
                print("Usage: crack <service> <target> <username> <wordlist> [threads] [-d|-b]")
                input("\nPress Enter to continue...")
                clear()
                continue
                
            service = args[1]
            target = args[2]
            username = args[3]
            wordlist = args[4]
            threads = 4
            attack_type = "dict"
            min_len = 1
            max_len = 4
            
            i = 5
            while i < len(args):
                if args[i].isdigit():
                    threads = int(args[i])
                elif args[i] == "-d":
                    attack_type = "dict"
                elif args[i] == "-b":
                    attack_type = "bruteforce"
                    if i + 2 < len(args) and args[i+1].isdigit() and args[i+2].isdigit():
                        min_len = int(args[i+1])
                        max_len = int(args[i+2])
                        i += 2
                i += 1
            
            if attack_type == "dict":
                if not os.path.exists(wordlist):
                    print(f"Error: Wordlist file not found: {wordlist}")
                    input("\nPress Enter to continue...")
                    continue
            
            if service == "zip" and attack_type == "dict":
                if not os.path.exists(target):
                    print(f"Error: ZIP file not found: {target}")
                    input("\nPress Enter to continue...")
                    continue
            
            try:
                cracker_instance = Cracker(target, username, wordlist, threads)
                if attack_type == "bruteforce":
                    print(f"\nStarting {service} brute force attack on {target} (length {min_len}-{max_len})...")
                else:
                    print(f"\nStarting {service} dictionary attack on {target}...")
                result = cracker_instance.start_attack(service, attack_type, min_len, max_len)
                print(f"\n{result}")
            except Exception as e:
                print(f"Error: {e}")
            input("\nPress Enter to continue...")
        elif choice.startswith("webscan "):
            target = choice[8:].strip()
            if target:
                try:
                    print(f"\nStarting web vulnerability scan for: {target}")
                    results = webscanner.full_scan(target)
                    print("\n" + "="*50)
                    print("WEB VULNERABILITY SCAN RESULTS")
                    print("="*50)
                    display_web_results(results)
                    print("="*50)
                    input("\nPress Enter to continue...")
                except Exception as e:
                    print(f"Error during web scan: {str(e)}")
                    input("\nPress Enter to continue...")
            else:
                print("Usage: webscan <url>")
                input("\nPress Enter to continue...")
        else:
            print("Invalid choice")
            input("\nPress Enter to continue...")
            clear()

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"\nCritical error: {e}")
        sys.exit(1)