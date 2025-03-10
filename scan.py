from pymetasploit3.msfrpc import MsfRpcClient
import dig_module
import nmap_module
import zap_module

def run_scan(domain):
    # Get the IPs for the provided domain
    ips = dig_module.get_IP(domain)
    
    portmin = "0"
    portmax = "50"
    portrange = f"{portmin}-{portmax}"
    
    # Run nmap scan on the IPs within the given port range
    results = nmap_module.scan(ips, portrange)
    
    # Run the full scan with OWASP ZAP using the domain and nmap results
    zap_module.run_full_scan(domain, results)
    
    # Optionally, return a report or results for further processing
    return "Scan complete for domain: " + domain
