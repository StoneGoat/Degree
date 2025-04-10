import dig_module
import nmap_module
import zap_module
import nikto_module

def run_scan(domain, id):
    # Get the IPs for the provided domain
    ips = dig_module.get_IP(domain)
    
    # Run nmap scan on the IPs within the given port range
    nmap_results = nmap_module.scan(ips)
    nikto_results = nikto_module.nikto_scan_to_xml(domain)
    
    # Run the full scan with OWASP ZAP using the domain and nmap results
    zap_module.run_full_scan(domain, nmap_results, nikto_results, id)
    
    # Optionally, return a report or results for further processing
    return "Scan complete for domain: " + domain


##TESTING ONLY####
def scan(domain):
    ips = dig_module.get_IP(domain)
    print(ips)
    portmin = "0"
    portmax = "50"
    portrange = f"{portmin}-{portmax}"
    
    # Run nmap scan on the IPs within the given port range
    results = nmap_module.scan(ips, portrange)
    print(results)