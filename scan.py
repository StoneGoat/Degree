import dig_module
import nmap_module
import zap_module
import nikto_module

def run_scan(domain, id):
    ips = dig_module.get_IP(domain)
    
    nmap_results = nmap_module.scan(ips)
    nikto_results = nikto_module.nikto_scan_to_xml(domain)
    
    zap_module.run_full_scan(domain, nmap_results, nikto_results, id)
    
    return "Scan complete for domain: " + domain
