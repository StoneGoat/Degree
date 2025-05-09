from concurrent.futures import ThreadPoolExecutor, as_completed
import dig_module
import nmap_module
import nikto_module
import zap_module
import AI.chat as chat

def run_scan(domain, scan_id, level):
    ips = dig_module.get_IP(domain)

    def do_nmap():
        xml = nmap_module.scan_scan_to_xml(ips, scan_id)
        print("NMAP SCAN DONE")
        print("NMAP SCAN DONE")
        print("NMAP SCAN DONE")
        print("NMAP SCAN DONE")
        print("NMAP SCAN DONE")
        print("NMAP SCAN DONE")
        print("NMAP SCAN DONE")
        print("NMAP SCAN DONE")
        chat.run_nmap_analysis(f"scan_results/{scan_id}/nmap.xml", scan_id, level)
        return xml

    def do_nikto():
        xml = nikto_module.nikto_scan_to_xml(domain, scan_id)
        print("NIKTO SCAN DONE")
        print("NIKTO SCAN DONE")
        print("NIKTO SCAN DONE")
        print("NIKTO SCAN DONE")
        print("NIKTO SCAN DONE")
        print("NIKTO SCAN DONE")
        print("NIKTO SCAN DONE")
        print("NIKTO SCAN DONE")
        print("NIKTO SCAN DONE")
        chat.run_nikto_analysis(f"scan_results/{scan_id}/nikto.xml", scan_id, level)
        return xml
    
    def do_zap():
        xml = zap_module.run_full_scan(domain, scan_id)
        chat.run_zap_analysis(xml, scan_id, level)
        return xml

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(do_nmap): 'nmap',
            executor.submit(do_nikto): 'nikto',
            executor.submit(do_zap): 'zap',
        }
        for fut in as_completed(futures):
            which = futures[fut]
            try:
                _ = fut.result()
                print(f"[{scan_id}] {which.upper()} scan done")
            except Exception as e:
                print(f"[{scan_id}] Error in {which} scan: {e}")

    return f"Scan complete for domain: {domain}"
