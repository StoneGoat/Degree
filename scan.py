# scan.py

from concurrent.futures import ThreadPoolExecutor, as_completed
import dig_module
import nmap_module
import nikto_module
import zap_module
import AI.chat as chat  # if you still need to fire off AI early

def run_scan(domain, scan_id, level):
    ips = dig_module.get_IP(domain)

    # 1) helper wrappers if you want to trigger AI-as-soon-as-nmap/nikto finish:
    def do_nmap():
        xml = nmap_module.scan_scan_to_xml(ips, scan_id)
        chat.run_nmap_analysis(xml, scan_id, level)
        return xml

    def do_nikto():
        xml = nikto_module.nikto_scan_to_xml(domain, scan_id)
        chat.run_nikto_analysis(xml, scan_id, level)
        return xml

    # 2) run them concurrently
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            executor.submit(do_nmap): 'nmap',
            executor.submit(do_nikto): 'nikto',
        }
        for fut in as_completed(futures):
            which = futures[fut]
            try:
                _ = fut.result()
                print(f"[{scan_id}] {which.upper()} scan done")
            except Exception as e:
                print(f"[{scan_id}] Error in {which} scan: {e}")

    # 3) now run ZAP (which writes zap-report-<scan_id>.xml)
    zap_module.run_full_scan(domain, scan_id)

    return f"Scan complete for domain: {domain}"
