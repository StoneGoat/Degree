from concurrent.futures import ThreadPoolExecutor, as_completed
import dig_module
import nmap_module
import nikto_module
import zap_module
import session_cookie_module
import AI.chat as chat
import frontend

def run_scan(domain, scan_id, level, login_url, username=None, password=None):
    session_cookies = None
    if username and password:
        session_cookies = session_cookie_module.get_session(
            login_url,
            username=username,
            password=password
        )

    ips = dig_module.get_IP(domain)

    def do_nmap():
        xml = nmap_module.scan_scan_to_xml(ips, scan_id, session_cookies)
        print(f"[{scan_id}] NMAP scan done")
        frontend.send_nmap_to_AI(f"scan_results/{scan_id}/nmap.xml", scan_id=scan_id, level=level)
        return xml

    def do_nikto():
        xml = nikto_module.nikto_scan_to_xml(domain, scan_id, session_cookies)
        print(f"[{scan_id}] NIKTO scan done")
        frontend.send_nikto_to_AI(f"scan_results/{scan_id}/nikto.xml", scan_id, level)
        return xml

    def do_zap():
        xml = zap_module.run_authenticated_scan(domain, username, password, scan_id, session_cookies)
        print(f"[{scan_id}] ZAP scan done")
        frontend.send_zap_to_AI(xml, scan_id, level)
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
                fut.result()
            except Exception as e:
                print(f"[{scan_id}] Error in {which} scan: {e}")

    return f"Scan complete for domain: {domain}"

#run_scan("https://vuln.stenaeke.org/", "jkahsdkasejajhsdjahsd", 2, "admin", "password")
