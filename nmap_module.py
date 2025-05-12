import nmap
import os
from xml_module import convert_dict_to_pretty_xml

RESULTS_DIR = 'scan_results'
nmap_scanner = nmap.PortScanner()

def filter_nmap_result(result):
    filtered = {}
    for host, host_data in result.get('scan', {}).items():
        entry = {
            "hostnames": host_data.get("hostnames", []),
            "addresses": host_data.get("addresses", {}),
            "status": host_data.get("status", {})
        }
        if "tcp" in host_data:
            # only keep open ports
            entry["open_ports"] = {
                port: info
                for port, info in host_data["tcp"].items()
                if info.get("state") == "open"
            }
        filtered[host] = entry
    return filtered

def scan_scan_to_xml(ips, scan_id, session_cookies=None):
    if isinstance(ips, str):
        ips = [ips]

    # Base nmap args
    args = '-sV -Pn --top-ports 1000 --script vuln'

    # Inject cookies if provided
    if session_cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in session_cookies.items())
        args += f' --script-args http.cookie="{cookie_str}"'

    results = {}
    for ip in ips:
        raw = nmap_scanner.scan(hosts=ip, arguments=args)
        results[ip] = filter_nmap_result(raw)

    xml_str = convert_dict_to_pretty_xml("NmapScanResults", results)

    out_dir = os.path.join(RESULTS_DIR, scan_id)
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, 'nmap.xml')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(xml_str)
    print(f"→ Saved Nmap report: {path}")

    return xml_str
