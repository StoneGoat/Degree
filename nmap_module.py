import nmap
from xml_util import convert_dict_to_pretty_xml

nmapScan = nmap.PortScanner()

def filter_nmap_result(result):
    filtered = {}
    scan_data = result.get('scan', {})
    for host, host_data in scan_data.items():
        filtered[host] = {
            "hostnames": host_data.get("hostnames", []),
            "addresses": host_data.get("addresses", {}),
            "status": host_data.get("status", {})
        }
        if "tcp" in host_data:
            open_ports = {}
            for port, details in host_data["tcp"].items():
                if details.get("state") == "open":
                    open_ports[port] = details
            filtered[host]["open_ports"] = open_ports
    return filtered

def scan(ips):
    results = {}
    if isinstance(ips, str):
        ips = [ips]
    for ip in ips:
        raw_result = nmapScan.scan(ip, arguments='-Pn --top-ports 1000')
        filtered_result = filter_nmap_result(raw_result)
        results[ip] = filtered_result
    pretty_xml_str = convert_dict_to_pretty_xml("NmapScanResults", results)
    return pretty_xml_str

xml = scan("35.228.57.67")
print(xml)
