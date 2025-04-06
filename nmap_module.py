import nmap
from xml_util import convert_dict_to_pretty_xml

nmapScan = nmap.PortScanner()

def scan(ips, portrange):
    results = {}
    for ip in ips:
        result = nmapScan.scan(ip, portrange, arguments='-Pn')
        results[ip] = result
    pretty_xml_str = convert_dict_to_pretty_xml("NmapScanResults", results)
    return pretty_xml_str