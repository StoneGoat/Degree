#!/usr/bin/env python3
import time
from zapv2 import ZAPv2
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

# Config
API_KEY = '126gp7bpv1rfgf5aqbious8cpb'
PROXY = 'http://localhost:8080'

zap = ZAPv2(apikey=API_KEY, proxies={'http': PROXY, 'https': PROXY})

def spider_scan(target_url):
    print(f"Starting Spider scan on {target_url}")
    scan_id = zap.spider.scan(target_url)
    time.sleep(2)

    # Poll the status until the scan completes
    while int(zap.spider.status(scan_id)) < 100:
        progress = zap.spider.status(scan_id)
        print(f"Spider progress: {progress}%")
        time.sleep(2)
    print("Spider scan completed.")

def active_scan(target_url):
    print(f"Starting Active scan on {target_url}")
    scan_id = zap.ascan.scan(target_url)
    time.sleep(2)

    # Poll the status until the scan completes
    while True:
        status_str = zap.ascan.status(scan_id)
        try:
            status = int(status_str)
        except ValueError:
            print(f"Active scan status returned an unexpected value: '{status_str}'. Exiting scan loop.")
            break
        if status >= 100:
            break
        print(f"Active scan progress: {status}%")
        time.sleep(5)
    print("Active scan completed.")


def save_report(nmap_results_xml, nikto_results_xml, id):
    # Get the ZAP report as an XML string
    zap_xml_str = zap.core.xmlreport(apikey=API_KEY)
    try:
        zap_root = ET.fromstring(zap_xml_str)
    except ET.ParseError as e:
        zap_root = ET.Element("zapReport")
        zap_root.text = "Error parsing ZAP report: " + str(e)
    
    # Parse the nmap results XML
    try:
        nmap_root = ET.fromstring(nmap_results_xml)
    except ET.ParseError as e:
        nmap_root = ET.Element("nmapResults")
        nmap_root.text = "Error parsing nmap report: " + str(e)

    try:
        nikto_root = ET.fromstring(nikto_results_xml)
    except ET.ParseError as e:
        nikto_root = ET.Element("nmapResults")
        nikto_root.text = "Error parsing nmap report: " + str(e)
    
    # Create a final root element
    final_root = ET.Element("ScanReport")
    final_root.append(zap_root)
    final_root.append(nmap_root)
    final_root.append(nikto_root)
    
    # Convert the final XML tree to a string
    xml_string = ET.tostring(final_root, encoding='unicode', method='xml')
    
    with open(f"scan-report{id}.xml", "w") as f:
        f.write(xml_string)


def run_full_scan(target, nmap_results, nikto_results, id):
    target = 'https://' + target
    spider_scan(target)
    active_scan(target)
    save_report(nmap_results, nikto_results)