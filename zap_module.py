#!/usr/bin/env python3
import time
from zapv2 import ZAPv2
import json

# Configuration
API_KEY = 'ctrj0tgroh8lurrpffi4sdqibm'
PROXY = 'http://localhost:8080'  # assuming default port 8080

# Initialize ZAP client with the specified proxy and API key
zap = ZAPv2(apikey=API_KEY, proxies={'http': PROXY, 'https': PROXY})

def spider_scan(target_url):
    """
    Initiates a spider scan on the target URL and polls until completion.
    """
    print(f"Starting Spider scan on {target_url}")
    scan_id = zap.spider.scan(target_url)
    time.sleep(2)  # give ZAP time to start the scan

    # Poll the status until the scan completes (status == 100)
    while int(zap.spider.status(scan_id)) < 100:
        progress = zap.spider.status(scan_id)
        print(f"Spider progress: {progress}%")
        time.sleep(2)
    print("Spider scan completed.")

def active_scan(target_url):
    """
    Initiates an active scan on the target URL and polls until completion.
    """
    print(f"Starting Active scan on {target_url}")
    scan_id = zap.ascan.scan(target_url)
    time.sleep(2)  # give ZAP time to start the scan

    # Poll the status until the scan completes (status == 100)
    while int(zap.ascan.status(scan_id)) < 100:
        progress = zap.ascan.status(scan_id)
        print(f"Active scan progress: {progress}%")
        time.sleep(5)
    print("Active scan completed.")

def save_report(results):
    with open("scan-report.xml", "w") as f:
        f.write(zap.core.xmlreport(apikey=API_KEY))
    with open("scan-report.xml", "a") as f:
        f.write("\n" + json.dumps(results, indent=4))



def run_full_scan(target, results):
    target = 'https://' + target
    spider_scan(target)
    active_scan(target)
    save_report(results)

