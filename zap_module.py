import time
from zapv2 import ZAPv2
import os

# Config
API_KEY = '126gp7bpv1rfgf5aqbious8cpb'
PROXY = 'http://localhost:8080'
RESULTS_DIR = 'scan_results'

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


def save_report(id):
    xml = zap.core.xmlreport(apikey=API_KEY)
    out_dir = os.path.join(RESULTS_DIR, str(id))
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"zap.xml")
    with open(path, 'w', encoding='utf-8') as f:
        f.write(xml)
    print(f"Saved ZAP XML report to {path}")


def run_full_scan(target, id):
    target = 'https://' + target
    spider_scan(target)
    active_scan(target)
    save_report(id)