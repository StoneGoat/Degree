import subprocess
import os
from xml_module import convert_dict_to_pretty_xml
from dotenv import load_dotenv
from pathlib import Path

dotenv_path = Path('.env/.env')
load_dotenv(dotenv_path=dotenv_path)
RESULTS_DIR = os.getenv('RESULTS_DIR')

def nikto_scan_to_xml(target, scan_id, session_cookies=None):
    flag = '-h' if not target.startswith(('http://', 'https://')) else '-url'

    cmd = [
        'nikto',
        flag, target,
        '-nointeractive',
        '-Display', 'E4',
        '-usecookies'
    ]
    
    if session_cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in session_cookies.items())
        cmd += ['-O', f'STATIC-COOKIE={cookie_str}']

    print("CMD: " + str(cmd))

    proc = subprocess.run(cmd, capture_output=True, text=True)
    raw = proc.stdout or ''
    if proc.returncode != 0:
        raw += "\n\n[nikto stderr]\n" + proc.stderr

    xml_str = convert_dict_to_pretty_xml("NiktoScanResults",
                                         {"raw_output": raw})

    out_dir = os.path.join(RESULTS_DIR, scan_id)
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, 'nikto.xml')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(xml_str)
    print(f"→ Saved Nikto report: {path}")

    return xml_str
