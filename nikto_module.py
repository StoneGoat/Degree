import subprocess
import os
from xml_module import convert_dict_to_pretty_xml

RESULTS_DIR = 'scan_results'

def nikto_scan_to_xml(target, scan_id):
    cmd = ['nikto', '-host', target, '-Display', 'E4']
    proc = subprocess.run(cmd, capture_output=True, text=True)
    raw = proc.stdout or ''
    if proc.returncode != 0:
        raw += "\n\n[nikto stderr]\n" + proc.stderr

    parsed = {"raw_output": raw}
    xml_str = convert_dict_to_pretty_xml("NiktoScanResults", parsed)

    out_dir = os.path.join(RESULTS_DIR, scan_id)
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f'nikto.xml')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(xml_str)
    print(f"→ Saved Nikto report: {path}")

    return xml_str
