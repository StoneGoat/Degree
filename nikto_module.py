import subprocess
import os
from xml_util import convert_dict_to_pretty_xml

def nikto_scan(target):
    output_file = 'nikto_output.txt'
    command = ['nikto', '-host', target, '-Display', 'E4']
    with open(output_file, 'w') as f:
        subprocess.run(command, stdout=f, stderr=subprocess.PIPE, text=True)
    with open(output_file, 'r') as f:
        scan_results = f.read()
    return scan_results

def parse_nikto_output(output):
    return {"raw_output": output}

def nikto_scan_to_xml(target):
    output = nikto_scan(target)
    os.remove('nikto_output.txt')
    parsed_output = parse_nikto_output(output)
    return convert_dict_to_pretty_xml("NiktoScanResults", parsed_output)

