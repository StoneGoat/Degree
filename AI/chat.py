import xml.etree.ElementTree as ET
import requests
import re
import json

API_URL = "http://127.0.0.1:9000/chat"

model_list = {
    "segolilylabs/Lily-Cybersecurity-7B-v0.2",
    "WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0",
    "chuanli11/Llama-3.2-3B-Instruct-uncensored"
}

scan_results = {}

def send_chat_request(prompt, chat_id=None, model_id="WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0",
                      token_limit=4096, temperature=1, top_p=1, role="user"):
    payload = {
        "prompt": prompt,
        "model_id": model_id,
        "token_limit": token_limit,
        "temperature": temperature,
        "top_p": top_p,
        "role": role
    }
    if chat_id is not None:
        payload["chat_id"] = chat_id

    response = requests.post(API_URL, json=payload)
    if response.status_code == 200:
        data = response.json()
        return data["chat_id"], data["response"]
    else:
        print("Error:", response.text)
        return None, None

def interactive_chat():
    # Initialize the chat session with a system message.
    chat_id, _ = send_chat_request("You are a cyber security specialist", role="system")
    if chat_id is None:
        print("Failed to initialize chat session.")
        return
    print("Chat session started. Type 'exit' to quit.\n")
    
    while True:
        user_input = input("You: ")
        if user_input.strip().lower() == "exit":
            print("Ending chat session.")
            break
        
        chat_id, response_text = send_chat_request(user_input, chat_id=chat_id)
        if response_text is None:
            print("Error receiving response. Exiting.")
            break
        
        print("Assistant:", response_text, "\n")

def get_alert_items_from_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    alert_items = []
    # Look for the OWASPZAPReport element if it's not the root.
    zap_report = root.find('OWASPZAPReport') or root
    for site in zap_report.findall('site'):
        alerts = site.find('alerts')
        if alerts is not None:
            for alertitem in alerts.findall('alertitem'):
                alert = alertitem.find('alert').text if alertitem.find('alert') is not None else ''
                desc = alertitem.find('desc').text if alertitem.find('desc') is not None else ''
                solution = alertitem.find('solution').text if alertitem.find('solution') is not None else ''
                count = alertitem.find('count').text if alertitem.find('count') is not None else ''
                message = (f"Alert: {alert}\n"
                           f"Description: {desc}\n"
                           f"Solution: {solution}\n"
                           f"Count: {count}")
                alert_items.append(message)
    return alert_items

def parse_markdown_response_ordered(response):
    """
    Parses the markdown response by finding header lines that indicate new sections.
    It returns a list of section contents in the order they appear.
    This function expects headers in a format like:
        ### Issue Explanation:
    or optionally with a number:
        ### 1. Issue Explanation:
    and splits the response into the content sections following each header.
    """
    # Pattern: start of line, optional spaces, 1-6 '#' characters, optional number and period,
    # then the header text, followed by a colon, then end of line.
    header_pattern = re.compile(
        r'^(?:\s*#{1,6}\s*)(?:\d+\.\s*)?(.*?)\s*:\s*$',
        re.MULTILINE
    )
    headers = list(header_pattern.finditer(response))
    sections = []
    if not headers:
        return sections

    for i, match in enumerate(headers):
        start = match.end()
        end = headers[i+1].start() if i+1 < len(headers) else len(response)
        content = response[start:end].strip()
        sections.append(content)
    return sections

def save_json(data, filename):
    """Saves the data dictionary to a JSON file."""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"JSON saved as {filename}")

def test_alert_items(xml_file_path="../scan-report2.xml", model_id="WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0", scan_id=""):
    """
    Loads alert items from the XML file and sends each as a message to the AI.
    It parses the markdown response and checks that it contains exactly 5 sections.
    Instead of saving each alert separately, all alerts in one scan are aggregated
    into one JSON file with alert numbers as keys.
    """
    alert_messages = get_alert_items_from_xml(xml_file_path)
    
    prompt = """
        You are a cybersecurity expert. Given the following vulnerability alert details extracted from an OWASP ZAP report, please provide a comprehensive analysis in clear markdown format. For each section, ensure the header starts with exactly "###". The sections should be:

        1. **Issue Explanation:** Describe what the vulnerability is and why it matters.
        2. **Impact Analysis:** Explain the potential risks and security impact if this vulnerability is exploited.
        3. **Exploitation Details:** Outline how an attacker might exploit this vulnerability.
        4. **Step-by-Step Remediation:** Provide a detailed, sequential list of numbered steps to mitigate or resolve the issue.
        5. **References & Best Practices:** Include links to relevant documentation or established best practices.

        Please ensure every section header starts with exactly "###".
    """
    # Initialize the chat session with the system prompt.
    chat_id, _ = send_chat_request(prompt, role="system", model_id=model_id)
    if chat_id is None:
        print("Failed to initialize chat session.")
        return
    print("Initialized chat session with ID:", chat_id)

    fixed_keys = ["issue", "impact", "exploit", "solution", "reference"]
    scan_results["zap"] = {}
    
    for i, message in enumerate(alert_messages):
        print("Sending alert message:")
        print(message)
        max_attempts = 3
        attempt = 0
        sections = []
        while attempt < max_attempts:
            chat_id, response = send_chat_request(message, chat_id=chat_id, model_id=model_id)
            print("Response received:")
            print(response)
            sections = parse_markdown_response_ordered(response)
            
            if len(sections) == 5:
                break
            else:
                print(f"Response has {len(sections)} sections (expected 5). Resending request (attempt {attempt+1})...")
                attempt += 1
        
        if attempt == max_attempts:
            print(f"Failed to get a proper response after {max_attempts} attempts for alert {i}.")
        else:
            # Map the 6 sections to the fixed keys.
            alert_data = dict(zip(fixed_keys, sections))
            alert_name = re.search(r"Alert:\s*(.+)", message).group(1)
            print(f"Alert Name: {alert_name}")
            scan_results["zap"][f"{alert_name}"] = alert_data
            vulnerability_data = {alert_name: alert_data}
            send_vulnerability_to_api(vulnerability_data, scan_id)

        print("-" * 80)

def get_nmap_results_from_xml(file_path):
    """
    Parse the XML file and retrieve Nmap scan details.
    Returns a list of string messages formatted for the AI.
    """
    tree = ET.parse(file_path)
    root = tree.getroot()
    # Locate the NmapScanResults element (it might now be nested under <ScanReport>)
    nmap_results = root.find('NmapScanResults')
    if nmap_results is None:
        print("No NmapScanResults element found in the XML.")
        return []

    results = []
    # Iterate over each host element inside NmapScanResults.
    for host_element in nmap_results:
        host_tag = host_element.tag  # e.g. tag_35_228_57_67
        message = f"Nmap Scan Results for {host_tag}\n"
        # Extract overall scan details from the <nmap> element.
        nmap_elem = host_element.find('nmap')
        if nmap_elem is not None:
            command_line = nmap_elem.findtext('command_line', default="N/A")
            tcp_method = nmap_elem.findtext('scaninfo/tcp/method', default="N/A")
            tcp_services = nmap_elem.findtext('scaninfo/tcp/services', default="N/A")
            timestr = nmap_elem.findtext('scanstats/timestr', default="N/A")
            elapsed = nmap_elem.findtext('scanstats/elapsed', default="N/A")
            uphosts = nmap_elem.findtext('scanstats/uphosts', default="N/A")
            downhosts = nmap_elem.findtext('scanstats/downhosts', default="N/A")
            totalhosts = nmap_elem.findtext('scanstats/totalhosts', default="N/A")
            message += f"Command Line: {command_line}\n"
            message += f"Scan Info: Method: {tcp_method}, Services: {tcp_services}\n"
            message += (f"Scan Stats: Time: {timestr}, Elapsed: {elapsed} seconds, "
                        f"Up: {uphosts}, Down: {downhosts}, Total: {totalhosts}\n")
        # Extract host and port details from the <scan> element.
        scan_elem = host_element.find('scan')
        if scan_elem is not None:
            host_scan_elem = scan_elem.find(host_tag)
            if host_scan_elem is not None:
                hostname = host_scan_elem.findtext('hostnames/name', default="N/A")
                ipv4 = host_scan_elem.findtext('addresses/ipv4', default="N/A")
                state = host_scan_elem.findtext('status/state', default="N/A")
                reason = host_scan_elem.findtext('status/reason', default="N/A")
                message += f"Host: {hostname}, IP: {ipv4}, Status: {state} ({reason})\n"
                tcp_elem = host_scan_elem.find('tcp')
                if tcp_elem is not None:
                    message += "Port Details:\n"
                    for port_elem in tcp_elem:
                        port_tag = port_elem.tag
                        port_number = port_tag.split('_')[1] if '_' in port_tag else port_tag
                        port_state = port_elem.findtext('state', default="N/A")
                        port_reason = port_elem.findtext('reason', default="N/A")
                        port_name = port_elem.findtext('name', default="N/A")
                        message += f"  Port {port_number}: {port_name} is {port_state} (Reason: {port_reason})\n"
        results.append(message)
    return results

def clean_response(response):
    # List any unwanted introductory phrases you have observed
    unwanted_phrases = [
        "Here is a brief overview of the Nmap scan results in markdown format:",
        "Here is a brief overview:"
    ]
    for phrase in unwanted_phrases:
        if response.startswith(phrase):
            response = response[len(phrase):].strip()
    return response

def test_nmap_object(xml_file_path="../scan-report2.xml", 
                     model_id="WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0", scan_id=None):
    """
    Loads Nmap scan results from the XML file and sends each as a message to the AI.
    The AI response is expected to be a brief overview of the scan results in clear markdown format,
    with no introductory text. The results are aggregated into one JSON file keyed by host tag.
    """
    nmap_messages = get_nmap_results_from_xml(xml_file_path)
    print(f"DEBUG: Retrieved {len(nmap_messages)} Nmap messages from XML.")
    print(f"DEBUG: Nmap messages:\n{nmap_messages}")
    
    # Updated prompt instructing no meta text.
    prompt = """
        You are a cybersecurity expert analyzing Nmap scan results. Provide a structured analysis with these specific sections:

        ### Network Exposure Summary
        Summarize the overall network exposure based on open ports and services.

        ### Open Ports & Services
        List all open ports and running services discovered, including versions if available.

        ### Security Observations
        Identify potential security concerns based on exposed services.

        ### Recommended Actions
        Suggest specific hardening measures based on the scan findings.

        IMPORTANT: Only analyze information explicitly present in the scan results. Use concise bullet points within each section. Do not add introductory text or concluding statements.
    """
    # Initialize the chat session with the system prompt.
    chat_id, _ = send_chat_request(prompt, role="system", model_id=model_id)
    if chat_id is None:
        print("DEBUG: Failed to initialize chat session.")
        return
    print("DEBUG: Initialized chat session with ID:", chat_id)
    
    scan_results["nmap"] = {}
    
    for i, message in enumerate(nmap_messages):
        print("\nDEBUG: Processing Nmap message index", i)
        print("DEBUG: Message content:\n", message)
        
        # Send the message to the AI and get a single overview response.
        chat_id, response = send_chat_request(message, chat_id=chat_id, model_id=model_id)
        print("DEBUG: Raw response received:")
        print(response)
        
        # Clean up the response by removing any unwanted introductory text.
        cleaned_response = clean_response(response)
        print("DEBUG: Cleaned response:")
        print(cleaned_response)
        
        # Extract the host tag from the first line of the message.
        match = re.search(r"Nmap Scan Results for (.+)", message)
        host_tag = match.group(1) if match else f"host_{i}"
        print(f"DEBUG: Nmap Host Tag: {host_tag}")
        
        # Store the cleaned response as the overview.
        scan_results["nmap"][host_tag] = {"overview": cleaned_response}
        vulnerability_data = {"overview": cleaned_response}
        send_vulnerability_to_api(vulnerability_data, scan_id)
        print("-" * 80)

def send_vulnerability_to_api(vulnerability_data, scan_id=None):
    if not scan_id:
        print("Warning: No scan_id provided when sending vulnerability data")
        return None
        
    # Define the API endpoint URL
    url = f"http://localhost:5000/update?scan_id={scan_id}"
    
    # Add more detailed debugging
    print(f"Debugging vulnerability_data:")
    print(f"Type of vulnerability_data: {type(vulnerability_data)}")
    print(f"Contents of vulnerability_data: {vulnerability_data}")
    print(f"Sending vulnerability data to {url}")
    
    # Set headers for JSON content
    headers = {'Content-Type': 'application/json'}
    
    # Send the POST request to your Flask API
    try:
        # Ensure the data is JSON serializable
        json_data = json.dumps(vulnerability_data)
        print(f"JSON-serialized data: {json_data}")
        
        response = requests.post(url, data=json_data, headers=headers)
        
        if response.status_code == 200:
            print(f"Successfully sent data to API for scan {scan_id}")
            return response.json()
        else:
            print(f"Error from API: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"Exception sending data to API: {str(e)}")
        return None
  
def get_nikto_results_from_xml(file_path):
    """
    Parse the XML file and retrieve Nikto scan details.
    Returns a list of string messages formatted for the AI.
    """
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    # Locate the NiktoScanResults element
    nikto_results = root.find('NiktoScanResults')
    if nikto_results is None:
        print("No NiktoScanResults element found in the XML.")
        return []

    results = []
    # Extract the raw output
    raw_output = nikto_results.findtext('raw_output')
    if raw_output:
        message = f"Nikto Scan Results\n\n{raw_output}\n\n This is the end of the context."
        results.append(message)
    else:
        print("No raw_output found in NiktoScanResults.")
    
    return results

def test_nikto_object(xml_file_path="../scan-report2.xml", 
                     model_id="WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0", scan_id=None):
    """
    Loads Nikto scan results from the XML file and sends each as a message to the AI.
    The AI response is expected to be a structured analysis of the scan results in clear markdown format.
    """
    nikto_messages = get_nikto_results_from_xml(xml_file_path)
    print(f"DEBUG: Retrieved {len(nikto_messages)} Nikto messages from XML.")
    
    if not nikto_messages:
        print("DEBUG: No Nikto scan results found in the XML.")
        return
    
    # System prompt for Nikto analysis
    prompt = """
        You are a cybersecurity expert. Given the security scan results, provide a comprehensive analysis in clear markdown format. For each distinct vulnerability found, include these five sections with headers formatted exactly as shown:

        ### Issue Explanation
        Describe what the vulnerability is and why it matters.

        ### Impact Analysis
        Explain the potential risks and security impact if this vulnerability is exploited.

        ### Exploitation Details
        Outline how an attacker might exploit this vulnerability.

        ### Step-by-Step Remediation
        Provide a detailed, sequential list of numbered steps to mitigate or resolve the issue.

        ### References & Best Practices
        Include links to relevant documentation or established best practices.

        IMPORTANT: Only analyze vulnerabilities explicitly mentioned in the scan results. Do not invent additional vulnerabilities. If only a few issues are found, focus on providing thorough analysis of those specific findings.
    """
    
    # Initialize the chat session with the system prompt
    chat_id, _ = send_chat_request(prompt, role="system", model_id=model_id)
    if chat_id is None:
        print("DEBUG: Failed to initialize chat session.")
        return
    print("DEBUG: Initialized chat session with ID:", chat_id)
    
    # Initialize nikto section in scan_results if not already present
    if "nikto" not in scan_results:
        scan_results["nikto"] = {}
    
    for i, message in enumerate(nikto_messages):
        print("\nDEBUG: Processing Nikto message index", i)
        print("DEBUG: Message content:\n", message)
        
        # Send the message to the AI and get a structured analysis
        chat_id, response = send_chat_request(message, chat_id=chat_id, model_id=model_id)
        print("DEBUG: Raw response received:")
        print(response)
        
        # Clean up the response by removing any unwanted introductory text
        cleaned_response = clean_response(response)
        print("DEBUG: Cleaned response:")
        print(cleaned_response)
        
        # Store the cleaned response as the analysis
        scan_results["nikto"]["analysis"] = cleaned_response
        
        # Send the vulnerability data to the API if scan_id is provided
        if scan_id:
            vulnerability_data = {"nikto_analysis": cleaned_response}
            send_vulnerability_to_api(vulnerability_data, scan_id)
        
        print("-" * 80)

def run_AI(xml_file_path="../scan-report2.xml", 
                     model_id="WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0",
                     scan_id=""):
    print("Running AI")
    test_alert_items(xml_file_path, model_id, scan_id)
    test_nmap_object(xml_file_path, model_id, scan_id)
    test_nikto_object(xml_file_path, model_id, scan_id)

if __name__ == "__main__":
    mode = input("Enter 'test' to run alert items test or 'chat' for interactive chat: ").strip().lower()
    if mode == 'test':
        test_alert_items()
        test_nmap_object()
        save_json(scan_results, "scan_results.json")
    else:
        interactive_chat()
