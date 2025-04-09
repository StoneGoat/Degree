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
        r'^(?:\s*#{1,6}\s*)(?:\d+\.\s*)?(.*?)(?:\s*:)?\s*$',
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

def test_alert_items(xml_file_path="../scan-report2.xml", model_id="WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0", scan_id="", level=1):
    """
    Loads alert items from the XML file and sends each as a message to the AI.
    It parses the markdown response and checks that it contains exactly 5 sections.
    Instead of saving each alert separately, all alerts in one scan are aggregated
    into one JSON file with alert numbers as keys.
    """
    alert_messages = get_alert_items_from_xml(xml_file_path)
    
    prompt = """
        You are a cybersecurity expert communicating with non-technical stakeholders. Given the following vulnerability alert details extracted from an OWASP ZAP report, please provide an accessible analysis in clear markdown format that anyone can understand. For each section, ensure the header starts with exactly "###". The sections should be:

        1. **Issue Explanation:** Explain the vulnerability using simple analogies and everyday examples. Avoid technical jargon and focus on why this matters to the business and users in real-world terms.
        2. **Impact Analysis:** Describe what could go wrong in plain language, focusing on business consequences, user trust issues, and potential financial or reputational impacts.
        3. **Exploitation Simplified:** Use a simple story or scenario to illustrate how an attacker might take advantage of this vulnerability, similar to explaining a home security issue.
        4. **Step-by-Step Remediation:** Provide practical, jargon-free steps that can be understood by management and conveyed to technical teams. Focus on the "what" more than the "how."
        5. **References & Resources:** Include beginner-friendly resources and explain why each resource is helpful.

        Please ensure every section header starts with exactly "###". Use visual metaphors, real-world comparisons, and avoid technical terminology wherever possible. If technical terms must be used, briefly explain them.
    """

    if level == 1:
        prompt = """
            You are a cybersecurity expert communicating with IT professionals who have intermediate technical knowledge. Given the following vulnerability alert details extracted from an OWASP ZAP report, please provide a balanced technical analysis in clear markdown format. For each section, ensure the header starts with exactly "###". The sections should be:

            1. **Issue Explanation:** Describe the vulnerability's technical mechanisms and security principles involved, while connecting them to practical business implications. Include context about when and where this vulnerability typically appears.
            2. **Impact Analysis:** Analyze specific security risks with concrete examples of what attackers could achieve, including data compromise scenarios, access control failures, or system disruptions.
            3. **Exploitation Details:** Outline specific methodologies an attacker might use, including tools, techniques, and prerequisites needed for successful exploitation.
            4. **Step-by-Step Remediation:** Provide detailed implementation instructions with appropriate code snippets, configuration examples, and testing procedures to verify the fix. Include both immediate fixes and long-term preventive measures.
            5. **References & Best Practices:** Include technical documentation links, relevant standards (OWASP/CWE), and industry best practices that are specifically applicable to this vulnerability.

            Please ensure every section header starts with exactly "###". Include practical examples and enough technical detail for implementation while avoiding excessive complexity that would only be relevant to security specialists.
        """
    elif level == 2:
        prompt = """
            You are a cybersecurity expert writing for security engineers and developers. Given the following vulnerability details from an OWASP ZAP report, provide an expert-level technical analysis in markdown format. For each section, ensure the header starts with exactly "###". The sections should be:

            1. **Issue Explanation:** Provide a technical analysis of the vulnerability including HTTP header mechanics, information disclosure vectors, and implementation details across common web technologies.

            2. **Impact Analysis:** Analyze the security implications including potential for fingerprinting, precise version enumeration, and how this vulnerability can be combined with other reconnaissance techniques in a sophisticated attack.

            3. **Exploitation Details:** Include specific technical methods for exploiting this vulnerability, with a code example demonstrating automated header collection and analysis.

            4. **Technical Remediation:** Provide configuration examples for at least TWO of the following platforms: Apache, Nginx, IIS, Express.js, or PHP. Include both server-level and application-level remediation approaches.

            5. **Security Resources:** Include technically-relevant references to documentation, security advisories, and implementation guides.

            Please ensure every section header starts with exactly "###" and focus on providing technically precise guidance that would be valuable to experienced security professionals.
        """

    fixed_keys = ["issue", "impact", "exploit", "solution", "reference"]
    scan_results["zap"] = {}
    
    for i, message in enumerate(alert_messages):
            # Initialize the chat session with the system prompt.
        chat_id, _ = send_chat_request(prompt, role="system", model_id=model_id)
        if chat_id is None:
            print("Failed to initialize chat session.")
            return
        print("Initialized chat session with ID:", chat_id)

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
    Parse the XML file and retrieve Nmap scan details based on the actual XML structure.
    Returns a list of string messages formatted for the AI.
    """
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    # Locate the NmapScanResults element
    nmap_results = root.find('NmapScanResults')
    if nmap_results is None:
        print("No NmapScanResults element found in the XML.")
        return []

    results = []
    # Iterate over each host element inside NmapScanResults
    for host_element in nmap_results:
        host_tag = host_element.tag  # e.g. tag_35_228_57_67
        message = f"Nmap Scan Results for {host_tag}\n"
        
        # Find the nested host element that contains the actual data
        nested_host = host_element.find(host_tag)
        if nested_host is not None:
            # Extract host details
            hostname = nested_host.findtext('hostnames/name', default="N/A")
            ipv4 = nested_host.findtext('addresses/ipv4', default="N/A")
            state = nested_host.findtext('status/state', default="N/A")
            reason = nested_host.findtext('status/reason', default="N/A")
            
            message += f"Host: {hostname}, IP: {ipv4}, Status: {state} ({reason})\n"
            
            # Extract port details from the open_ports element
            open_ports = nested_host.find('open_ports')
            if open_ports is not None:
                message += "Open Ports and Services:\n"
                for port_elem in open_ports:
                    port_tag = port_elem.tag
                    port_number = port_tag.split('_')[1] if '_' in port_tag else port_tag
                    port_state = port_elem.findtext('state', default="N/A")
                    port_reason = port_elem.findtext('reason', default="N/A")
                    port_name = port_elem.findtext('name', default="N/A")
                    port_product = port_elem.findtext('product', default="")
                    port_version = port_elem.findtext('version', default="")
                    
                    # Build a more detailed port information string
                    service_info = f"{port_name}"
                    if port_product or port_version:
                        service_info += f" ({port_product} {port_version})".strip()
                    
                    message += f"  Port {port_number}: {service_info} is {port_state} (Reason: {port_reason})\n"
            else:
                message += "No open ports found.\n"
                
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
                     model_id="WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0", scan_id=None, level=0):
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
        You are a cybersecurity expert analyzing Nmap scan results for non-technical stakeholders. Provide an easy-to-understand analysis with these specific sections:

        ### Network Exposure Summary
        Explain in simple terms what the scan found about the system's visibility to the outside world, using everyday comparisons.

        ### Open Ports & Services
        List what's "open" or accessible on the system in non-technical language, similar to explaining which doors and windows are unlocked.

        ### Security Concerns
        Describe potential risks in business terms, focusing on what these findings might mean for the organization's data and operations.

        ### Recommended Actions
        Suggest practical steps that management should consider, avoiding technical jargon and focusing on business priorities.

        IMPORTANT: Only analyze information explicitly present in the scan results. Use simple language and avoid technical terminology wherever possible. If technical terms must be used, briefly explain them.
    """

    if level == 1:
        prompt = """
            You are a cybersecurity expert analyzing Nmap scan results for IT professionals. Provide a balanced technical analysis with these specific sections:

            ### Network Exposure Summary
            Summarize the exposure profile including total open ports, most significant services, and overall attack surface assessment.

            ### Open Ports & Services
            List all discovered open ports, their associated services, and version information where available. Include a brief explanation of each service's function.

            ### Security Observations
            Identify specific security concerns based on the exposed services, including known risky configurations and potential vulnerabilities associated with detected service versions.

            ### Recommended Actions
            Provide practical remediation steps that include specific configurations and hardening measures. Include both immediate fixes and longer-term security improvements.

            IMPORTANT: Only analyze information explicitly present in the scan results. Provide technically accurate information with enough context for IT professionals to understand the implications without requiring advanced security expertise.
        """
    elif level == 2:
        prompt = """
            You are a cybersecurity expert analyzing Nmap scan results for security engineers and developers. Provide a detailed technical analysis with these specific sections:

            ### Network Exposure Analysis
            Analyze exposure including TCP sequence prediction difficulty, firewall/filtering detection, and service state analysis.

            ### Service Vulnerability Assessment
            For each service identified, provide:
            - Specific version-based vulnerabilities (if versions are detected)
            - Common misconfigurations for these services
            - Default credentials concerns
            - Protocol weaknesses

            ### Defense-in-Depth Recommendations
            Provide specific multi-layered security controls including:
            - Firewall rules with proper allow/deny logic. For example:
              # Allow SSH only from trusted network and deny all other SSH connections
              iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
              iptables -A INPUT -p tcp --dport 22 -j DROP

            - Service-specific hardening configurations (example snippets for SSH, web servers)
            - Network segmentation recommendations
            - Monitoring commands and log analysis strategies for detecting attacks

            IMPORTANT: Focus on providing specific, actionable technical guidance with concrete examples. Include command-line examples where appropriate. Ensure firewall rules follow proper security logic with specific source/destination constraints.
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
                     model_id="WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0", scan_id=None, level=0):
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
        You are a cybersecurity expert analyzing Nikto web security scan results for non-technical stakeholders. Provide an easy-to-understand analysis with these specific sections for each distinct vulnerability found:

        ### Issue Summary
        Explain the vulnerability in simple terms using everyday analogies. Avoid technical jargon and focus on why this matters to the business.

        ### Business Impact
        Describe what could go wrong in plain language, focusing on how this could affect customers, reputation, and operations.

        ### Risk Scenario
        Use a simple story or real-world comparison to illustrate how this vulnerability might be exploited.

        ### Action Steps
        Suggest practical steps that management should prioritize, explained in business terms rather than technical instructions.

        ### Additional Resources
        List beginner-friendly resources where stakeholders can learn more about this type of security issue.

        IMPORTANT: Only analyze vulnerabilities explicitly mentioned in the scan results. Use simple language and everyday comparisons. If technical terms must be used, briefly explain them.
    """
    
    if level == 1:
        prompt = """
            You are a cybersecurity expert analyzing Nikto web security scan results for IT professionals. Provide a balanced technical analysis with these specific sections for each distinct vulnerability found:

            ### Issue Explanation
            Describe the vulnerability's technical mechanisms while connecting them to practical business implications. Include context about when and where this vulnerability typically appears.

            ### Impact Assessment
            Analyze specific security risks with concrete examples of what attackers could achieve, including data compromise scenarios and system disruptions.

            ### Exploitation Methods
            Outline specific methodologies an attacker might use, including common tools and techniques needed for successful exploitation.

            ### Implementation Plan
            Provide detailed remediation instructions with appropriate configuration examples and testing procedures to verify the fix. Include both immediate mitigation and long-term solutions.

            ### Technical References
            Include documentation links, relevant standards (OWASP/CWE), and industry best practices specific to this vulnerability.

            IMPORTANT: Only analyze vulnerabilities explicitly mentioned in the scan results. Provide technically accurate information with enough context for IT professionals to understand and address the issues without requiring advanced security expertise.
        """
    elif level == 2:
        prompt = """
            You are a cybersecurity expert analyzing Nikto web security scan results for security engineers and developers. For each distinct vulnerability found, provide a technical analysis with these EXACT section headers:

            ### Technical Vulnerability Analysis
            Provide detailed technical analysis of the vulnerability including affected components, root causes, and exploitation requirements.

            ### Security Implications
            Describe attack vectors, potential exploit chains, and how this vulnerability might combine with others in sophisticated attacks.

            ### Exploitation Techniques
            Show specific code or commands that demonstrate exploitation. For example:
            curl -H "X-Frame-Options: ALLOWALL" -v http://example.com

            ### Remediation Implementation
            Provide specific configuration examples. For example:
            # Apache configuration to prevent clickjacking
            Header always append X-Frame-Options SAMEORIGIN

            # Nginx configuration to prevent clickjacking
            add_header X-Frame-Options "SAMEORIGIN";

            ### Security Resources
            Include links to CVEs, advisories and implementation guides specific to this vulnerability.

            IMPORTANT: Only analyze vulnerabilities explicitly mentioned in the scan results. You MUST use the exact section headers listed above and include code examples in your response.
        """
  
    
    # Initialize nikto section in scan_results if not already present
    if "nikto" not in scan_results:
        scan_results["nikto"] = {}
    
    for i, message in enumerate(nikto_messages):
        # Initialize the chat session with the system prompt
        chat_id, _ = send_chat_request(prompt, role="system", model_id=model_id)
        if chat_id is None:
            print("DEBUG: Failed to initialize chat session.")
            return
        print("DEBUG: Initialized chat session with ID:", chat_id)

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
                     scan_id="",
                     level=2):
    print("Running AI")
    test_alert_items(xml_file_path, model_id, scan_id, level=level)
    test_nmap_object(xml_file_path, model_id, scan_id, level)
    test_nikto_object(xml_file_path, model_id, scan_id, level)

if __name__ == "__main__":
    mode = input("Enter 'test' to run alert items test or 'chat' for interactive chat: ").strip().lower()
    if mode == 'test':
        # level = int(input("Input Level"))

        for i in range(1, 3):
          print("Testing for Level: " + str(i))
          # test_alert_items(level=i)
          # test_nmap_object(level=i)  
          test_nikto_object(level=i)
          # save_json(scan_results, "scan_results.json")
    else:
        interactive_chat()
