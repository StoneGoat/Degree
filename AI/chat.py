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
            You are a cybersecurity expert writing for technical implementers (developers, sysadmins, DevOps engineers). Given the following vulnerability alert details extracted from an OWASP ZAP report, please provide a practical, implementation-focused analysis in clear markdown format. For each section, ensure the header starts with exactly "###". The sections should be:

            1. ### Issue Explanation: Describe the vulnerability's technical mechanism, common root causes in code or configuration, and where it typically occurs within the web stack (frontend, backend, server config, etc.). Explain the direct security principle being violated.
            2. ### Impact Analysis: Detail the specific, direct technical consequences of exploitation. Provide concrete examples like "attacker could read file X," "attacker could execute command Y," "user sessions could be hijacked," or "sensitive data Z could be exposed in transit/at rest."
            3. ### Exploitation Details & Proof-of-Concept: Outline the steps an attacker might take to exploit this vulnerability. If applicable and safe, provide a simple command-line example (e.g., using `curl`) or a conceptual code snippet demonstrating the exploit technique. Mention common tools used for this specific type of finding.
            4. ### Step-by-Step Remediation & Verification: Provide detailed, actionable instructions for fixing the vulnerability. Include specific code examples, configuration snippets for relevant platforms (e.g., Apache, Nginx, IIS, framework-specific settings), required library updates, or necessary API usage changes. Crucially, describe how to test and verify that the fix has been successfully implemented. Address both immediate corrections and long-term prevention (e.g., input validation, output encoding, secure defaults). Offer configuration examples for at least ONE common platform if applicable (e.g., Apache, Nginx, IIS, Express.js, Spring Boot, PHP).
            5. ### Technical References & Best Practices: Include links to official documentation for the affected technologies, relevant OWASP Cheat Sheets, specific CWE (Common Weakness Enumeration) entries, and applicable secure coding or secure configuration best practices directly related to the fix.

            Please ensure every section header starts with exactly "###". Provide sufficient technical detail for direct implementation and validation, focusing on practical steps and verifiable outcomes.
        """
    elif level == 2:
        prompt = """
            You are a senior cybersecurity analyst communicating with fellow security professionals (engineers, analysts, pentesters). Given the following vulnerability details from an OWASP ZAP report, provide an expert-level cybersecurity analysis in markdown format. Focus on risk, threat context, and strategic mitigation. For each section, ensure the header starts with exactly "###". The sections should be:

            1. ### Technical Deep Dive: Provide a detailed technical breakdown of the vulnerability mechanism, including relevant protocols, common misconfigurations across different technology stacks, and how it manifests in the context of the application's architecture. Discuss the nuances of detection and potential false positives/negatives.
            2. ### Risk & Threat Context Analysis: Analyze the security implications in depth. Discuss potential attack chains (how this vulnerability could be combined with others), relevance to specific threat actor TTPs (Tactics, Techniques, and Procedures), impact on reconnaissance/fingerprinting, potential for bypassing existing security controls, and alignment with risk management frameworks or compliance requirements (e.g., PCI-DSS, HIPAA if applicable).
            3. ### Advanced Exploitation Vectors: Discuss sophisticated or less common methods for exploiting this vulnerability. Analyze the prerequisites, feasibility, and potential indicators of compromise (IoCs) associated with exploitation attempts. Mention relevant tools or frameworks often used by attackers for this type of vulnerability beyond basic exploitation.
            4. ### Strategic Mitigation & Defense-in-Depth: Outline comprehensive mitigation strategies. Focus on secure design principles, architectural changes, recommended configurations from a security best-practice standpoint (less about specific syntax, more about the 'why'), detection engineering opportunities (e.g., relevant logging, monitoring, WAF rule concepts), and how to integrate the fix into the broader vulnerability management program. Discuss compensating controls if immediate remediation isn't feasible.
            5. ### Advanced Security Resources & Intelligence: Include references to relevant CVEs, detailed technical write-ups, research papers, exploit databases (Exploit-DB), MITRE ATT&CK or CAPEC mappings, and threat intelligence reports discussing the exploitation of this vulnerability class in the wild.

            Please ensure every section header starts with exactly "###". Focus on providing analytical depth, strategic insights, and actionable intelligence valuable to experienced security professionals. Avoid overly generic advice and focus on the specific vulnerability context.
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
        Explain in simple terms what the scan found about the system's visibility (like which 'digital doors and windows' seem to be open or visible), using everyday comparisons.

        ### Open Ports & Services Explained
        List what's "open" or accessible on the system in non-technical language (e.g., "Web Server Access," "Remote Login Access," "File Sharing Access"). Explain briefly what purpose these openings might serve, similar to explaining the function of different doors on a building. (Formerly 'Open Ports & Services')

        ### Security Concerns
        Describe potential risks in business terms, focusing on what these open 'doors' might mean for the organization's data security, customer privacy, and operational continuity.

        ### Recommended Actions
        Suggest practical steps that management should consider (e.g., "Review if all open access points are necessary," "Ensure security settings are up-to-date"). Avoid technical jargon and focus on business priorities and instructing technical teams.

        IMPORTANT: Only analyze information explicitly present in the Nmap scan results. Use simple language and avoid technical terminology wherever possible. If technical terms must be used, briefly explain them. Ensure every section header starts with exactly "###".
    """

    if level == 1:
        prompt = """
            You are a cybersecurity expert analyzing Nmap scan results for technical implementers. Provide a practical, implementation-focused analysis in clear markdown format. For each distinct host scanned, use these specific sections:

            ### Network Exposure Summary
            Summarize the host's exposure profile based on the scan: IP address, hostname (if available), state (up/down), total open/filtered/closed ports found, and operating system guess (if Nmap provided one). Assess the immediate attack surface presented.

            ### Open Ports & Services Details
            List all discovered open and potentially open (open|filtered) ports. For each port, include: Port number, protocol (TCP/UDP), state (open, open|filtered), service name, and version information if detected by Nmap. Briefly explain the standard function of each identified service. (Combines L1 'Open Ports & Services' and adds OS info)

            ### Security Findings & Vulnerabilities
            Identify specific security concerns based on the open ports, services, and versions detected. List potential vulnerabilities associated with detected service versions (mentioning CVEs if easily identifiable from version numbers), common misconfigurations for these services, risks associated with the detected OS, and default credential possibilities. (Adapting L1 'Security Observations' & L2 'Service Vulnerability Assessment')

            ### Step-by-Step Remediation & Verification
            Provide detailed, actionable instructions for hardening the host based on the findings:
            * Instructions to close unnecessary ports (e.g., using firewall rules).
            * Steps to update vulnerable services to patched versions.
            * Specific configuration examples for hardening exposed services (e.g., SSH hardening directives, web server security headers).
            * Firewall rule examples (e.g., `iptables`, `ufw`, `firewalld`, or Windows Firewall commands) to restrict access to necessary source IPs/networks.
            * Describe how to test and verify the fixes (e.g., re-running Nmap with specific options, using netcat/telnet to test ports, checking service status and configuration). (Adapting L1 'Recommended Actions' & L2 'Defense-in-Depth Recommendations')

            ### Technical References & Best Practices
            Include links to official documentation for identified services/OS, CVE databases (like MITRE CVE or NIST NVD), OS hardening guides (e.g., CIS Benchmarks), firewall documentation, and relevant secure configuration best practices.

            IMPORTANT: Only analyze information explicitly present in the Nmap scan results. Provide sufficient technical detail for direct implementation and validation. Ensure every section header starts with exactly "###".
        """
    elif level == 2:
        prompt = """
            You are a senior cybersecurity analyst communicating with fellow security professionals regarding Nmap scan results. Provide an expert-level analysis in markdown format using these specific sections:

            ### Attack Surface Analysis
            Interpret Nmap outputs (port states, OS/service detection, NSE results, scan artifacts) to assess the host/network's detailed exposure profile and potential scan limitations.

            ### Risk & Threat Context
            Analyze the strategic risk posed by the findings, their relevance to potential attack paths and threat actor TTPs, and prioritization within the overall security posture.

            ### Advanced Assessment & Exploitation Potential
            Discuss potential follow-on assessment actions (manual testing, vuln scanning), exploitability of identified services, and interpretation of advanced Nmap indicators (e.g., timing, TCP/IPID).

            ### Strategic Hardening & Detection
            Recommend defense-in-depth strategies including network architecture considerations (segmentation), service hardening principles, advanced detection/monitoring approaches, and configuration management integration.

            ### Advanced Security Resources & Intelligence
            Provide links to relevant advanced technical resources (protocol/service specifics, CVEs), applicable threat intelligence, and related security frameworks or best practices (MITRE ATT&CK, NIST).

            IMPORTANT: Focus on deep interpretation of the provided Nmap data, strategic implications, and actionable intelligence for security professionals. Ensure every section header starts with exactly "###".
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
            You are a cybersecurity expert analyzing Nikto web security scan results for technical implementers (developers, sysadmins, DevOps engineers). Provide a practical, implementation-focused analysis in clear markdown format. For each distinct vulnerability found, use these specific sections:

            ### Issue Explanation
            Describe the vulnerability's technical mechanism (e.g., outdated component, specific misconfiguration identified by Nikto), common root causes, and where it typically occurs within the web stack. Explain the direct security principle being violated.

            ### Impact Analysis
            Detail the specific, direct technical consequences of exploitation based on the Nikto finding. Provide concrete examples like "allows directory listing," "exposes specific software version enabling known exploits," or "indicates weak SSL/TLS configuration." (Formerly 'Impact Assessment')

            ### Exploitation Details & Proof-of-Concept
            Outline the steps an attacker might take, leveraging the information from the Nikto scan. If applicable and safe, provide a simple command-line example (e.g., using `curl`, `nmap` scripts, or specific tool commands related to the finding) demonstrating the vulnerability. (Adapting 'Exploitation Methods' & 'Exploitation Techniques')

            ### Step-by-Step Remediation & Verification
            Provide detailed, actionable instructions for fixing the vulnerability identified by Nikto. Include specific configuration snippets (e.g., for Apache, Nginx, IIS based on the finding), required software updates/patches, or necessary configuration changes. Crucially, describe how to test and verify that the fix has been successfully implemented (e.g., re-running a specific Nikto check, using `openssl s_client`, checking headers). Offer configuration examples for at least ONE common platform if applicable. (Adapting 'Implementation Plan' & 'Remediation Implementation')

            ### Technical References & Best Practices
            Include links to official documentation for the affected software/protocols, relevant CVEs if version information is found, specific CWE entries, OWASP guides, and applicable secure configuration best practices directly related to the fix. (Adapting 'Technical References' & 'Security Resources')

            IMPORTANT: Only analyze vulnerabilities explicitly mentioned in the Nikto scan results. Provide sufficient technical detail for direct implementation and validation. Ensure every section header starts with exactly "###".
        """
    elif level == 2:
        prompt = """
            You are a senior cybersecurity analyst communicating with fellow security professionals (engineers, analysts, pentesters) regarding Nikto web security scan results. Provide an expert-level cybersecurity analysis in markdown format for each distinct vulnerability found. Focus on risk, threat context, and strategic mitigation using these specific sections:

            ### Technical Deep Dive
            Provide a detailed technical breakdown of the vulnerability mechanism as identified or suggested by the Nikto finding. Discuss relevant protocols, underlying component weaknesses, potential variations not explicitly tested by Nikto, and nuances of accurate detection versus potential false positives associated with the Nikto check.

            ### Risk & Threat Context Analysis
            Analyze the security implications in depth. Discuss how this finding contributes to the overall attack surface, potential attack chains (how this could be leveraged with other weaknesses), relevance to specific threat actor TTPs targeting this type of vulnerability/component, value for reconnaissance/fingerprinting, potential for bypassing security controls, and alignment with risk management or compliance frameworks.

            ### Advanced Exploitation Vectors
            Discuss sophisticated or less common methods for exploiting the weakness indicated by the Nikto finding, going beyond the basic check. Analyze prerequisites, feasibility, potential impact variations, and indicators of compromise (IoCs) associated with exploitation attempts targeting this vulnerability. Mention relevant advanced tools or manual techniques.

            ### Strategic Mitigation & Defense-in-Depth
            Outline comprehensive mitigation strategies related to the finding. Focus on secure design principles, architectural considerations (e.g., network segmentation, WAF placement), security configuration hardening principles (the 'why' behind specific settings), detection engineering opportunities (specific logging, monitoring alerts, WAF rule logic), and integrating the fix into vulnerability management. Discuss compensating controls.

            ### Advanced Security Resources & Intelligence
            Include references to relevant CVEs (especially for version-specific findings), detailed technical write-ups on the vulnerability class, exploit databases (Exploit-DB), relevant research papers, MITRE ATT&CK or CAPEC mappings, and threat intelligence reports discussing the exploitation of this type of finding in the wild.

            IMPORTANT: Only analyze vulnerabilities explicitly mentioned in the Nikto scan results. Focus on providing analytical depth, strategic insights, and actionable intelligence valuable to experienced security professionals. Ensure every section header starts with exactly "###".
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
    test_nmap_object(xml_file_path, model_id, scan_id, level=level)
    test_nikto_object(xml_file_path, model_id, scan_id, level=level)

if __name__ == "__main__":
    mode = input("Enter 'test' to run alert items test or 'chat' for interactive chat: ").strip().lower()
    if mode == 'test':
        # level = int(input("Input Level"))

        for i in range(2, 3):
          print("Testing for Level: " + str(i))
          # test_alert_items(level=i)
          test_nmap_object(level=i)  
          # test_nikto_object(level=i)
          # save_json(scan_results, "scan_results.json")
    else:
        interactive_chat()
