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
                      token_limit=4096, temperature=1, top_p=1, role="user", level=0):
    payload = {
        "prompt": prompt,
        "model_id": model_id,
        "token_limit": token_limit,
        "temperature": temperature,
        "top_p": top_p,
        "role": role,
        "level": level
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

def get_alert_items_from_xml(file_path, level=0):
    tree = ET.parse(file_path)
    root = tree.getroot()
    alert_items = []
    
    # Use the root directly since OWASPZAPReport is the root element in the XML
    # This line is the key fix:
    zap_report = root
    
    for site in zap_report.findall('site'):
        alerts = site.find('alerts')
        if alerts is not None:
            for alertitem in alerts.findall('alertitem'):
                
                if alertitem.find('riskcode').text == '0' and level<2:
                    continue

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
    alert_messages = get_alert_items_from_xml(xml_file_path, level)
    
    prompt = """
        You are a cybersecurity expert writing specifically for **non-technical managers and stakeholders**. Your absolute primary goal is **clarity and making complex topics feel simple and relatable using everyday language**. Pretend you are explaining this to someone with no tech background.

        Analyze the provided OWASP ZAP vulnerability details and generate a report in clear markdown format.

        **Report Structure:** It is essential that your response is structured into **exactly the following five sections**, presented in this order. Ensure **all five sections are included** and contain helpful information tailored for this non-technical audience. Use Markdown H3 (starting with ###) for each section header.

        1.  ### Issue Explanation:
            * **Style Requirement:** Your explanation **must use simple analogies and relatable, everyday examples**. Focus entirely on *why* this matters in real-world terms. **Strictly avoid technical jargon**. (Example tone: Like explaining why leaving your house keys under the doormat is risky).
        2.  ### Impact Analysis:
            * **Style Requirement:** Describe potential negative outcomes using only **plain language**. Focus specifically on tangible **business consequences** (e.g., costs, service downtime), damage to **user trust**, and potential **financial or reputational harm**. Quantify if possible (e.g., "could cost X", "affect Y users").
        3.  ### Exploitation Simplified:
            * **Style Requirement:** Tell a **simple story or scenario** showing how an attacker might misuse this. **Use a real-world comparison** (like explaining how a simple scam works). Keep it easy to visualize and **strictly non-technical**.
        4.  ### Step-by-Step Remediation:
            * **Style Requirement:** Provide **practical, completely jargon-free action steps**. Focus on the 'what' (e.g., "ask the tech team to check setting X", "prioritize updating software Y") in terms a manager can understand and communicate. Think "instructions for a smart friend".
        5.  ### References & Resources:
            * **Style Requirement:** Provide 1-3 links ONLY to **genuinely beginner-friendly resources** (e.g., simple articles, short explanatory videos - avoid dense technical docs). For each link, briefly explain in **simple terms why it's helpful** for someone non-technical.

        **Final Instructions:** Review your entire response before finishing. Ensure it strictly follows the **five-section structure** AND maintains the **consistently non-technical, analogy-rich, story-driven style** requested throughout. **The non-technical, easy-to-understand style is just as crucial as the five-section structure.** Do not include any other sections.
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

    chat_id, _ = send_chat_request(prompt, role="system", model_id=model_id)
    
    for i, message in enumerate(alert_messages):
        if i % 3 == 0:
            chat_id, _ = send_chat_request(prompt, role="system", model_id=model_id)

            # Initialize the chat session with the system prompt.
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
            chat_id, response = send_chat_request(message, chat_id=chat_id, model_id=model_id, level=level)
            print("Response received:")
            print(response)
            sections = parse_markdown_response_ordered(response)

            break
            
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
            send_vulnerability_to_api(vulnerability_data, scan_id, 4)

        print("-" * 80)

def get_nmap_results_from_xml(file_path):
    """
    Parse the XML file and retrieve Nmap scan details based on the actual XML structure.
    Returns a list of string messages formatted for the AI.
    """
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    # Check if the root element is NmapScanResults
    if root.tag != 'NmapScanResults':
        print(f"Expected NmapScanResults as root element, but found {root.tag}")
        return []

    results = []
    # Iterate over each host element inside NmapScanResults (root)
    for host_element in root:
        host_tag = host_element.tag  # e.g. tag_62_63_203_92
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

        ## Nmap Overview
        This is the main Nmap Header.

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
        chat_id, response = send_chat_request(message, chat_id=chat_id, model_id=model_id, level=level)
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
        send_vulnerability_to_api(vulnerability_data, scan_id, 3)
        print("-" * 80)

def send_vulnerability_to_api(vulnerability_data, scan_id=None, order=0):
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
        content = {"content": vulnerability_data, "order": order}
        json_data = json.dumps(content)
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
    
    # The root element is already NiktoScanResults
    print(f"Root tag: {root.tag}")  # This will print "NiktoScanResults"

    # Access the raw_output directly
    raw_output = root.find('raw_output')

    results = []
    if raw_output is not None:
        # Get the text content of the raw_output element
        raw_output_text = raw_output.text
        message = f"Nikto Scan Results\n\n{raw_output_text}\n\n This is the end of the context."
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
        chat_id, response = send_chat_request(message, chat_id=chat_id, model_id=model_id, level=level)
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
            send_vulnerability_to_api(vulnerability_data, scan_id, 2)
        
        print("-" * 80)

def run_AI(xml_file_path="../scan-report2.xml", 
                     model_id="WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0",
                     scan_id="",
                     level=2):
    print("Running AI")
    test_alert_items(xml_file_path, model_id, scan_id, level=level)
    test_nmap_object(xml_file_path, model_id, scan_id, level=level)
    test_nikto_object(xml_file_path, model_id, scan_id, level=level)

def run_zap_analysis(xml_file_path, scan_id, level):
    test_alert_items(xml_file_path, model_id="WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0", scan_id=scan_id, level=level)

def run_nmap_analysis(xml_file_path, scan_id, level):
    test_nmap_object(xml_file_path, model_id="WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0", scan_id=scan_id, level=level)

def run_nikto_analysis(xml_file_path, scan_id, level):
    test_nikto_object(xml_file_path, model_id="WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0", scan_id=scan_id, level=level)

def run_overview_analysis(xml_file_path, scan_id, level):
    test_scan_overview(xml_file_path=xml_file_path, scan_id=scan_id, level=level)

def get_scan_overview(file_path):
    """
    Extracts a concise overview from the XML scan report.
    
    Args:
        file_path (str): Path to the XML file
        
    Returns:
        str: Formatted summary text for LLM input
    """
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    summary_text = "SECURITY SCAN OVERVIEW\n\n"
    
    # 1. Extract target information
    site_element = root.find(".//site")
    if site_element is not None:
        target_name = site_element.get("name", "Unknown")
        target_host = site_element.get("host", "Unknown")
        target_port = site_element.get("port", "Unknown")
        target_ssl = site_element.get("ssl", "Unknown")
        
        summary_text += f"TARGET: {target_name}\n"
        summary_text += f"Host: {target_host}\n"
        summary_text += f"Port: {target_port}\n"
        summary_text += f"SSL Enabled: {target_ssl}\n\n"
    
    # 2. Extract ZAP alert summary
    summary_text += "ZAP FINDINGS:\n"
    alert_items = root.findall(".//alertitem")
    
    # Group alerts by risk level
    risk_levels = {"High": [], "Medium": [], "Low": [], "Informational": []}
    
    for alert in alert_items:
        alert_name = alert.findtext("alert", "Unknown")
        risk_desc = alert.findtext("riskdesc", "Unknown")
        
        # Map risk level from description
        if "High" in risk_desc:
            risk_levels["High"].append(alert_name)
        elif "Medium" in risk_desc:
            risk_levels["Medium"].append(alert_name)
        elif "Low" in risk_desc:
            risk_levels["Low"].append(alert_name)
        else:
            risk_levels["Informational"].append(alert_name)
    
    # Add counts by risk level
    for level, alerts in risk_levels.items():
        if alerts:
            summary_text += f"{level} Risk Issues: {len(alerts)}\n"
            for alert in alerts:
                summary_text += f"- {alert}\n"
            summary_text += "\n"
    
    # 3. Extract Nmap findings
    nmap_results = root.find(".//NmapScanResults")
    if nmap_results is not None:
        summary_text += "NMAP FINDINGS:\n"
        
        for host_element in nmap_results:
            host_tag = host_element.tag
            nested_host = host_element.find(f"./{host_tag}")
            
            if nested_host is not None:
                hostname = nested_host.findtext(".//hostnames/name", "Unknown")
                ipv4 = nested_host.findtext(".//addresses/ipv4", "Unknown")
                state = nested_host.findtext(".//status/state", "Unknown")
                
                summary_text += f"Host: {hostname} ({ipv4}), Status: {state}\n"
                
                # Count open ports
                open_ports = []
                for port_elem in nested_host.findall(".//tcp/*"):
                    port_state = port_elem.findtext("state", "")
                    if port_state == "open":
                        port_tag = port_elem.tag
                        port_number = port_tag.split('_')[1] if '_' in port_tag else port_tag
                        port_name = port_elem.findtext("name", "Unknown service")
                        open_ports.append(f"{port_number}/{port_name}")
                
                if open_ports:
                    summary_text += f"Open ports: {', '.join(open_ports)}\n"
                else:
                    summary_text += "No open ports detected\n"
        
        summary_text += "\n"
    
    # 4. Extract Nikto findings
    nikto_results = root.find(".//NiktoScanResults")
    if nikto_results is not None:
        summary_text += "NIKTO FINDINGS:\n"
        raw_output = nikto_results.findtext("raw_output", "")
        
        # Extract just the important lines from Nikto output
        findings = []
        for line in raw_output.split("\n"):
            if line.startswith("+ ") and not line.startswith("+ Target") and not "requests:" in line and not "host(s) tested" in line:
                findings.append(line.strip())
        
        if findings:
            for finding in findings:
                summary_text += f"{finding}\n"
        else:
            summary_text += "No significant findings reported\n"
    
    # 5. Request for overview
    summary_text += "\nPlease provide a concise executive summary of this security scan. Include:\n"
    summary_text += "1. Overall security posture assessment\n"
    summary_text += "2. Most significant security issues identified\n"
    summary_text += "3. Key recommendations in order of priority\n"
    summary_text += "Format the response in clear markdown with appropriate headers."
    
    return summary_text

def test_scan_overview(xml_file_path = "../scan-report2.xml", model_id="WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0", scan_id=None, level=0):
    """
    Extracts scan data and sends it to the LLM for an overview analysis.
    
    Args:
        xml_file_path (str): Path to the XML file
        model_id (str): ID of the LLM to use
        scan_id (str, optional): Scan ID for API updates
        
    Returns:
        str: LLM's overview analysis
    """
    # Extract formatted overview text
    overview_text = get_scan_overview(xml_file_path)
    print(f"Extracted overview from {xml_file_path}")
    
    # Initialize chat session with system prompt
    system_prompt = """You are a senior cybersecurity expert providing executive summaries of security scan findings.
    Focus on clarity, brevity, and actionable insights. Format your overview with markdown headings.
    Prioritize issues based on risk level and highlight only the most significant findings."""
    
    chat_id, _ = send_chat_request(system_prompt, role="system", model_id=model_id)
    if chat_id is None:
        print("Failed to initialize chat session for overview.")
        return "Failed to generate overview."
    
    # Send the overview text to get analysis
    chat_id, response = send_chat_request(overview_text, chat_id=chat_id, model_id=model_id, level=level)
    if response is None:
        print("Failed to receive overview response.")
        return "Failed to generate overview."
    
    print("Successfully generated scan overview")
    
    # Send to API if scan_id is provided
    if scan_id:
        overview_data = {"scan_overview": response}
        send_vulnerability_to_api(overview_data, scan_id, 0)
    
    return response

if __name__ == "__main__":
    mode = input("Enter 'test' to run alert items test or 'chat' for interactive chat: ").strip().lower()
    if mode == 'test':
        # level = int(input("Input Level"))

        for i in range(2, 3):
          print("Testing for Level: " + str(i))
          # test_alert_items(level=i)
          # test_nmap_object(level=i)  
          # test_nikto_object(level=i)
          print("\n\n\nResponse:\n\n\n" + test_scan_overview(xml_file_path="../scan_results/d39d0e8a-864e-4655-b459-b43124cdaded/scan-report.xml"))
          # save_json(scan_results, "scan_results.json")
    else:
        interactive_chat()
