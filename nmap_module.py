import nmap
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

nmapScan = nmap.PortScanner()

def sanitize_tag(tag):
    tag = str(tag)
    # If the tag starts with a digit, prefix it (e.g., with 'tag_')
    if tag and tag[0].isdigit():
        tag = "tag_" + tag
    # Replace dots and spaces with underscores
    tag = tag.replace(".", "_").replace(" ", "_")
    # Optionally, add more replacements for any other invalid characters
    return tag

def dict_to_xml(tag, d):
    """
    Recursively converts a dictionary into an XML Element.
    
    :param tag: The tag name for the root element of this dictionary.
    :param d: The dictionary to convert.
    :return: An ElementTree Element.
    """
    elem = ET.Element(sanitize_tag(tag))
    for key, val in d.items():
        key_str = sanitize_tag(key)
        if isinstance(val, dict):
            child = dict_to_xml(key_str, val)
            elem.append(child)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    child = dict_to_xml(key_str, item)
                else:
                    child = ET.Element(key_str)
                    child.text = str(item)
                elem.append(child)
        else:
            child = ET.Element(key_str)
            child.text = str(val)
            elem.append(child)
    return elem

def scan(ips, portrange):
    results = {}
    for ip in ips:
        result = nmapScan.scan(ip, portrange, arguments='-Pn')
        results[ip] = result

        print(f"Nmap: {result.get('nmap', {})}")
        print(f"Scan: {result.get('scan', {})}")

        if ip in result.get("scan", {}) and "tcp" in result["scan"][ip]:
            tcp_results = result["scan"][ip]["tcp"]
            print("Ports open:\n")
            for port, tcp_result in tcp_results.items():
                port_info = f"Port {port} - {tcp_result['state']}"
                if tcp_result.get("name"):
                    port_info += f", {tcp_result['name']}"
                if tcp_result.get("product"):
                    port_info += f", {tcp_result['product']}"
                if tcp_result.get("extrainfo"):
                    port_info += f", {tcp_result['extrainfo']}"
                print(port_info)
        else:
            print(f"No open TCP ports found for {ip}")

    # Convert the results dictionary to XML.
    root = dict_to_xml("NmapScanResults", results)
    # Convert to a string (this gives a single-line XML)
    xml_str = ET.tostring(root, encoding="unicode", method="xml")
    
    # Use minidom to pretty-print the XML with indentation and newlines.
    dom = minidom.parseString(xml_str)
    pretty_xml_str = dom.toprettyxml(indent="    ")
    return pretty_xml_str
