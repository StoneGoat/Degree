import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from collections import Counter
import re

def parse_security_scan_xml(file_path):
    """Parse the security scan XML file and extract relevant data."""
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    data = {
        'zap': parse_zap_data(root.find('OWASPZAPReport')),
        'nmap': parse_nmap_data(root.find('NmapScanResults')),
        'nikto': parse_nikto_data(root.find('NiktoScanResults'))
    }
    
    return data

def parse_zap_data(zap_report):
    """Extract OWASP ZAP data from the XML."""
    if zap_report is None:
        return None
    
    alerts = []
    
    for site in zap_report.findall('site'):
        site_name = site.get('name', 'Unknown')
        for alertitem in site.findall('.//alertitem'):
            alert = {
                'name': alertitem.findtext('alert', 'Unknown Alert'),
                'risk_code': int(alertitem.findtext('riskcode', '0')),
                'risk_desc': alertitem.findtext('riskdesc', 'Unknown'),
                'confidence': int(alertitem.findtext('confidence', '0')),
                'confidence_desc': alertitem.findtext('confidencedesc', 'Unknown'),
                'count': int(alertitem.findtext('count', '0')),
                'site': site_name
            }
            alerts.append(alert)
    
    return alerts

def parse_nmap_data(nmap_results):
    """Extract Nmap scan data from the XML."""
    if nmap_results is None:
        return None
    
    hosts = []
    
    for host_elem in nmap_results:
        host_tag = host_elem.tag
        scan_elem = host_elem.find('.//scan')
        if scan_elem is not None:
            host_scan = scan_elem.find(host_tag)
            if host_scan is not None:
                host = {
                    'hostname': host_scan.findtext('.//hostnames/name', 'Unknown'),
                    'ip': host_scan.findtext('.//addresses/ipv4', 'Unknown'),
                    'status': host_scan.findtext('.//status/state', 'Unknown'),
                    'ports': []
                }
                
                tcp_elem = host_scan.find('tcp')
                if tcp_elem is not None:
                    for port_elem in tcp_elem:
                        port_tag = port_elem.tag
                        port_number = port_tag.split('_')[1] if '_' in port_tag else port_tag
                        port = {
                            'number': port_number,
                            'name': port_elem.findtext('name', 'Unknown'),
                            'state': port_elem.findtext('state', 'Unknown')
                        }
                        host['ports'].append(port)
                
                hosts.append(host)
    
    return hosts

def parse_nikto_data(nikto_results):
    """Extract Nikto scan data from the XML."""
    if nikto_results is None:
        return None
    
    raw_output = nikto_results.findtext('raw_output', '')
    
    # Parse the findings from the raw output
    findings = []
    lines = raw_output.strip().split('\n')
    
    for line in lines:
        if line.startswith('+ ') and not line.startswith('+ Start Time') and not line.startswith('+ End Time') and not line.startswith('+ 1 host'):
            # This is a finding
            finding = line[2:].strip()
            findings.append(finding)
    
    return {
        'raw_output': raw_output,
        'findings': findings
    }

def visualize_zap_risk_distribution(zap_data, output_file='zap_risk_distribution.png'):
    """Create a pie chart showing distribution of risks by severity."""
    if not zap_data:
        print("No ZAP data available for visualization")
        return
    
    # Define risk levels and their descriptions
    risk_levels = {
        0: 'Informational',
        1: 'Low',
        2: 'Medium',
        3: 'High'
    }
    
    # Count alerts by risk code
    risk_counts = Counter([alert['risk_code'] for alert in zap_data])
    
    # Prepare data for plotting
    labels = [risk_levels.get(code, f'Unknown ({code})') for code in risk_counts.keys()]
    values = list(risk_counts.values())
    
    # Create explode values (slight separation for the highest risk)
    explode = [0.1 if code == max(risk_counts.keys()) else 0 for code in risk_counts.keys()]
    
    # Plot
    plt.figure(figsize=(10, 7))
    plt.pie(values, labels=labels, explode=explode, autopct='%1.1f%%', 
            shadow=True, startangle=90, colors=plt.cm.YlOrRd(np.linspace(0.2, 0.8, len(labels))))
    plt.title('Distribution of Vulnerabilities by Risk Level')
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()
    print(f"Saved ZAP risk distribution chart to {output_file}")

def visualize_alert_counts(zap_data, output_file='zap_alert_counts.png'):
    """Create a horizontal bar chart of alert counts."""
    if not zap_data:
        print("No ZAP data available for visualization")
        return
    
    # Count occurrences of each alert
    alert_names = [alert['name'] for alert in zap_data]
    alert_counts = Counter(alert_names)
    
    # Sort by count (descending)
    sorted_alerts = sorted(alert_counts.items(), key=lambda x: x[1], reverse=True)
    
    # Get top 10 alerts for better readability
    top_alerts = sorted_alerts[:10]
    
    # Plot
    plt.figure(figsize=(12, 8))
    bars = plt.barh(
        [name for name, _ in top_alerts],
        [count for _, count in top_alerts],
        color=plt.cm.viridis(np.linspace(0.2, 0.8, len(top_alerts)))
    )
    
    # Add count labels to the bars
    for bar, count in zip(bars, [count for _, count in top_alerts]):
        plt.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2, 
                 str(count), va='center')
    
    plt.xlabel('Number of Occurrences')
    plt.ylabel('Alert Type')
    plt.title('Most Common Security Alerts')
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()
    print(f"Saved alert counts chart to {output_file}")

def visualize_confidence_vs_risk(zap_data, output_file='zap_confidence_vs_risk.png'):
    """Create a bubble chart showing risk vs. confidence levels."""
    if not zap_data:
        print("No ZAP data available for visualization")
        return
    
    # Create a DataFrame for easier manipulation
    df = pd.DataFrame(zap_data)
    
    # Define risk and confidence levels
    risk_levels = {0: 'Informational', 1: 'Low', 2: 'Medium', 3: 'High'}
    confidence_levels = {0: 'Low', 1: 'Medium', 2: 'Medium', 3: 'High'}
    
    # Map numeric codes to descriptions
    df['risk_desc'] = df['risk_code'].map(risk_levels)
    df['confidence_desc'] = df['confidence'].map(confidence_levels)
    
    # Create a pivot table
    pivot = pd.pivot_table(
        df, 
        values='count',
        index='risk_desc',
        columns='confidence_desc',
        aggfunc='sum',
        fill_value=0
    )
    
    # Sort the indices for better visual representation
    risk_order = ['High', 'Medium', 'Low', 'Informational']
    confidence_order = ['High', 'Medium', 'Low']
    
    # Reindex to get the right order and handle missing values
    pivot = pivot.reindex(index=risk_order, columns=confidence_order, fill_value=0)
    
    # Plot as a heatmap using matplotlib
    plt.figure(figsize=(10, 8))
    
    # Create a heatmap manually
    im = plt.imshow(pivot.values, cmap='YlOrRd')
    plt.colorbar(im, label='Alert Count')
    
    # Set ticks and labels
    plt.xticks(np.arange(len(pivot.columns)), pivot.columns)
    plt.yticks(np.arange(len(pivot.index)), pivot.index)
    
    # Add text annotations to cells
    for i in range(len(pivot.index)):
        for j in range(len(pivot.columns)):
            text = plt.text(j, i, pivot.values[i, j],
                           ha="center", va="center", color="black" if pivot.values[i, j] < 10 else "white")
    
    plt.xlabel('Confidence Level')
    plt.ylabel('Risk Level')
    plt.title('Alert Count: Risk Level vs. Confidence Level')
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()
    print(f"Saved confidence vs risk chart to {output_file}")

def visualize_nmap_port_status(nmap_data, output_file='nmap_port_status.png'):
    """Create a horizontal bar chart showing port status."""
    if not nmap_data:
        print("No Nmap data available for visualization")
        return
    
    # Collect port information
    ports = []
    for host in nmap_data:
        ports.extend(host['ports'])
    
    # Count port status
    port_status = {}
    for port in ports:
        port_name = f"{port['number']}/{port['name']}"
        if port_name not in port_status:
            port_status[port_name] = {'open': 0, 'closed': 0, 'filtered': 0}
        
        state = port['state'].lower()
        if state in port_status[port_name]:
            port_status[port_name][state] += 1
        else:
            port_status[port_name][state] = 1
    
    # Prepare data for plotting
    port_names = list(port_status.keys())
    open_counts = [port_status[port]['open'] for port in port_names]
    closed_counts = [port_status[port]['closed'] for port in port_names]
    filtered_counts = [port_status[port]['filtered'] for port in port_names]
    
    # Plot
    plt.figure(figsize=(12, 8))
    x = np.arange(len(port_names))
    width = 0.25
    
    plt.barh(x - width, open_counts, width, label='Open', color='#5cb85c')
    plt.barh(x, closed_counts, width, label='Closed', color='#d9534f')
    plt.barh(x + width, filtered_counts, width, label='Filtered', color='#f0ad4e')
    
    plt.yticks(x, port_names)
    plt.xlabel('Count')
    plt.ylabel('Port / Service')
    plt.title('Port Status Summary')
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()
    print(f"Saved Nmap port status chart to {output_file}")

def visualize_nikto_findings(nikto_data, output_file='nikto_findings.png'):
    """Create a visualization of Nikto findings."""
    if not nikto_data or not nikto_data['findings']:
        print("No Nikto data available for visualization")
        return
    
    # Categorize findings
    categories = {
        'Information Disclosure': ['x-powered-by', 'server:', 'retrieved'],
        'Missing Security Headers': ['X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security'],
        'Server Configuration': ['redirects', 'CGI Directories'],
        'Vulnerabilities': ['vulnerable', 'exploit', 'attack', 'XSS', 'injection']
    }
    
    # Count findings by category
    category_counts = {cat: 0 for cat in categories}
    other_count = 0
    
    for finding in nikto_data['findings']:
        finding_lower = finding.lower()
        categorized = False
        
        for cat, keywords in categories.items():
            if any(keyword.lower() in finding_lower for keyword in keywords):
                category_counts[cat] += 1
                categorized = True
                break
        
        if not categorized:
            other_count += 1
    
    if other_count > 0:
        category_counts['Other'] = other_count
    
    # Plot
    plt.figure(figsize=(10, 7))
    
    labels = list(category_counts.keys())
    values = list(category_counts.values())
    colors = plt.cm.Set3(np.linspace(0, 1, len(labels)))
    
    plt.pie(values, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors, shadow=True)
    plt.axis('equal')
    plt.title('Nikto Findings by Category')
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()
    print(f"Saved Nikto findings chart to {output_file}")

def create_dashboard(security_data, output_file='security_dashboard.png'):
    """Create a comprehensive dashboard with multiple visualizations."""
    fig = plt.figure(figsize=(24, 18))  # Increased figure size for more space
    plt.suptitle('Security Scan Results Dashboard', fontsize=24, y=0.98)
    
    # Define grid layout with more space between plots
    gs = fig.add_gridspec(3, 2, hspace=0.5, wspace=0.4)  # Increased wspace for more horizontal space
    
    # ZAP Risk Distribution
    if security_data['zap']:
        ax1 = fig.add_subplot(gs[0, 0])
        risk_counts = Counter([alert['risk_code'] for alert in security_data['zap']])
        risk_levels = {0: 'Informational', 1: 'Low', 2: 'Medium', 3: 'High'}
        labels = [risk_levels.get(code, f'Unknown ({code})') for code in risk_counts.keys()]
        values = list(risk_counts.values())
        explode = [0.1 if code == max(risk_counts.keys()) else 0 for code in risk_counts.keys()]
        
        ax1.pie(values, labels=labels, explode=explode, autopct='%1.1f%%', 
                shadow=True, startangle=90, colors=plt.cm.YlOrRd(np.linspace(0.2, 0.8, len(labels))))
        ax1.set_title('ZAP: Vulnerability Risk Distribution')
        ax1.axis('equal')
    
    # Top ZAP Alerts - Modified to handle long titles
    if security_data['zap']:
        ax2 = fig.add_subplot(gs[0, 1])
        alert_names = [alert['name'] for alert in security_data['zap']]
        alert_counts = Counter(alert_names)
        sorted_alerts = sorted(alert_counts.items(), key=lambda x: x[1], reverse=True)
        top_alerts = sorted_alerts[:5]  # Show top 5 for dashboard
        
        # Truncate long alert names to prevent overlap
        truncated_names = []
        for name, _ in top_alerts:
            if len(name) > 30:  # Truncate if longer than 30 chars
                truncated_names.append(name[:27] + '...')
            else:
                truncated_names.append(name)
        
        y_pos = np.arange(len(top_alerts))
        bars = ax2.barh(y_pos, [count for _, count in top_alerts], 
                color=plt.cm.viridis(np.linspace(0.2, 0.8, len(top_alerts))))
        
        # Set truncated names for display
        ax2.set_yticks(y_pos)
        ax2.set_yticklabels(truncated_names)
        
        # Add count labels to the bars
        for bar, count in zip(bars, [count for _, count in top_alerts]):
            ax2.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2, 
                     str(count), va='center')
        
        ax2.invert_yaxis()
        ax2.set_title('ZAP: Top Alert Types')
        ax2.set_xlabel('Count')
    
    # Nmap Port Status
    if security_data['nmap']:
        ax3 = fig.add_subplot(gs[1, 0])
        ports = []
        for host in security_data['nmap']:
            ports.extend(host['ports'])
        
        # Count port states
        port_states = Counter([port['state'] for port in ports])
        
        ax3.bar(list(port_states.keys()), list(port_states.values()), 
                color=plt.cm.Set2(np.linspace(0, 1, len(port_states))))
        ax3.set_title('Nmap: Port Status Summary')
        ax3.set_xlabel('Port State')
        ax3.set_ylabel('Count')
        
        # Add a small summary of open ports
        open_ports = [f"{port['number']}/{port['name']}" for port in ports if port['state'].lower() == 'open']
        if open_ports:
            open_port_text = "Open ports: " + ", ".join(open_ports)
            ax3.text(0.5, -0.15, open_port_text, ha='center', transform=ax3.transAxes)
    
    # Nikto Findings
    if security_data['nikto'] and security_data['nikto']['findings']:
        ax4 = fig.add_subplot(gs[1, 1])
        
        # Categorize findings
        categories = {
            'Information Disclosure': ['x-powered-by', 'server:', 'retrieved'],
            'Missing Security Headers': ['X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security'],
            'Server Configuration': ['redirects', 'CGI Directories'],
            'Vulnerabilities': ['vulnerable', 'exploit', 'attack', 'XSS', 'injection']
        }
        
        # Count findings by category
        category_counts = {cat: 0 for cat in categories}
        other_count = 0
        
        for finding in security_data['nikto']['findings']:
            finding_lower = finding.lower()
            categorized = False
            
            for cat, keywords in categories.items():
                if any(keyword.lower() in finding_lower for keyword in keywords):
                    category_counts[cat] += 1
                    categorized = True
                    break
            
            if not categorized:
                other_count += 1
        
        if other_count > 0:
            category_counts['Other'] = other_count
        
        # Plot
        labels = list(category_counts.keys())
        values = list(category_counts.values())
        colors = plt.cm.Set3(np.linspace(0, 1, len(labels)))
        
        ax4.pie(values, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors)
        ax4.axis('equal')
        ax4.set_title('Nikto: Findings by Category')
    
    # Summary of all findings
    ax5 = fig.add_subplot(gs[2, :])
    
    # Prepare summary data
    tool_names = []
    total_findings = []
    high_risk = []
    medium_risk = []
    low_risk = []
    info = []
    
    # ZAP summary
    if security_data['zap']:
        tool_names.append('OWASP ZAP')
        zap_alerts = security_data['zap']
        total_findings.append(len(zap_alerts))
        
        zap_risk_counts = Counter([alert['risk_code'] for alert in zap_alerts])
        high_risk.append(zap_risk_counts.get(3, 0))
        medium_risk.append(zap_risk_counts.get(2, 0))
        low_risk.append(zap_risk_counts.get(1, 0))
        info.append(zap_risk_counts.get(0, 0))
    
    # Nmap summary
    if security_data['nmap']:
        tool_names.append('Nmap')
        ports = []
        for host in security_data['nmap']:
            ports.extend(host['ports'])
        
        total_findings.append(len(ports))
        open_ports = len([port for port in ports if port['state'].lower() == 'open'])
        
        # Assign risk levels based on open ports
        if open_ports > 5:
            high_risk.append(open_ports)
            medium_risk.append(0)
            low_risk.append(0)
        elif open_ports > 2:
            high_risk.append(0)
            medium_risk.append(open_ports)
            low_risk.append(0)
        else:
            high_risk.append(0)
            medium_risk.append(0)
            low_risk.append(open_ports)
        
        info.append(len(ports) - open_ports)
    
    # Nikto summary
    if security_data['nikto'] and security_data['nikto']['findings']:
        tool_names.append('Nikto')
        findings = security_data['nikto']['findings']
        total_findings.append(len(findings))
        
        # Roughly categorize by severity based on keywords
        high_keywords = ['vulnerable', 'critical', 'exploit']
        medium_keywords = ['missing header', 'information leak', 'disclosure']
        
        h_count = sum(1 for f in findings if any(k in f.lower() for k in high_keywords))
        m_count = sum(1 for f in findings if any(k in f.lower() for k in medium_keywords))
        l_count = len(findings) - h_count - m_count
        
        high_risk.append(h_count)
        medium_risk.append(m_count)
        low_risk.append(l_count)
        info.append(0)  # Nikto doesn't typically classify as informational
    
    # Plot stacked bar chart of risk levels
    x = np.arange(len(tool_names))
    width = 0.5
    
    ax5.bar(x, high_risk, width, label='High Risk', color='#d9534f')
    ax5.bar(x, medium_risk, width, bottom=high_risk, label='Medium Risk', color='#f0ad4e')
    ax5.bar(x, low_risk, width, bottom=np.array(high_risk) + np.array(medium_risk), 
           label='Low Risk', color='#5bc0de')
    ax5.bar(x, info, width, 
           bottom=np.array(high_risk) + np.array(medium_risk) + np.array(low_risk),
           label='Informational', color='#5cb85c')
    
    ax5.set_title('Security Findings by Tool and Risk Level')
    ax5.set_xticks(x)
    ax5.set_xticklabels(tool_names)
    ax5.legend()
    
    # Add total count labels on top of each bar
    for i, v in enumerate(total_findings):
        ax5.text(i, v + 0.5, str(v), ha='center')
    
    # Save the dashboard
    plt.tight_layout(rect=[0, 0, 1, 0.97])  # Adjust for the suptitle
    plt.savefig(output_file, dpi=120, bbox_inches='tight')
    plt.close()
    print(f"Saved security dashboard to {output_file}")


# Alternative visualize_alert_counts function
def visualize_alert_counts(zap_data, output_file='zap_alert_counts.png'):
    """Create a horizontal bar chart of alert counts with better handling of long alert names."""
    if not zap_data:
        print("No ZAP data available for visualization")
        return
    
    # Count occurrences of each alert
    alert_names = [alert['name'] for alert in zap_data]
    alert_counts = Counter(alert_names)
    
    # Sort by count (descending)
    sorted_alerts = sorted(alert_counts.items(), key=lambda x: x[1], reverse=True)
    
    # Get top 10 alerts for better readability
    top_alerts = sorted_alerts[:10]
    
    # Plot
    plt.figure(figsize=(14, 10))  # Wider figure for more space
    
    # Truncate long names
    y_labels = []
    for name, _ in top_alerts:
        if len(name) > 40:
            y_labels.append(name[:37] + '...')
        else:
            y_labels.append(name)
    
    # Plot bars with more space
    bars = plt.barh(
        y_labels,
        [count for _, count in top_alerts],
        color=plt.cm.viridis(np.linspace(0.2, 0.8, len(top_alerts)))
    )
    
    # Add count labels to the bars
    for bar, count in zip(bars, [count for _, count in top_alerts]):
        plt.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2, 
                 str(count), va='center')
    
    plt.xlabel('Number of Occurrences')
    plt.ylabel('Alert Type')
    plt.title('Most Common Security Alerts')
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()
    print(f"Saved alert counts chart to {output_file}")

def main(xml_file_path):
    """Main function to run the visualization process."""
    print(f"Analyzing security scan data from {xml_file_path}")
    
    try:
        # Parse the XML data
        security_data = parse_security_scan_xml(xml_file_path)
        
        # Generate individual visualizations
        if security_data['zap']:
            visualize_zap_risk_distribution(security_data['zap'])
            visualize_alert_counts(security_data['zap'])
            visualize_confidence_vs_risk(security_data['zap'])
        
        if security_data['nmap']:
            visualize_nmap_port_status(security_data['nmap'])
        
        if security_data['nikto']:
            visualize_nikto_findings(security_data['nikto'])
        
        # Create a comprehensive dashboard
        create_dashboard(security_data)
        
        print("Visualization complete!")
    
    except Exception as e:
        print(f"Error during visualization: {str(e)}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        xml_file = sys.argv[1]
    else:
        xml_file = "scan-report.xml"  # Default filename
    
    main(xml_file)