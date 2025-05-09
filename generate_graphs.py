import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from collections import Counter
import re
import sys
import os
import traceback

OUTPUT_DPI = 75

def parse_security_scan_xml(file_path):
    """Parse the security scan XML file and extract relevant data."""
    print(f"Parsing XML file: {file_path}")
    try:
        tree = ET.parse(file_path, parser=ET.XMLParser(encoding='utf-8'))
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing XML file {file_path} with utf-8: {e}")
        try:
            print("  - Retrying parse with latin-1 encoding...")
            tree = ET.parse(file_path, parser=ET.XMLParser(encoding='latin-1'))
            root = tree.getroot()
        except Exception as e_fallback:
            print(f"  - Error parsing XML file {file_path} with fallback encoding: {e_fallback}")
            return None
    except FileNotFoundError:
        print(f"Error: File not found during parsing attempt at {file_path}")
        return None
    except Exception as e_other:
        print(f"An unexpected error occurred during XML parsing setup: {e_other}")
        return None

    data = {'zap': None, 'nmap': None, 'nikto': None}
    found_sections = []

    # ZAP Parsing
    try:
        zap_report = root.find('.//OWASPZAPReport')
        if zap_report is not None:
            data['zap'] = parse_zap_data(zap_report)
            if data['zap'] is not None:
                unique_alerts = len(set(a['pluginid'] for a in data['zap'] if 'pluginid' in a))
                found_sections.append("ZAP")
                print(f"  - Parsed ZAP data ({unique_alerts} unique alert types found).")
            else:
                print("  - Found ZAP section, but no alerts parsed (parser returned None/empty).")
        else:
            print("  - OWASP ZAP report section not found in XML.")
    except Exception as e_zap:
        print(f"  - Error during ZAP parsing: {e_zap}")
        traceback.print_exc(limit=1)

    # Nmap Parsing
    try:
        nmap_results = root.find('.//NmapScanResults')
        if nmap_results is not None:
            data['nmap'] = parse_nmap_data(nmap_results)
            if data['nmap'] is not None:
                found_sections.append("Nmap")
                print(f"  - Parsed Nmap data from <NmapScanResults> ({len(data['nmap'])} hosts found).")
            else:
                print("  - Found <NmapScanResults> section, but no host data parsed.")
        else:
            nmap_run_results = root.find('.//nmaprun')
            if nmap_run_results is not None:
                print("  - Found standard <nmaprun> tag. Parsing standard Nmap format.")
                print("    (Standard Nmap parser not implemented in this version)")
            else:
                print("  - Nmap results section (<NmapScanResults> or <nmaprun>) not found in XML.")
    except Exception as e_nmap:
        print(f"  - Error during Nmap parsing: {e_nmap}")
        traceback.print_exc(limit=1)

    # Nikto Parsing
    try:
        nikto_output_text = None; nikto_source = "Not Found"
        nikto_results_tag = root.find('.//NiktoScanResults/raw_output')
        if nikto_results_tag is not None:
            nikto_output_text = nikto_results_tag.text; nikto_source = "<NiktoScanResults>"
        else:
            nikto_tool_node = root.find(".//tool[name='Nikto']")
            if nikto_tool_node is not None:
                output_node = nikto_tool_node.find('output')
                if output_node is not None and output_node.text:
                    nikto_output_text = output_node.text; nikto_source = "<tool name='Nikto'>"
        if nikto_output_text:
            data['nikto'] = parse_nikto_data_from_output(nikto_output_text)
            if data['nikto'] and data['nikto'].get('findings'):
                found_sections.append("Nikto")
                print(f"  - Parsed Nikto data from {nikto_source} ({len(data['nikto']['findings'])} findings).")
            elif data['nikto']: print(f"  - Found Nikto section ({nikto_source}), but no findings parsed.")
            else: print(f"  - Found Nikto section ({nikto_source}), but failed to parse raw output.")
        else: print("  - Nikto results section not found using common patterns.")
    except Exception as e_nikto:
        print(f"  - Error during Nikto parsing: {e_nikto}")
        traceback.print_exc(limit=1)

    if not found_sections:
        print("\nWarning: No relevant security tool data (ZAP, Nmap, Nikto) could be parsed successfully from the XML.")

    return data

def parse_zap_data(zap_report):
    """Extract OWASP ZAP data from the XML."""
    alerts = []
    try:
        for alertitem in zap_report.findall('.//alertitem'):
            instance_count = len(alertitem.findall('.//instance'))
            alert_count = instance_count if instance_count > 0 else int(alertitem.findtext('count', '1'))
            site_element = None
            parent = alertitem.find('..') # Direct parent
            if parent is not None and parent.tag == 'site' and 'name' in parent.attrib:
                 site_element = parent
            else:
                 grandparent = parent.find('..') if parent is not None else None # Grandparent
                 if grandparent is not None and grandparent.tag == 'site' and 'name' in grandparent.attrib:
                      site_element = grandparent

            site_name = site_element.get('name', 'Unknown Site') if site_element is not None else 'Unknown Site (Structure Mismatch)'
            alert = {
                'name': alertitem.findtext('alert', 'Unknown Alert'),
                'pluginid': alertitem.findtext('pluginid', 'N/A'),
                'risk_code': int(alertitem.findtext('riskcode', '-1')),
                'risk_desc': alertitem.findtext('riskdesc', 'Unknown'),
                'confidence': int(alertitem.findtext('confidence', '-1')),
                'confidence_desc': alertitem.findtext('confidencedesc', 'Unknown'),
                'count': alert_count,
                'site': site_name}
            alerts.append(alert)
        return alerts if alerts else None
    except Exception as e:
        print(f"    - Error parsing individual ZAP alert item: {e}"); traceback.print_exc(limit=1)
        return alerts if alerts else None

def parse_nmap_data(nmap_results_root):
    """Extract Nmap scan data from the custom XML structure."""
    hosts_data = []
    try:
        # Iterate through the first level tags
        for outer_host_tag in nmap_results_root:
            # Find the nested tag with the same name which seems to contain the data
            host_data_tag = outer_host_tag.find(f'.//{outer_host_tag.tag}')
            if host_data_tag is None:
                 # If the nested tag isn't found, maybe the structure is flat sometimes?
                 # Try using the outer tag itself. If still no address, skip.
                if outer_host_tag.find('.//addresses/ipv4') is None and outer_host_tag.find('.//addresses/ipv6') is None:
                     print(f"   - Warning: Skipping Nmap entry - Could not find host data within <{outer_host_tag.tag}> or its children.")
                     continue
                host_data_tag = outer_host_tag # Use the outer tag as the data source

            host_info = {'hostname': 'Unknown', 'ip': 'Unknown IP', 'status': 'Unknown State', 'ports': []}

            # Extract IP address
            ip_elem_v4 = host_data_tag.find('.//addresses/ipv4')
            ip_elem_v6 = host_data_tag.find('.//addresses/ipv6')
            if ip_elem_v4 is not None:
                host_info['ip'] = ip_elem_v4.text
            elif ip_elem_v6 is not None:
                 host_info['ip'] = ip_elem_v6.text # Fallback to IPv6

            # Extract Hostname
            hostname_elem = host_data_tag.find('.//hostnames/name')
            if hostname_elem is not None:
                host_info['hostname'] = hostname_elem.text

            # Extract Status
            status_elem = host_data_tag.find('.//status/state')
            if status_elem is not None:
                host_info['status'] = status_elem.text

            # Extract Ports from <open_ports>
            open_ports_tag = host_data_tag.find('.//open_ports')
            if open_ports_tag is not None:
                for port_tag in open_ports_tag:
                    port_id_str = port_tag.tag.replace('tag_', '')
                    if not port_id_str.isdigit():
                         print(f"   - Warning: Skipping port with non-numeric tag name '{port_tag.tag}' under host {host_info['ip']}")
                         continue

                    portid = port_id_str
                    protocol = 'tcp' # Assuming tcp

                    state_elem = port_tag.find('state')
                    name_elem = port_tag.find('name')
                    product_elem = port_tag.find('product')
                    version_elem = port_tag.find('version')
                    extrainfo_elem = port_tag.find('extrainfo')

                    if state_elem is not None:
                        port_info = {
                            'number': portid,
                            'protocol': protocol,
                            'state': state_elem.text or 'Unknown',
                            'name': name_elem.text if name_elem is not None else 'Unknown',
                            'product': product_elem.text if product_elem is not None else '',
                            'version': version_elem.text if version_elem is not None else '',
                            'extrainfo': extrainfo_elem.text if extrainfo_elem is not None else ''
                        }
                        host_info['ports'].append(port_info)
                    else:
                         print(f"   - Warning: Skipping incomplete port data for port tag '{port_tag.tag}' under host {host_info['ip']}")

            hosts_data.append(host_info)
        return hosts_data if hosts_data else None
    except Exception as e:
        print(f"      - Error parsing Nmap data section: {e}")
        traceback.print_exc(limit=1)
        return hosts_data if hosts_data else None

def parse_nikto_data_from_output(raw_output):
    """Extract Nikto scan findings from raw text output."""
    if not raw_output or not isinstance(raw_output, str): return None
    findings = []
    try:
        # Improved pattern to better exclude headers and summarize lines
        finding_pattern = re.compile(
            r"^\+\s+(?!Server:|Target IP:|Target Hostname:|Target Port:|Start Time:|End Time:|Nikto version|\d+\s+hosts? tested|\d+\s+requests?|\d+ error\(s\) and \d+ item\(s\) reported|Retrieved x-powered-by|Allowed HTTP Methods:|The anti-clickjacking|X-Content-Type-Options|Cookie .+ created without|Strict-Transport-Security|X-Frame-Options)(.*)",
            re.MULTILINE | re.IGNORECASE
        )
        for match in finding_pattern.finditer(raw_output):
            if match.group(1):
                finding_text = match.group(1).strip()
                if finding_text: findings.append(finding_text)
        # Fallback if regex misses things
        if not findings:
            lines = raw_output.strip().split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('+ ') and not any(header.lower() in line.lower() for header in ['Server:', 'Target IP:', 'Target Hostname:', 'Target Port:', 'Start Time:', 'End Time:', 'Nikto version', 'host(s) tested']):
                    finding = line[2:].strip()
                    if finding and 'retrieved' not in finding.lower() and 'allowed http methods' not in finding.lower():
                         findings.append(finding)

        return {'raw_output': raw_output, 'findings': findings} if findings else None
    except Exception as e:
        print(f"    - Error parsing Nikto raw output: {e}"); traceback.print_exc(limit=1)
        return None


# Visualize ZAP Risk Distribution
def visualize_zap_risk_distribution(zap_data, output_file='1_zap_risk_distribution.png'):
    """Create a pie chart showing distribution of UNIQUE ZAP alert types by risk severity."""
    if not zap_data: print("  - Skipping ZAP Risk Distribution: No ZAP data."); return
    try:
        risk_levels = { 3: 'High', 2: 'Medium', 1: 'Low', 0: 'Informational', -1: 'Unknown'}
        risk_colors = { 'High': '#d9534f', 'Medium': '#f0ad4e', 'Low': '#5bc0de', 'Informational': '#5cb85c', 'Unknown': '#777777'}
        unique_alerts_by_risk = Counter(); processed_plugin_ids = set()
        for alert in zap_data:
            plugin_id = alert.get('pluginid', 'N/A')
            if plugin_id not in processed_plugin_ids:
                risk_code = alert.get('risk_code', -1); unique_alerts_by_risk[risk_code] += 1
                processed_plugin_ids.add(plugin_id)
        risk_counts = unique_alerts_by_risk
        plot_labels_legend, plot_labels_pie, plot_values, plot_colors, plot_explode = [], [], [], [], []
        ordered_codes = [3, 2, 1, 0, -1]
        present_codes = [code for code in risk_counts if code != -1 and risk_counts[code] > 0]
        max_risk_code_present = max(present_codes) if present_codes else -2
        total_unique_alerts = sum(risk_counts.values())
        if total_unique_alerts == 0: print("  - Skipping ZAP Risk Distribution: No unique alerts found."); return
        for code in ordered_codes:
            if code in risk_counts and risk_counts[code] > 0:
                label = risk_levels.get(code, f'Unknown ({code})'); value = risk_counts[code]
                color = risk_colors.get(label, risk_colors['Unknown'])
                percentage = (value / total_unique_alerts) * 100 if total_unique_alerts > 0 else 0
                plot_labels_legend.append(f"{label} ({value})"); plot_labels_pie.append(f'{percentage:.1f}%')
                plot_values.append(value); plot_colors.append(color)
                plot_explode.append(0.1 if code == max_risk_code_present else 0)
        if not plot_values: print("  - Skipping ZAP Risk Distribution: No data to plot."); return

        plt.figure(figsize=(10, 7))
        wedges, texts = plt.pie(plot_values, labels=plot_labels_pie, explode=plot_explode, autopct=None, pctdistance=0.80, shadow=False, startangle=90, colors=plot_colors, textprops={'color':"w", 'weight':'bold'}, wedgeprops={'edgecolor': 'white'})
        plt.title(f'ZAP: Distribution of Unique Alert Types by Risk (Total Unique: {total_unique_alerts})')
        plt.axis('equal')
        if wedges: plt.legend(wedges, plot_labels_legend, title="Risk Levels (Unique Count)", loc="center left", bbox_to_anchor=(0.95, 0.5))
        plt.tight_layout(rect=[0, 0, 0.85, 1])
        try:
            plt.savefig(output_file, bbox_inches='tight', dpi=OUTPUT_DPI, transparent=True)
            print(f"  - Saved ZAP unique risk distribution chart to {output_file} (DPI: {OUTPUT_DPI})")
        except Exception as e_save: print(f"  - Error saving ZAP unique risk distribution chart: {e_save}")
        plt.close()
    except Exception as e_viz: print(f"  - Error during ZAP unique risk distribution visualization: {e_viz}"); traceback.print_exc(limit=2); plt.close()

# Visualize ZAP Alert Counts
def visualize_alert_counts(zap_data, output_file='2_zap_alert_counts.png'):
    """Create a horizontal bar chart of ZAP alert TOTAL OCCURRENCES."""
    if not zap_data: print("  - Skipping ZAP Alert Counts: No ZAP data."); return
    try:
        alert_counts = Counter()
        for alert in zap_data: alert_counts[alert.get('name', 'Unknown Alert')] += alert.get('count', 1)
        top_alerts = alert_counts.most_common(15)
        if not top_alerts: print("  - Skipping ZAP Alert Counts: No alerts found."); return
        alert_labels = [name for name, count in top_alerts]; alert_values = [count for name, count in top_alerts]
        y_labels = []
        max_label_length = 60
        for name in alert_labels: y_labels.append(name[:max_label_length - 3] + '...' if len(name) > max_label_length else name)
        fig_height = max(6, len(y_labels) * 0.5)

        plt.figure(figsize=(10, fig_height)); y_pos = np.arange(len(y_labels)) # Keep original figsize
        bars = plt.barh(y_pos, alert_values, color=plt.cm.viridis(np.linspace(0.8, 0.2, len(y_labels))))
        plt.yticks(y_pos, y_labels, fontsize=9); plt.gca().invert_yaxis()
        max_val = max(alert_values) if alert_values else 1
        for bar in bars:
            width = bar.get_width(); label_x_pos = width + (max_val * 0.01)
            plt.text(label_x_pos, bar.get_y() + bar.get_height()/2., f'{int(width)}', va='center', ha='left', fontsize=9)
        plt.xlabel('Total Occurrences'); plt.ylabel('Alert Type')
        plt.title(f'Top {len(top_alerts)} Most Common Security Alerts by Occurrence Count (ZAP)')
        plt.tight_layout(pad=1.0); plt.xlim(right=max_val * 1.15)
        try:
            plt.savefig(output_file, bbox_inches='tight', dpi=OUTPUT_DPI, transparent=True)
            print(f"  - Saved ZAP alert counts by occurrence chart to {output_file} (DPI: {OUTPUT_DPI})")
        except Exception as e_save: print(f"  - Error saving ZAP alert counts by occurrence chart: {e_save}")
        plt.close()
    except Exception as e_viz: print(f"  - Error during ZAP alert counts visualization: {e_viz}"); traceback.print_exc(limit=2); plt.close()

# Visualize Nmap Port Status
def visualize_nmap_port_status(nmap_data, output_file='4_nmap_port_status.png'):
    if not nmap_data: print("  - Skipping Nmap Port Status: No Nmap data."); return
    try:
        port_states = []; open_ports_summary = Counter()
        for host in nmap_data:
            host_ports = host.get('ports')
            if host_ports:
                for port in host_ports:
                    state = port.get('state', 'unknown'); port_states.append(state)
                    if state == 'open': open_ports_summary[f"{port.get('number', '?')}/{port.get('protocol', 'p')} ({port.get('name', 'service')})"] += 1
        if not port_states: print("  - Skipping Nmap Port Status: No port info found."); return
        state_counts = Counter(port_states)
        common_states_order = ['open', 'closed', 'filtered', 'open|filtered', 'closed|filtered']
        states_to_plot, counts_to_plot, other_count = [], [], 0
        present_states = list(state_counts.keys())
        for state in common_states_order:
            if state in state_counts: states_to_plot.append(state); counts_to_plot.append(state_counts[state])
        for state, count in state_counts.items():
           if state not in common_states_order: other_count += count
        if other_count > 0: states_to_plot.append('other'); counts_to_plot.append(other_count)
        if not counts_to_plot: print("  - Skipping Nmap Port Status: No states to plot."); return
        state_colors = {'open': '#5cb85c', 'closed': '#d9534f', 'filtered': '#f0ad4e', 'open|filtered': '#7aacc9', 'closed|filtered': '#e17c79', 'other': '#aaaaaa'}
        colors = [state_colors.get(state, '#aaaaaa') for state in states_to_plot]

        plt.figure(figsize=(8, 6)); bars = plt.bar(states_to_plot, counts_to_plot, color=colors) # Keep original figsize
        max_count = max(counts_to_plot) if counts_to_plot else 1
        for bar in bars:
            yval = bar.get_height()
            if yval > 0: plt.text(bar.get_x() + bar.get_width()/2.0, yval + (max_count * 0.01), int(yval), va='bottom', ha='center')
        plt.xlabel('Port State'); plt.ylabel('Count'); plt.title('Nmap: Port State Summary Across All Hosts')
        if open_ports_summary:
            top_open = open_ports_summary.most_common(5)
            open_text = "Top Open Ports: " + ", ".join([f"{p} ({c})" for p, c in top_open])
            if len(open_ports_summary) > 5: open_text += ", ..."
            plt.text(0.5, -0.15, open_text, ha='center', va='top', transform=plt.gca().transAxes, fontsize=9, wrap=True)
        plt.tight_layout(rect=[0, 0.05, 1, 1]); plt.ylim(top=max_count * 1.15)
        try:
            plt.savefig(output_file, bbox_inches='tight', dpi=OUTPUT_DPI, transparent=True)
            print(f"  - Saved Nmap port status chart to {output_file} (DPI: {OUTPUT_DPI})")
        except Exception as e_save: print(f"  - Error saving Nmap port status chart: {e_save}")
        plt.close()
    except Exception as e_viz: print(f"  - Error during Nmap port status visualization: {e_viz}"); traceback.print_exc(limit=2); plt.close()

# Visualize Nikto Findings
def visualize_nikto_findings(nikto_data, output_file='5_nikto_findings.png'):
    if not nikto_data or not nikto_data.get('findings'): print("  - Skipping Nikto Findings: No findings."); return
    try:
        findings = nikto_data['findings']
        if not findings: print("  - Skipping Nikto Findings: Findings list empty."); return
        categories = {
            'Outdated/Vuln': ['outdated', 'vulnerable', 'osvdb-', 'cve-', 'cwe-', ' edb-id:', 'injection', 'xss', 'cross site scripting', 'default file', 'backup file'],
            'Config/Headers': ['x-frame-options', 'x-content-type-options', 'strict-transport-security', 'content-security-policy', 'server header', 'x-powered-by', 'cookie', 'httponly', 'secure flag', 'options', 'trace', 'debug', 'allow', 'directory indexing', 'robots.txt'],
            'Info Disclosure': ['interesting', 'leaked', ' reveals ', 'emails found', 'apache mod_info', 'phpinfo()', '/icons/', 'default page', 'directory listing'],
            'Server Info': ['server:', 'apache', 'nginx', 'iis', 'openssl']}
        category_counts = {cat: 0 for cat in categories}; category_counts['Other'] = 0
        for finding in findings:
            finding_lower = finding.lower(); categorized = False
            for cat, keywords in categories.items():
                if any(keyword.lower() in finding_lower for keyword in keywords):
                    category_counts[cat] += 1; categorized = True; break
            if not categorized: category_counts['Other'] += 1
        plot_data = {cat: count for cat, count in category_counts.items() if count > 0}
        if not plot_data: print("  - Skipping Nikto Findings: No categories found."); return

        plt.figure(figsize=(10, 8)); labels = list(plot_data.keys()); values = list(plot_data.values()) # Keep original figsize
        colors = plt.cm.Set3(np.linspace(0, 1, len(labels)))
        total_findings = sum(values)
        def autopct_func(pct): count = int(round(pct * total_findings / 100.0)); return f'{count}' if pct >= 5 and count > 0 else ''
        wedges, texts, autotexts = plt.pie(values, autopct=autopct_func, startangle=90, colors=colors, pctdistance=0.80, textprops={'color':'black', 'weight':'bold'}, wedgeprops={'edgecolor': 'white'})
        plt.title(f'Nikto: Findings Summary by Category (Total: {total_findings})'); plt.axis('equal')
        legend_labels = [f'{l} ({v})' for l, v in plot_data.items()]
        if wedges: plt.legend(wedges, legend_labels, title="Categories (Count)", loc="center left", bbox_to_anchor=(1, 0.5))
        plt.tight_layout(rect=[0, 0, 0.80, 1])
        try:
            plt.savefig(output_file, bbox_inches='tight', dpi=OUTPUT_DPI, transparent=True)
            print(f"  - Saved Nikto findings chart to {output_file} (DPI: {OUTPUT_DPI})")
        except Exception as e_save: print(f"  - Error saving Nikto findings chart: {e_save}")
        plt.close()
    except Exception as e_viz: print(f"  - Error during Nikto findings visualization: {e_viz}"); traceback.print_exc(limit=2); plt.close()

# Visualize Overall Summary
def visualize_summary_findings(security_data, output_file='0_summary_findings.png'):
    """Create a stacked bar chart summarizing UNIQUE findings by tool and risk level."""
    print("\n--- Generating Overall Summary Chart (Unique Counts) ---")
    try:
        tool_names = []
        total_findings_display = []
        high_risk, medium_risk, low_risk, info_risk = [], [], [], []
        risk_colors = { 'High': '#d9534f', 'Medium': '#f0ad4e', 'Low': '#5bc0de', 'Informational': '#5cb85c'}

        # ZAP Summary
        if security_data.get('zap'):
            tool_names.append('OWASP ZAP'); zap_alerts = security_data['zap']; unique_alerts_by_risk = Counter(); processed_plugin_ids = set()
            for alert in zap_alerts:
                plugin_id = alert.get('pluginid', 'N/A')
                if plugin_id not in processed_plugin_ids: risk_code = alert.get('risk_code', -1); unique_alerts_by_risk[risk_code] += 1; processed_plugin_ids.add(plugin_id)
            h=unique_alerts_by_risk.get(3,0);m=unique_alerts_by_risk.get(2,0);l=unique_alerts_by_risk.get(1,0);i=unique_alerts_by_risk.get(0,0)+unique_alerts_by_risk.get(-1,0);zap_total_unique=h+m+l+i
            total_findings_display.append(zap_total_unique);high_risk.append(h);medium_risk.append(m);low_risk.append(l);info_risk.append(i)
            print(f"  - ZAP Summary (Unique Types): H={h}, M={m}, L={l}, I={i} (Total Unique: {zap_total_unique})")
        else:
            if security_data.get('nmap') or security_data.get('nikto'): tool_names.append('OWASP ZAP');total_findings_display.append(0);high_risk.append(0);medium_risk.append(0);low_risk.append(0);info_risk.append(0);print("  - ZAP Summary: No data found.")
        # Nmap Summary
        if security_data.get('nmap'):
            tool_names.append('Nmap'); nmap_hosts = security_data['nmap']; all_ports = [p for host in nmap_hosts if host.get('ports') for p in host.get('ports')]; open_ports = [p for p in all_ports if p.get('state') == 'open']; open_ports_count = len(open_ports); total_findings_display.append(open_ports_count)
            n_high, n_med, n_low, n_info = 0, 0, 0, 0
            if open_ports_count > 5: n_high = open_ports_count; 
            elif open_ports_count > 2: n_med = open_ports_count; 
            elif open_ports_count > 0 : n_low = open_ports_count
            high_risk.append(n_high); medium_risk.append(n_med); low_risk.append(n_low); info_risk.append(n_info)
            print(f"  - Nmap Summary: Open Ports={open_ports_count} -> H={n_high}, M={n_med}, L={n_low}, I={n_info}")
        else:
             if security_data.get('zap') or security_data.get('nikto'): tool_names.append('Nmap');total_findings_display.append(0);high_risk.append(0);medium_risk.append(0);low_risk.append(0);info_risk.append(0);print("  - Nmap Summary: No data found.")
        # Nikto Summary
        if security_data.get('nikto') and security_data['nikto'].get('findings'):
            tool_names.append('Nikto'); findings = security_data['nikto']['findings']; nikto_total = len(findings); total_findings_display.append(nikto_total)
            high_keywords=['vulnerable','osvdb-','cve-','edb-id',' xss','injection','attack','exploit'];medium_keywords=['outdated','default file','backup file','directory indexing','password'];low_keywords=['x-frame-options','x-content-type-options','strict-transport-security','cookie','httponly','server header','x-powered-by']
            h_count, m_count, l_count, i_count = 0, 0, 0, 0; categorized_indices = set()
            for i, f in enumerate(findings):
                if any(k in f.lower() for k in high_keywords): h_count += 1; categorized_indices.add(i)
            for i, f in enumerate(findings):
                if i not in categorized_indices and any(k in f.lower() for k in medium_keywords): m_count += 1; categorized_indices.add(i)
            for i, f in enumerate(findings):
                if i not in categorized_indices and any(k in f.lower() for k in low_keywords): l_count += 1; categorized_indices.add(i)
            i_count = nikto_total - len(categorized_indices)
            high_risk.append(h_count); medium_risk.append(m_count); low_risk.append(l_count); info_risk.append(i_count)
            print(f"  - Nikto Summary (Unique Findings): H={h_count}, M={m_count}, L={l_count}, I={i_count} (Total Unique: {nikto_total})")
        else:
            if security_data.get('zap') or security_data.get('nmap'): tool_names.append('Nikto');total_findings_display.append(0);high_risk.append(0);medium_risk.append(0);low_risk.append(0);info_risk.append(0);print("  - Nikto Summary: No data found.")

        # Plotting
        if not tool_names: print("  - Skipping Overall Summary: No tool data found."); return

        x = np.arange(len(tool_names)); width = 0.6
        fig, ax = plt.subplots(figsize=(10, 6))
        np_info=np.array(info_risk);np_low=np.array(low_risk);np_med=np.array(medium_risk);np_high=np.array(high_risk);totals_for_label=np.array(total_findings_display)

        if not (len(x) == len(np_info) == len(np_low) == len(np_med) == len(np_high) == len(totals_for_label)): print("  - Error: Mismatch in array lengths for summary plotting. Skipping."); plt.close(); return

        bar_info=ax.bar(x,np_info,width,label='Informational',color=risk_colors['Informational'])
        bar_low=ax.bar(x,np_low,width,bottom=np_info,label='Low Risk',color=risk_colors['Low'])
        bottom_medium=np_info+np_low
        bar_medium=ax.bar(x,np_med,width,bottom=bottom_medium,label='Medium Risk',color=risk_colors['Medium'])
        bottom_high=bottom_medium+np_med
        bar_high=ax.bar(x,np_high,width,bottom=bottom_high,label='High Risk',color=risk_colors['High'])

        ax.set_ylabel('Number of Unique Findings / Open Ports')
        ax.set_title('Security Findings Summary by Tool (Unique Counts / Severity)')
        ax.set_xticks(x); ax.set_xticklabels(tool_names)
        ax.legend(title="Risk Level", bbox_to_anchor=(1.02, 1), loc='upper left')

        max_total = totals_for_label.max() if totals_for_label.size > 0 else 1
        for i, total in enumerate(totals_for_label):
            if total > 0 : ax.text(i, total + (max_total*0.01), f'{int(total)}', ha='center', va='bottom')

        plt.tight_layout(rect=[0, 0, 0.88, 1]); plt.ylim(bottom=0, top=max_total * 1.1 if max_total>0 else 1)

        try:
            plt.savefig(output_file, bbox_inches='tight', dpi=OUTPUT_DPI, transparent=True)
            print(f"  - Saved Overall Summary chart to {output_file} (DPI: {OUTPUT_DPI})")
        except Exception as e_save: print(f"  - Error saving Overall Summary chart: {e_save}")
        plt.close()
    except Exception as e_viz: print(f"  - Error during Overall Summary visualization: {e_viz}"); traceback.print_exc(limit=2); plt.close()

def main(xml_file_path, output_dir):
    """Main function to parse the XML and generate individual visualizations."""
    print(f"\nAttempting to analyze security scan data from: {xml_file_path}")
    if not os.path.exists(xml_file_path):
        print(f"\nError: Input XML file not found at '{xml_file_path}'"); return
    security_data = None
    try:
        security_data = parse_security_scan_xml(xml_file_path)
        if not security_data:
            print("\nFailed to parse any relevant security data. Exiting visualization."); return

        print("\nGenerating individual visualizations...")

        # Construct full output paths using os.path.join
        summary_output_path = os.path.join(output_dir, '0_summary_findings.png')
        zap_risk_output_path = os.path.join(output_dir, '1_zap_risk_distribution.png')
        zap_alerts_output_path = os.path.join(output_dir, '2_zap_alert_counts.png')
        nmap_status_output_path = os.path.join(output_dir, '4_nmap_port_status.png')
        nikto_findings_output_path = os.path.join(output_dir, '5_nikto_findings.png')

        # Generate Overall Summary Chart First
        visualize_summary_findings(security_data, output_file=summary_output_path)
        # Generate ZAP Visualizations
        if security_data.get('zap'):
            print("\n--- ZAP Visualizations ---")
            visualize_zap_risk_distribution(security_data['zap'], output_file=zap_risk_output_path)
            visualize_alert_counts(security_data['zap'], output_file=zap_alerts_output_path)
            print(f"  - Skipping ZAP Confidence vs Risk heatmap.")
        else: print("\n--- Skipping ZAP Visualizations (No ZAP data parsed) ---")
        # Generate Nmap Visualizations
        if security_data.get('nmap'):
            print("\n--- Nmap Visualizations ---")
            visualize_nmap_port_status(security_data['nmap'], output_file=nmap_status_output_path)
        else: print("\n--- Skipping Nmap Visualizations (No Nmap data parsed) ---")
        # Generate Nikto Visualizations
        nikto_data = security_data.get('nikto')
        if nikto_data and nikto_data.get('findings'):
            print("\n--- Nikto Visualizations ---")
            visualize_nikto_findings(nikto_data, output_file=nikto_findings_output_path)
        elif nikto_data: print("\n--- Skipping Nikto Visualizations (Nikto data present but no findings parsed) ---")
        else: print("\n--- Skipping Nikto Visualizations (No Nikto data parsed) ---")

        print("\nIndividual visualization generation process complete!")
        print(f"Please check the directory '{output_dir}' for the generated PNG files.")

    except FileNotFoundError: print(f"Error: XML file disappeared at '{xml_file_path}'")
    except ET.ParseError as e: print(f"Error parsing XML file '{xml_file_path}': {e}")
    except KeyError as e:
        print(f"\nError accessing expected data key during visualization: {e}. Check parsing logic & XML structure.")
        print("-" * 60); traceback.print_exc(); print("-" * 60)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {str(e)}")
        print("-" * 60); traceback.print_exc(); print("-" * 60)
        plt.close('all')

def generate_all_graphs_for_scan(scan_id):
    """
    Generates all graphs for a given scan ID.
    Constructs paths and calls the main visualization logic.
    Returns the output directory path on success, None on failure.
    """
    output_dir = os.path.join("scan_results", scan_id)
    xml_filename = os.path.join(output_dir, f"scan-report.xml")

    print(f"\n--- Starting Graph Generation for Scan ID: {scan_id} ---")
    print(f"Expecting Input XML: {xml_filename}")
    print(f"Output Directory for Graphs: {output_dir}")

    try: os.makedirs(output_dir, exist_ok=True)
    except OSError as e: print(f"Error creating output directory '{output_dir}' in generate_graphs: {e}"); return None

    if not os.path.exists(xml_filename): print(f"Error: Input XML '{xml_filename}' not found for graph generation."); return None

    try:
        main(xml_filename, output_dir)
        print(f"--- Graph Generation Potentially Complete for Scan ID: {scan_id} ---")
        return output_dir
    except Exception as e_main:
        print(f"--- Error during main graph processing for Scan ID {scan_id}: {e_main} ---")
        traceback.print_exc()
        return None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        script_name = os.path.basename(sys.argv[0])
        print(f"\nUsage: python {script_name} <scan_id>")
        sys.exit(1)
    scan_id_from_args = sys.argv[1]
    generate_all_graphs_for_scan(scan_id_from_args)