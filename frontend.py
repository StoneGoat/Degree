from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, send_file, send_from_directory
import threading
import uuid
import os
import datetime
from datetime import datetime as dt
import traceback
import combined_scan_module
import AI.chat as chat
import traceback # Import traceback for detailed error logging
import json
import xml.etree.ElementTree as ET

# Assuming these are your custom modules
import AI.chat as chat # More explicit import if chat is a module inside AI
import pdf_writer_module
import generate_graphs

# Config
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_default_development_secret_key') # Use env var or default
SCAN_RESULTS_BASE_DIR = os.path.abspath('scan_results')
app.config['SCAN_RESULTS_DIR'] = SCAN_RESULTS_BASE_DIR
STATUS_FILENAME = 'status.md'
VULNERABILITY_FILENAME = 'vulnerability.md'

# Ensure the scan results directory exists
os.makedirs(app.config['SCAN_RESULTS_DIR'], exist_ok=True)
print(f"Scan results will be stored in: {app.config['SCAN_RESULTS_DIR']}")

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domain = request.form.get("domain")
        level_str = request.form.get("level")
        username, password = "", ""
        if request.form.get("haslogin"):
          username = request.form.get("username")
          password = request.form.get("password")
        level_map = {"Manager": 0, "Developer": 1, "CyberSec": 2}
        level = level_map.get(level_str)

        if level is None:
                flash("Invalid level selected.")
                return redirect(url_for("index"))

        if not domain:
            flash("Please enter a domain.")
            return redirect(url_for("index"))

        try:
            # Generate a unique scan ID
            scan_id = str(uuid.uuid4())
            # scan_id = "d39d0e8a-864e-4655-b459-b43124cdaded"

            print(f"Generated new scan ID: {scan_id}")

            # Create directory for this scan using the absolute base path
            scan_dir = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
            os.makedirs(scan_dir, exist_ok=True)
            print(f"Created scan directory: {scan_dir}")

            # Initialize the VULNERABILITY md file (minimal header)
            md_file_path = os.path.join(scan_dir, VULNERABILITY_FILENAME)
            try:
                with open(md_file_path, 'w', encoding='utf-8') as f:
                    f.write(f"# Scan Results for {domain}\n\n")
                    f.write(f"*Scan ID: `{scan_id}`*\n")
                    f.write(f"*Scan requested: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
                print(f"Initialized Vulnerability Markdown file: {md_file_path}")
            except IOError as e:
                print(f"Error writing initial vulnerability markdown: {e}")
                flash(f"Error initializing scan report file: {e}")
                return redirect(url_for("index"))

            # Initialize the STATUS md file with user-specified content
            status_md_path = os.path.join(scan_dir, STATUS_FILENAME)
            try:
                with open(status_md_path, 'w', encoding='utf-8') as f:
                    f.write(f"# Scan Status for {domain}\n\n")
                    f.write(f"*Scan ID: `{scan_id}`*\n")
                    f.write(f"*Scan started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
                    f.write("## Initializing Scan\n\n")
                    f.write("Please wait while we analyze the target. This page will update automatically.\n\n")
                print(f"Initialized Status Markdown file: {status_md_path}")
            except IOError as e:
                print(f"Error writing initial status markdown: {e}")
                flash(f"Error initializing scan status file: {e}")

            # Redirect to results page
            response = redirect(url_for('scan_results', scan_id=scan_id, domain=domain, level=level_str))
            # Start the scan process in a background thread
            scan_thread = threading.Thread(target=run_scan_process, args=(scan_id, domain, level, scan_dir, md_file_path, status_md_path, username, password))
            scan_thread.daemon = True
            scan_thread.start()

            return response

        except Exception as e:
            print(f"Error starting scan: {e}")
            traceback.print_exc()
            flash(f"An unexpected error occurred while starting the scan: {str(e)}")
            return redirect(url_for("index"))

    return render_template("index.html")

def run_scan_process(scan_id, domain, level, scan_dir, md_file_path, status_md_path, username, password):
    start_time = datetime.datetime.now()
    print(f"[{scan_id}] Background scan process started for {domain} (Level: {level})")

    def append_status(msg):
        with open(status_md_path, 'a', encoding='utf-8') as f:
            f.write(f"---\n\n{msg}\n\n")
        print(f"[{scan_id}] Status Updated: {msg.splitlines()[0]}...")

    # 1) notify start
    append_status(
        "## Scanning in Progress...\n\n"
        "Nmap and Nikto scans will start immediately and their AI analyses will fire as each XML completes."
    )

    # 2) run all scans
    print(f"[{scan_id}] Starting scan.run_scan...")
    combined_scan_module.run_scan(domain, scan_id, level, username, password)
    append_status(
        "## Scan Tool Execution Complete\n\n"
        "Nmap and Nikto have finished (and triggered AI). Starting ZAP now."
    )

    append_status("## ZAP AI Analysis Starting")
    zap_xml = os.path.join(scan_dir, f"zap.xml")
    if os.path.exists(zap_xml):
        send_zap_to_AI(scan_id, zap_xml, status_md_path, level)
    else:
        append_status("### ZAP AI Skipped: zap-report XML not found")

    create_combined_xml(scan_dir)

    overview_xml = os.path.join(scan_dir, f"scan-report.xml")
    send_overview_to_AI(scan_id, overview_xml, status_md_path, level)

    # 3) generate visual summaries
    append_status("## Generating Visual Summaries...")
    add_graphs_to_markdown(
        scan_id=scan_id,
        scan_dir=scan_dir,
        md_file_path=md_file_path,
        status_md_path=status_md_path
    )

    # 5) final summary
    end_time = datetime.datetime.now()
    duration = str(end_time - start_time).split('.')[0]
    append_status(
        "## Scan Process Complete\n\n"
        f"Finished at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Total duration: {duration}"
    )
    print(f"[{scan_id}] Scan process finished.")

def create_combined_xml(scan_dir):
    files = ['nikto.xml', 'nmap.xml', 'zap.xml']

    # Create the new root
    root = ET.Element('ScanResults')

    for fname in files:
        filepath = os.path.join(scan_dir, fname)
        tree = ET.parse(filepath)
        src_root = tree.getroot()
        root.append(src_root)

    # Write out, with XML declaration
    combined = ET.ElementTree(root)
    combined_path = os.path.join(scan_dir, "scan-report.xml")
    combined.write(combined_path, encoding='utf-8', xml_declaration=True)
    pass

@app.route("/results")
def scan_results():
    """Dedicated page for viewing scan results"""
    scan_id = request.args.get('scan_id')
    domain = request.args.get('domain', 'Unknown Domain')
    level = request.args.get('level', 'Unknown Level')

    if not scan_id:
        flash("No scan ID provided.")
        return redirect(url_for("index"))

    # try:
    #     uuid.UUID(scan_id, version=4)
    # except ValueError:
    #     flash("Invalid Scan ID format.")
    #     return redirect(url_for("index"))

    scan_dir = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
    if not os.path.isdir(scan_dir):
            flash(f"Scan results not found for ID: {scan_id}")
            return redirect(url_for("index"))

    return render_template("results.html", scan_id=scan_id, domain=domain, level=level)


def append_status(status_md_path, message):
    with open(status_md_path, 'a', encoding='utf-8') as f:
        f.write(f"---\n\n{message}\n\n")

def send_zap_to_AI(scan_id, xml_file_path, status_md_path, level):
    try:
        print(f"[{scan_id}] Starting ZAP analysis")
        append_status(
            status_md_path,
            "### ZAP Scan Completed. AI Analysis Starting.\n" +
            f"Started at: {dt.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        chat.run_zap_analysis(f"scan_results/{scan_id}/zap.xml", scan_id, level)
        append_status(
            status_md_path,
            "### ZAP AI Analysis Completed.\n" +
            f"Finished at: {dt.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
    except Exception:
        err = traceback.format_exc()
        print(f"[{scan_id}] ZAP analysis error:\n{err}")
        append_status(status_md_path,
            "### ZAP AI Analysis Error\n\n"
            "```" + err + "```"
        )

def send_nmap_to_AI(scan_id, xml_file_path, status_md_path, level):
    try:
        print(f"[{scan_id}] Starting Nmap analysis")
        append_status(
            status_md_path,
            "### Nmap Scan Completed. AI Analysis Starting.\n" +
            f"Started at: {dt.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        chat.run_nmap_analysis(xml_file_path, scan_id, level)
        append_status(status_md_path, "### Nmap AI Analysis Completed.\n" + f"Finished at: {dt.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    except Exception:
        err = traceback.format_exc()
        print(f"[{scan_id}] Nmap analysis error:\n{err}")
        append_status(status_md_path,
            "### Nmap AI Analysis Error\n\n"
            "```" + err + "```"
        )

def send_nikto_to_AI(scan_id, xml_file_path, status_md_path, level):
    try:
        print(f"[{scan_id}] Starting Nikto analysis")
        append_status(
            status_md_path,
            "### Nikto Scan Completed. AI Analysis Starting.\n" +
            f"Started at: {dt.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        chat.run_nikto_analysis(xml_file_path, scan_id, level)
        append_status(status_md_path, "### Nikto AI Analysis Completed.\n" +  f"Finished at: {dt.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    except Exception:
        err = traceback.format_exc()
        print(f"[{scan_id}] Nikto analysis error:\n{err}")
        append_status(status_md_path,
            "### Nikto AI Analysis Error\n\n"
            "```" + err + "```"
        )

def send_overview_to_AI(scan_id, xml_file_path, status_md_path, level):
    try:
        print(f"[{scan_id}] Starting Overview Analysis")
        chat.run_overview_analysis(xml_file_path=xml_file_path, scan_id=scan_id, level=level)
        append_status(status_md_path, "### Overview AI Analysis Completed.")
    except Exception:
        err = traceback.format_exc()
        print(f"[{scan_id}] Overview analysis error:\n{err}")
        append_status(status_md_path,
            "### Overview AI Analysis Error\n\n"
            "```" + err + "```"
        )


@app.route("/get_markdown")
def get_markdown():
    """Returns VULNERABILITY markdown content"""
    scan_id = request.args.get('scan_id')
    if not scan_id: return jsonify({"markdown": "# Error\n\nNo scan ID provided."}), 400
    try: uuid.UUID(scan_id, version=4)
    except ValueError: return jsonify({"markdown": f"# Error\n\nInvalid Scan ID format: {scan_id}"}), 400

    try:
        markdown_path = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id, VULNERABILITY_FILENAME)
        if os.path.exists(markdown_path):
            with open(markdown_path, 'r', encoding='utf-8') as f:
                markdown_content = f.read()
            return jsonify({"markdown": markdown_content})
        else:
            return jsonify({"markdown": f"# Vulnerability Report Initializing\n\nScan report for `{scan_id}` is being generated..."}), 404
    except Exception as e:
        print(f"Error getting vulnerability markdown for {scan_id}: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e), "markdown": f"# Server Error\n\nError loading vulnerability markdown content for scan {scan_id}."}), 500


@app.route("/get_status_markdown")
def get_status_markdown():
    """Returns STATUS markdown content"""
    scan_id = request.args.get('scan_id')
    if not scan_id: return jsonify({"markdown": "# Error\n\nNo scan ID provided."}), 400
    try: uuid.UUID(scan_id, version=4)
    except ValueError: return jsonify({"markdown": f"# Error\n\nInvalid Scan ID format: {scan_id}"}), 400

    try:
        status_markdown_path = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id, STATUS_FILENAME)
        if os.path.exists(status_markdown_path):
            with open(status_markdown_path, 'r', encoding='utf-8') as f:
                status_markdown_content = f.read()
            return jsonify({"markdown": status_markdown_content})
        else:
            return jsonify({"markdown": f"# Status Unavailable\n\nStatus file for scan `{scan_id}` not found (it should have been created at the start)."}), 404
    except Exception as e:
        print(f"Error getting status markdown for {scan_id}: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e), "markdown": f"# Server Error\n\nError loading status markdown content for scan {scan_id}."}), 500


@app.route("/update", methods=["POST"])
def update_results():
    """Endpoint for scanners to post VULNERABILITY results"""
    scan_id = request.args.get('scan_id')
    if not scan_id:
        print("Update request received without scan_id")
        return jsonify({"error": "No scan ID provided"}), 400
    # try: uuid.UUID(scan_id, version=4)
    # except ValueError:
    #     print(f"Update request received with invalid scan_id format: {scan_id}")
    #     return jsonify({"error": "Invalid Scan ID format"}), 400

    try:
        vulnerability_data = request.get_json()["content"]
        order = request.get_json()["order"]
        if not vulnerability_data:
            print(f"[{scan_id}] Update request received with no JSON data")
            return jsonify({"error": "No JSON data provided"}), 400

        print(f"[{scan_id}] Received update data via /update endpoint.")
        markdown_chunk = convert_to_markdown(vulnerability_data)

        scan_dir = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)

        json_filepath = os.path.join(scan_dir, "report.json")

        if not os.path.exists(json_filepath):
            with open(json_filepath, "w") as f:
                json.dump({0: (), 1: (), 2: (), 3: (), 4: (), 5: ()}, f, indent=4)

        md_file_path = os.path.join(scan_dir, VULNERABILITY_FILENAME)
        os.makedirs(scan_dir, exist_ok=True)

        try:
            with open(json_filepath, "r+") as f:
              try:
                  data = json.load(f)
              except json.JSONDecodeError:
                  # Empty or invalid JSON → reinitialize
                  data = {0: (), 1: (), 2: (), 3: (), 4: (), 5: ()}

              # 3. Update the mapping
              data[str(order)].append(markdown_chunk)

              # 4. Write back, then truncate any leftover
              f.seek(0)
              json.dump(data, f, indent=4)
              f.truncate()

              # Now rebuild the vulnerability.md from the JSON data
              with open(md_file_path, 'w', encoding='utf-8') as f:
                  for order_key in sorted(data.keys(), key=str):  # Sort by order key
                      for chunk in data[order_key]:
                          if chunk:  # Only write non-empty chunks
                              f.write(chunk)
            
            print(f"[{scan_id}] Appended received vulnerability data to {md_file_path}")
            return jsonify({"status": "success", "message": f"Results appended for scan {scan_id}"})
        except IOError as e:
            print(f"[{scan_id}] Error appending vulnerability data to {md_file_path}: {e}")
            return jsonify({"error": f"Failed to write update to report file: {e}"}), 500

    except Exception as e:
        print(f"Error processing /update request for {scan_id}: {str(e)}")
        traceback.print_exc()
        return jsonify({"error": f"Internal server error processing update: {str(e)}"}), 500


def convert_to_markdown(data):
    markdown = "\n\n"
    if isinstance(data, dict):
        if 'nmap_scan_summary' in data:
            markdown += "## Nmap Scan Summary\n\n"
            markdown += f"{data['nmap_scan_summary']}\n\n---\n"
            return markdown
        if 'zap_alerts' in data and isinstance(data['zap_alerts'], list):
            markdown += "## ZAP Scan Alerts\n\n"
            if not data['zap_alerts']: markdown += "_No ZAP alerts reported in this update._\n\n"
            else:
                for alert in data['zap_alerts']:
                    name = alert.get('name', 'Unnamed Alert')
                    risk = alert.get('risk', 'Unknown Risk')
                    desc = alert.get('description', 'No description.')
                    sol = alert.get('solution', 'No solution.')
                    markdown += f"### {name} (Risk: {risk})\n"
                    markdown += f"**Description:**\n{desc}\n\n"
                    markdown += f"**Solution:**\n{sol}\n\n"
                    if 'url' in alert: markdown += f"**URL:** `{alert['url']}`\n\n"
                    markdown += "---\n"
            return markdown
        if 'nikto_findings' in data and isinstance(data['nikto_findings'], list):
            markdown += "## Nikto Findings\n\n"
            if not data['nikto_findings']: markdown += "_No Nikto findings reported in this update._\n\n"
            else:
                for item in data['nikto_findings']:
                    desc = item.get('description', 'No description')
                    uri = item.get('uri', '')
                    markdown += f"- **{uri}**: {desc}\n"
            markdown += "\n---\n"
            return markdown
        # Fallback for generic dict
        for key, details in data.items():
            title = key.replace('_', ' ').title()
            markdown += f"### {title}\n\n"
            if isinstance(details, dict):
                for sub_key, value in details.items():
                    section_title = sub_key.replace('_', ' ').title()
                    markdown += f"**{section_title}:**\n\n{value}\n\n\n"
            elif isinstance(details, list):
                markdown += "**Items:**\n"
                for item in details: markdown += f"- {item}\n"
                markdown += "\n"
            else: markdown += f"\n{details}\n\n\n"
            markdown += "---\n\n"
        return markdown
    elif isinstance(data, str):
        markdown += "## General Update Finding\n\n"
        markdown += f"{data}\n\n---\n\n"
        return markdown
    elif isinstance(data, list):
        markdown += "## List Update Findings\n\n"
        for item in data: markdown += f"- {item}\n"
        markdown += "\n---\n\n"
        return markdown
    print(f"Warning: Unknown data type received in convert_to_markdown: {type(data)}")
    markdown += f"## Unknown Data Format Received\n\nCould not format:\n```\n{str(data)}\n```\n\n---\n\n"
    return markdown


@app.route("/download_pdf/<scan_id>")
def download_pdf(scan_id):
    """Generates and serves the PDF report based on VULNERABILITY.md"""
    try: uuid.UUID(scan_id, version=4)
    except ValueError:
        flash("Invalid Scan ID format.")
        return redirect(url_for("index"))

    scan_dir = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
    md_file = os.path.join(scan_dir, VULNERABILITY_FILENAME) # Source is vulnerability report
    output_pdf = os.path.join(scan_dir, f"scan_report_{scan_id}.pdf")

    if not os.path.exists(scan_dir):
        flash(f"Scan directory not found for ID: {scan_id}")
        return redirect(url_for('scan_results', scan_id=scan_id))
    if not os.path.exists(md_file):
        flash("Vulnerability report (markdown file) not found. PDF cannot be generated yet.")
        return redirect(url_for('scan_results', scan_id=scan_id))

    try:
        print(f"[{scan_id}] Generating PDF from {md_file} to {output_pdf}")
        pdf_writer_module.write_to_PDF(md_file, output_pdf)
        print(f"[{scan_id}] PDF generation complete.")

        if not os.path.exists(output_pdf):
            print(f"[{scan_id}] PDF generation failed - file not found: {output_pdf}")
            flash("PDF generation failed. Check server logs.")
            return redirect(url_for('scan_results', scan_id=scan_id))

        return send_file(
            output_pdf,
            as_attachment=True,
            download_name=f"Vulnerability_Report_{scan_id}.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        print(f"[{scan_id}] Error during PDF generation/sending: {e}")
        traceback.print_exc()
        flash(f"An error occurred during PDF generation: {str(e)}")
        return redirect(url_for('scan_results', scan_id=scan_id))


def add_graphs_to_markdown(scan_id, scan_dir, md_file_path, status_md_path):
    """Generates graphs. Appends LINKS to vulnerability.md. Appends STATUS/ERRORS to status.md."""
    print(f"[{scan_id}] --- Attempting graph generation and markdown update ---")
    graph_link_section = "\n\n## Visual Summary\n\n" # For vulnerability.md
    status_updates_for_graphs = [] # Collect status messages
    graphs_added_to_vuln = 0
    graphs_failed = []

    graph_files_relative = {
        "0_summary_findings.png": "Overall Findings Summary",
        "1_zap_risk_distribution.png": "ZAP Unique Alerts by Risk",
        "2_zap_alert_counts.png": "ZAP Top Alerts by Occurrence",
        "4_nmap_port_status.png": "Nmap Port Status Summary",
        "5_nikto_findings.png": "Nikto Findings by Category"
    }
    graph_output_dir = None

    try:
        print(f"[{scan_id}] Calling generate_graphs.generate_all_graphs_for_scan(scan_id='{scan_id}')")
        graph_output_dir = generate_graphs.generate_all_graphs_for_scan(scan_id)

        if graph_output_dir:
            if not os.path.isdir(graph_output_dir):
                msg = f"Graph Generation Warning: Script returned non-directory path: `{graph_output_dir}`. No graphs embedded."
                print(f"[{scan_id}] {msg}")
                status_updates_for_graphs.append(msg)
                graph_output_dir = None # Treat as failure for embedding
            else:
                msg = f"Graph Generation Status: Graphs generated successfully into directory: `{graph_output_dir}`."
                print(f"[{scan_id}] {msg}")
                status_updates_for_graphs.append(msg)

                for filename, title in graph_files_relative.items():
                    full_image_path = os.path.join(graph_output_dir, filename)
                    if os.path.exists(full_image_path):
                        image_url = f"/scan_results/{scan_id}/{filename}" # Relative URL for browser
                        graph_link_section += f"### {title}\n![{title}]({image_url})\n\n"
                        graphs_added_to_vuln += 1
                        print(f"[{scan_id}]   - Found {filename}. Added link to vuln report.")
                    else:
                        graphs_failed.append(filename)
                        print(f"[{scan_id}]   - Expected graph not found: {filename}")

                if graphs_failed:
                    msg = f"Missing Graphs: Expected graph files not found: `{'`, `'.join(graphs_failed)}`"
                    status_updates_for_graphs.append(msg)
                graph_link_section += "---\n\n" # Separator in vulnerability report
        else:
            msg = "Graph Generation Status: Graph generation failed or was skipped (returned None). No graphs added."
            print(f"[{scan_id}] {msg}")
            status_updates_for_graphs.append(msg)

    except Exception as e:
        msg = f"Graph Generation Error: An error occurred during processing:\n```\n{traceback.format_exc()}\n```"
        print(f"[{scan_id}] {msg.splitlines()[0]}") # Log first line
        status_updates_for_graphs.append(msg)
        if graph_output_dir is None and 'graph_output_dir' not in locals(): graph_output_dir = None

    # Append graph LINKS section to VULNERABILITY markdown
    if graphs_added_to_vuln > 0:
        try:
            print(f"[{scan_id}] Appending {graphs_added_to_vuln} graph links to {VULNERABILITY_FILENAME}.")

            json_filepath = os.path.join(scan_dir, "report.json")

            with open(json_filepath, "r+") as f:
              try:
                  data = json.load(f)
              except json.JSONDecodeError:
                  # Empty or invalid JSON → reinitialize
                  data = {0: (), 1: (), 2: (), 3: (), 4: (), 5: ()}

              # 3. Update the mapping
              data[str(1)].append(graph_link_section)

              # 4. Write back, then truncate any leftover
              f.seek(0)
              json.dump(data, f, indent=4)
              f.truncate()

              # Now rebuild the vulnerability.md from the JSON data
              with open(md_file_path, 'w', encoding='utf-8') as f:
                  for order_key in sorted(data.keys(), key=str):  # Sort by order key
                      for chunk in data[order_key]:
                          if chunk:  # Only write non-empty chunks
                              f.write(chunk)
              
        except IOError as e:
            msg = f"Markdown Write Error: Failed to write graph links to {VULNERABILITY_FILENAME}: `{e}`"
            print(f"[{scan_id}] {msg}")
            status_updates_for_graphs.append(msg) # Log this failure too
    else:
         print(f"[{scan_id}] No graph links generated to add to {VULNERABILITY_FILENAME}.")

    # Append graph STATUS/ERROR updates to STATUS markdown
    if status_updates_for_graphs:
        try:
            with open(status_md_path, 'a', encoding='utf-8') as f:
                 print(f"[{scan_id}] Appending graph status updates to {STATUS_FILENAME}.")
                 f.write(f"---\n\n### Graph Generation Status Updates\n\n")
                 for update in status_updates_for_graphs:
                     f.write(f"{update}\n\n")
        except IOError as e:
            print(f"[{scan_id}] CRITICAL ERROR: Could not write graph status updates to {status_md_path}: {e}")


@app.route('/scan_results/<scan_id>/<path:filename>')
def serve_scan_image(scan_id, filename):
    """Serves static files (like images) from the specific scan results directory"""
    try: uuid.UUID(scan_id, version=4)
    except ValueError:
        print(f"Invalid scan_id format requested in serve_scan_image: {scan_id}")
        return "Invalid Scan ID", 400

    directory = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
    requested_path = os.path.join(directory, filename)
    # Ensure path stays within the base scan directory
    if not os.path.abspath(requested_path).startswith(os.path.abspath(directory)):
        print(f"Forbidden path requested: {filename} for scan {scan_id}")
        return "Forbidden", 403

    print(f"Attempting to serve file: {filename} from directory: {directory}")
    if not os.path.isdir(directory): # Check directory existence first
        print(f"Directory not found: {directory}")
        return "Scan directory not found", 404

    try:
        return send_from_directory(directory, filename)
    except FileNotFoundError:
        print(f"File not found within directory: {requested_path}")
        return "File not found", 404
    except Exception as e:
        print(f"Error serving file {filename} from {directory}: {e}")
        traceback.print_exc()
        return "Error serving file", 500


if __name__ == "__main__":
    print("Starting Flask development server...")
    print(f"Access at: http://127.0.0.1:5000 or http://<your-ip>:5000")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)