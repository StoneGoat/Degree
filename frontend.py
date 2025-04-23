# -*- coding: utf-8 -*- # Add encoding declaration for safety
from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, send_file, send_from_directory
import threading # Import threading earlier
import uuid
import os
import datetime
import traceback # Import traceback for detailed error logging

# Assuming these are your custom modules
import scan
import AI.chat as chat # More explicit import if chat is a module inside AI
import pdf_writer_module
import generate_graphs

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_default_development_secret_key') # Use env var or default
# Use absolute path for robustness, especially if running from different directories
SCAN_RESULTS_BASE_DIR = os.path.abspath('scan_results')
app.config['SCAN_RESULTS_DIR'] = SCAN_RESULTS_BASE_DIR

# Filenames
STATUS_FILENAME = 'status.md'
VULNERABILITY_FILENAME = 'vulnerability.md'

# Ensure the scan results directory exists
os.makedirs(app.config['SCAN_RESULTS_DIR'], exist_ok=True)
print(f"Scan results will be stored in: {app.config['SCAN_RESULTS_DIR']}")

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domain = request.form.get("domain")
        level_str = request.form.get("level") # Keep original string for clarity if needed

        level_map = {"Manager": 0, "Developer": 1, "CyberSec": 2}
        level = level_map.get(level_str) # Use .get for safer dictionary access

        if level is None:
                flash("Invalid level selected.")
                return redirect(url_for("index"))

        if not domain:
            flash("Please enter a domain.")
            return redirect(url_for("index"))

        try:
            # Generate a unique scan ID
            scan_id = str(uuid.uuid4())
            print(f"Generated new scan ID: {scan_id}")

            # Create directory for this scan using the absolute base path
            scan_dir = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
            os.makedirs(scan_dir, exist_ok=True)
            print(f"Created scan directory: {scan_dir}")

            # Initialize the VULNERABILITY markdown file (minimal header)
            md_file_path = os.path.join(scan_dir, VULNERABILITY_FILENAME)
            try:
                with open(md_file_path, 'w', encoding='utf-8') as f:
                    # Only basic info here, findings will be appended
                    f.write(f"# Scan Results for {domain}\n\n")
                    f.write(f"*Scan ID: `{scan_id}`*\n")
                    f.write(f"*Scan requested: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
                print(f"Initialized Vulnerability Markdown file: {md_file_path}")
            except IOError as e:
                print(f"Error writing initial vulnerability markdown: {e}")
                flash(f"Error initializing scan report file: {e}")
                return redirect(url_for("index"))

            # --- Initialize the STATUS markdown file with user-specified content ---
            status_md_path = os.path.join(scan_dir, STATUS_FILENAME)
            try:
                with open(status_md_path, 'w', encoding='utf-8') as f:
                    f.write(f"# Scan Status for {domain}\n\n") # Adjusted header slightly for clarity
                    f.write(f"*Scan ID: `{scan_id}`*\n")
                    # Match user's example time label
                    f.write(f"*Scan started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
                    f.write("## Initializing Scan\n\n")
                    # Match user's example message
                    f.write("Please wait while we analyze the target. This page will update automatically.\n\n")
                print(f"Initialized Status Markdown file: {status_md_path}")
            except IOError as e:
                print(f"Error writing initial status markdown: {e}")
                flash(f"Error initializing scan status file: {e}")
                # Allow proceeding even if status fails, but log it.
            # --- End Status Initialization ---


            # Redirect to results page immediately
            response = redirect(url_for('scan_results', scan_id=scan_id, domain=domain, level=level_str))

            # Start the scan process in a background thread
            scan_thread = threading.Thread(target=run_scan_process, args=(scan_id, domain, level, scan_dir, md_file_path, status_md_path))
            scan_thread.daemon = True
            scan_thread.start()

            return response

        except Exception as e:
            print(f"Error starting scan: {e}")
            traceback.print_exc()
            flash(f"An unexpected error occurred while starting the scan: {str(e)}")
            return redirect(url_for("index"))

    # For GET requests, just show the index page
    return render_template("index.html")


def run_scan_process(scan_id, domain, level, scan_dir, md_file_path, status_md_path):
    """Run the full scan, graph generation, and AI analysis, logging status updates."""
    start_time = datetime.datetime.now()
    print(f"[{scan_id}] Background scan process started for {domain} (Level: {level})")

    # Helper function to append status updates safely to status.md
    def append_status(message):
        try:
            # Use a simpler format for appending subsequent messages
            with open(status_md_path, 'a', encoding='utf-8') as f:
                 # Adding timestamp within the message might be noisy, keep sections clear
                 f.write(f"---\n\n{message}\n\n") # Use markdown separator
            print(f"[{scan_id}] Status Updated: {message.splitlines()[0]}...")
        except IOError as e:
            print(f"[{scan_id}] CRITICAL ERROR: Could not write status update to {status_md_path}: {e}")
        except Exception as e_stat:
             print(f"[{scan_id}] UNEXPECTED ERROR writing status update: {e_stat}")

    # Initialize variable
    xml_file_path_for_ai = None

    try:
        # --- Add "Scanning in Progress" status update ---
        # Match user's second example section
        append_status("## Scanning in Progress...\n\nThe scan tools (Nmap, Nikto, ZAP, etc.) are now running. Results will be appended below as they become available.")
        # --- End Status Update ---

        # --- Run the actual scans (e.g., Nmap, Nikto, ZAP via scan.py) ---
        print(f"[{scan_id}] Starting scan.run_scan...")
        # Assumes scan.run_scan triggers updates via the /update endpoint or similar mechanism
        # which writes to VULNERABILITY_FILENAME
        scan.run_scan(domain, scan_id)
        print(f"[{scan_id}] scan.run_scan finished.")
        # Optionally add a status update after scan tools finish, before analysis
        append_status("## Scan Tool Execution Complete\n\nMain scanning tools have finished. Proceeding with data analysis and report generation.")


        # --- Find the XML Report (Needed for Graphs and AI) ---
        print(f"[{scan_id}] Looking for XML report...")
        xml_report_filename = f"scan-report{scan_id}.xml"
        potential_xml_path_scan_dir = os.path.join(scan_dir, xml_report_filename)
        potential_xml_path_root = xml_report_filename # Relative path check

        if os.path.exists(potential_xml_path_scan_dir):
                xml_file_path_for_ai = potential_xml_path_scan_dir
                print(f"[{scan_id}] Found XML report at: {xml_file_path_for_ai}")
        elif os.path.exists(potential_xml_path_root):
                xml_file_path_for_ai = potential_xml_path_root
                print(f"[{scan_id}] Found XML report at: {xml_file_path_for_ai}")
        else:
            error_msg = f"ERROR: Cannot find XML report '{xml_report_filename}' in {scan_dir} or application root."
            print(f"[{scan_id}] {error_msg}")
            append_status(f"## Scan Data Error\n\nCould not find the necessary XML report ('`{xml_report_filename}`') required for graph generation and full AI analysis. Subsequent steps needing this file will be skipped.")
            # xml_file_path_for_ai remains None


        # --- Perform AI Analysis and Graph Generation (only if XML found) ---
        if xml_file_path_for_ai:
            append_status("## Post-Scan Processing Started\n\nFound scan data. Starting AI analysis and graph generation.")

            # 1. AI Overview (Original Position)
            try:
                print(f"[{scan_id}] Running chat.test_scan_overview...")
                # Assumes this writes findings to vulnerability.md
                chat.test_scan_overview(xml_file_path=xml_file_path_for_ai, scan_id=scan_id)
                print(f"[{scan_id}] chat.test_scan_overview finished.")
                append_status("### AI Overview Generation Completed.")
            except Exception as e_overview:
                error_msg = f"Error during AI Scan Overview generation: `{e_overview}`"
                print(f"[{scan_id}] {error_msg}")
                # Write this specific *process* error to status markdown
                append_status(f"### AI Overview Error\n\nAn error occurred during the AI overview step: `{e_overview}`\n\nOverview might be missing or incomplete in the main report.")

            # 2. Generate and Add Graphs (Original Position)
            print(f"[{scan_id}] Starting graph generation...")
            # This function now writes links to md_file_path and status/errors to status_md_path
            add_graphs_to_markdown(scan_id=scan_id, scan_dir=scan_dir, md_file_path=md_file_path, status_md_path=status_md_path)
            print(f"[{scan_id}] Graph generation and markdown update finished.")
            # Status updates for graphs are handled *inside* add_graphs_to_markdown

            # 3. Main AI Analysis (Original Position)
            try:
                print(f"[{scan_id}] Running main AI analysis (send_to_AI)...")
                # Assumes this writes findings to vulnerability.md
                # Pass status path for potential *process* errors during the call
                send_to_AI(scan_id=scan_id, level=level, xml_file_path=xml_file_path_for_ai, md_file_path=md_file_path, status_md_path=status_md_path)
                print(f"[{scan_id}] Main AI analysis function finished.")
                append_status("### Main AI Analysis Completed.")
            except Exception as e_main_ai:
                # This outer catch might be redundant if send_to_AI is robust, but safe to keep.
                # send_to_AI writes specific *process* errors to status_md_path.
                print(f"[{scan_id}] Error caught after calling send_to_AI: {e_main_ai}")
                append_status(f"### AI Analysis Error\n\nAn unexpected error occurred related to the main AI analysis call: `{e_main_ai}`")

        else:
            # This case is handled where xml_file_path_for_ai is checked above.
            # The status message about skipping is already added there.
            print(f"[{scan_id}] Skipping AI processing and Graph generation due to missing XML report.")


        # --- Final Status Update ---
        end_time = datetime.datetime.now()
        duration = end_time - start_time
        completion_message = "## Scan Process Complete\n\n"
        completion_message += f"Scan process finished at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        completion_message += f"Total duration: {str(duration).split('.')[0]}\n\n"
        if not xml_file_path_for_ai:
            completion_message += "*Note: AI analysis and graph generation were skipped due to missing scan data.*\n"
        completion_message += "Vulnerability details (if any) are in the main report (`vulnerability.md`).\nYou can now download the report as a PDF (based on the vulnerability data).\n"
        append_status(completion_message)
        print(f"[{scan_id}] Scan process finished.")

    except Exception as e:
        error_msg = f"CRITICAL ERROR in background scan process: {str(e)}"
        print(f"[{scan_id}] {error_msg}")
        traceback.print_exc()
        # Record critical error in status markdown
        append_status(f"## Critical Scan Error\n\nA critical error occurred during the scan execution:\n```\n{traceback.format_exc()}\n```\nThe scan may be incomplete.")


# --- The rest of the functions remain largely the same as the previous version ---
# --- (send_to_AI, add_graphs_to_markdown already modified for status path) ---
# --- (get_markdown, get_status_markdown, update_results, convert_to_markdown, download_pdf, serve_scan_image) ---


@app.route("/results")
def scan_results():
    """Dedicated page for viewing scan results"""
    scan_id = request.args.get('scan_id')
    domain = request.args.get('domain', 'Unknown Domain')
    level = request.args.get('level', 'Unknown Level') # Get level string back

    if not scan_id:
        flash("No scan ID provided.")
        return redirect(url_for("index"))

    try:
        uuid.UUID(scan_id, version=4)
    except ValueError:
        flash("Invalid Scan ID format.")
        return redirect(url_for("index"))

    scan_dir = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
    if not os.path.isdir(scan_dir):
            flash(f"Scan results not found for ID: {scan_id}")
            return redirect(url_for("index"))

    return render_template("results.html", scan_id=scan_id, domain=domain, level=level)


def send_to_AI(scan_id, level, xml_file_path, md_file_path, status_md_path):
    """Sends data to the AI module. Assumes AI results are written to vulnerability.md. Writes PROCESS errors to status.md."""
    try:
        print(f"[{scan_id}] Starting AI analysis call with XML: {xml_file_path}")
        # Assumes chat.run_AI writes findings to vulnerability.md (e.g., via /update)
        chat.run_AI(xml_file_path=xml_file_path, scan_id=scan_id, level=level)
        print(f"[{scan_id}] AI analysis function call completed (results should be in vulnerability report).")

    except Exception as e:
        error_msg = f"Error during AI Analysis processing call: {str(e)}"
        print(f"[{scan_id}] {error_msg}")
        traceback.print_exc()
        # Append PROCESS error to status markdown
        try:
            with open(status_md_path, 'a', encoding='utf-8') as f:
                # Use a clear section header for this error
                f.write(f"---\n\n### AI Analysis Process Error\n\n")
                f.write("An error occurred while trying to run the main AI analysis phase:\n")
                f.write(f"```\n{traceback.format_exc()}\n```\n")
                f.write("AI-generated findings in the main report might be missing or incomplete.\n\n")
        except IOError as e_inner:
            print(f"[{scan_id}] CRITICAL ERROR: Could not write AI process error to status file {status_md_path}: {e_inner}")


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
            # Should exist, but handle gracefully
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
    try: uuid.UUID(scan_id, version=4)
    except ValueError:
        print(f"Update request received with invalid scan_id format: {scan_id}")
        return jsonify({"error": "Invalid Scan ID format"}), 400

    try:
        vulnerability_data = request.get_json()
        if not vulnerability_data:
            print(f"[{scan_id}] Update request received with no JSON data")
            return jsonify({"error": "No JSON data provided"}), 400

        print(f"[{scan_id}] Received update data via /update endpoint.")
        markdown_chunk = convert_to_markdown(vulnerability_data) # Formats findings

        scan_dir = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
        md_file_path = os.path.join(scan_dir, VULNERABILITY_FILENAME)
        os.makedirs(scan_dir, exist_ok=True) # Ensure dir exists

        try:
            with open(md_file_path, 'a', encoding='utf-8') as f:
                f.write(markdown_chunk)
            print(f"[{scan_id}] Appended received vulnerability data to {md_file_path}")
            return jsonify({"status": "success", "message": f"Results appended for scan {scan_id}"})
        except IOError as e:
            print(f"[{scan_id}] Error appending vulnerability data to {md_file_path}: {e}")
            # Consider logging this error to status.md as well
            # status_md_path = os.path.join(scan_dir, STATUS_FILENAME) # Need path
            # append_status(f"## Error Processing Update\n\nFailed to write received data to vulnerability report: {e}", status_md_path) # requires helper
            return jsonify({"error": f"Failed to write update to report file: {e}"}), 500

    except Exception as e:
        print(f"Error processing /update request for {scan_id}: {str(e)}")
        traceback.print_exc()
        # Consider logging this error to status.md as well
        return jsonify({"error": f"Internal server error processing update: {str(e)}"}), 500


def convert_to_markdown(data):
    """Converts vulnerability data (dict, list, str) to markdown format for VULNERABILITY report."""
    # This function remains unchanged from the previous corrected version,
    # focusing on formatting findings, not status messages.
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
        markdown += "## Generic Data Update\n\n"
        for key, details in data.items():
            title = key.replace('_', ' ').title()
            markdown += f"### {title}\n\n"
            if isinstance(details, dict):
                for sub_key, value in details.items():
                    section_title = sub_key.replace('_', ' ').title()
                    markdown += f"**{section_title}:**\n```\n{value}\n```\n\n"
            elif isinstance(details, list):
                markdown += "**Items:**\n"
                for item in details: markdown += f"- {item}\n"
                markdown += "\n"
            else: markdown += f"```\n{details}\n```\n\n"
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
        # Ensure pdf_writer_module can handle image paths correctly
        # It might need the base directory (scan_dir) to resolve relative image paths
        pdf_writer_module.writeToPDF(md_file, output_pdf) # Pass base_path if needed
        print(f"[{scan_id}] PDF generation complete.")

        if not os.path.exists(output_pdf):
            print(f"[{scan_id}] PDF generation failed - file not found: {output_pdf}")
            flash("PDF generation failed. Check server logs.")
            # Log PDF failure to status.md?
            # status_md_path = os.path.join(scan_dir, STATUS_FILENAME)
            # append_status("## PDF Generation Error\n\nFailed to create the PDF file after generation attempt.", status_md_path)
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
        # Log PDF failure to status.md?
        # status_md_path = os.path.join(scan_dir, STATUS_FILENAME)
        # append_status(f"## PDF Generation Error\n\nAn exception occurred: {e}", status_md_path)
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

    # --- Append graph LINKS section to VULNERABILITY markdown ---
    if graphs_added_to_vuln > 0:
        try:
            with open(md_file_path, 'a', encoding='utf-8') as f:
                print(f"[{scan_id}] Appending {graphs_added_to_vuln} graph links to {VULNERABILITY_FILENAME}.")
                f.write(graph_link_section)
        except IOError as e:
            msg = f"Markdown Write Error: Failed to write graph links to {VULNERABILITY_FILENAME}: `{e}`"
            print(f"[{scan_id}] {msg}")
            status_updates_for_graphs.append(msg) # Log this failure too
    else:
         print(f"[{scan_id}] No graph links generated to add to {VULNERABILITY_FILENAME}.")
         # Optionally add placeholder to vulnerability.md if desired
         # try:
         #     with open(md_file_path, 'a', encoding='utf-8') as f:
         #         f.write("\n\n## Visual Summary\n\n_No visual summary graphs were generated or found._\n\n---\n\n")
         # except IOError as e: print(f"[{scan_id}] Error writing 'no graphs' to vuln md: {e}")

    # --- Append graph STATUS/ERROR updates to STATUS markdown ---
    if status_updates_for_graphs:
        try:
            with open(status_md_path, 'a', encoding='utf-8') as f:
                 print(f"[{scan_id}] Appending graph status updates to {STATUS_FILENAME}.")
                 # Add a clear section header for all graph-related status messages
                 f.write(f"---\n\n### Graph Generation Status Updates\n\n")
                 for update in status_updates_for_graphs:
                     f.write(f"{update}\n\n") # Add spacing between updates
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
    # Security check: Ensure path stays within the base scan directory
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
    # Use debug=False for production or when using external debuggers/reloaders
    app.run(host='0.0.0.0', port=5000, debug=True)