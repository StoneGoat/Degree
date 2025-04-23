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
            scan_id = "f0fc43df-33c4-4eef-9a09-47edfc8a652c"
            scan_id = str(uuid.uuid4())
            print(f"Generated new scan ID: {scan_id}")

            # Create directory for this scan using the absolute base path
            scan_dir = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
            os.makedirs(scan_dir, exist_ok=True)
            print(f"Created scan directory: {scan_dir}")

            # Initialize the markdown file with minimal content
            md_file_path = os.path.join(scan_dir, 'vulnerability.md')
            try:
                with open(md_file_path, 'w', encoding='utf-8') as f:
                    f.write(f"# Scan Results for {domain}\n\n")
                    f.write(f"*Scan ID: `{scan_id}`*\n")
                    f.write(f"*Scan started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
                    f.write("## Initializing Scan\n\n")
                    f.write("Please wait while we analyze the target. This page will update automatically.\n\n")
                print(f"Initialized Markdown file: {md_file_path}")
            except IOError as e:
                print(f"Error writing initial markdown: {e}")
                flash(f"Error initializing scan report file: {e}")
                return redirect(url_for("index"))


            # Redirect to results page immediately
            # Pass domain and level string for display on results page if needed
            response = redirect(url_for('scan_results', scan_id=scan_id, domain=domain, level=level_str))

            # Start the scan process in a background thread to avoid blocking
            scan_thread = threading.Thread(target=run_scan_process, args=(scan_id, domain, level, scan_dir, md_file_path))
            scan_thread.daemon = True # Ensures thread exits when main app exits
            scan_thread.start()

            return response

        except Exception as e:
            print(f"Error starting scan: {e}")
            traceback.print_exc()
            flash(f"An unexpected error occurred while starting the scan: {str(e)}")
            return redirect(url_for("index"))

    # For GET requests, just show the index page
    return render_template("index.html")

def run_scan_process(scan_id, domain, level, scan_dir, md_file_path):
    """Run the full scan, graph generation, and AI analysis in a separate thread"""
    start_time = datetime.datetime.now()
    print(f"[{scan_id}] Background scan process started for {domain} (Level: {level})")

    # Initialize variable to None early
    xml_file_path_for_ai = None

    try:
        # Add a note to the markdown file that scanning has begun
        try:
            with open(md_file_path, 'a', encoding='utf-8') as f:
                f.write("## Scanning in Progress...\n\n")
                f.write("The scan tools (Nmap, Nikto, ZAP, etc.) are now running. Results will be appended below as they become available.\n\n")
            print(f"[{scan_id}] Updated markdown: Scanning in progress")
        except IOError as e:
             print(f"[{scan_id}] Error updating markdown (scan start): {e}")
             # Continue scan even if markdown update fails initially

        # --- Run the actual scans ---
        print(f"[{scan_id}] Starting scan.run_scan...")
        # Keeping this call as requested - ensure scan.py's run_scan DEFINITION accepts scan_id
        scan.run_scan(domain, scan_id)
        print(f"[{scan_id}] scan.run_scan finished.")

        # --- Find the XML Report ---
        # Moved this block UP - must happen before graphs or AI use the path
        print(f"[{scan_id}] Looking for XML report...")
        xml_report_filename = f"scan-report{scan_id}.xml"
        potential_xml_path_scan_dir = os.path.join(scan_dir, xml_report_filename)
        potential_xml_path_root = xml_report_filename # Relative to app root

        if os.path.exists(potential_xml_path_scan_dir):
             xml_file_path_for_ai = potential_xml_path_scan_dir
             print(f"[{scan_id}] Found XML report at: {xml_file_path_for_ai}")
        elif os.path.exists(potential_xml_path_root):
             xml_file_path_for_ai = potential_xml_path_root
             print(f"[{scan_id}] Found XML report at: {xml_file_path_for_ai}")
        else:
             # xml_file_path_for_ai remains None
             print(f"[{scan_id}] ERROR: Cannot find XML report '{xml_report_filename}' in {scan_dir} or application root.")
             # Append error to markdown
             try:
                with open(md_file_path, 'a', encoding='utf-8') as f:
                    f.write("\n## Scan Data Error\n\n")
                    f.write(f"Could not find the necessary XML report ('{xml_report_filename}') to perform graph generation and AI analysis.\n\n")
             except IOError as e:
                 print(f"[{scan_id}] Error writing XML finding error to markdown: {e}")


        # --- Perform AI Analysis (including overview) ---
        print(f"[{scan_id}] Starting AI processing...")
        if xml_file_path_for_ai:
            # Only run AI steps if the XML file was actually found
            try:
                print(f"[{scan_id}] Running chat.test_scan_overview...")
                # Moved the overview call here, INSIDE the check for the XML file
                chat.test_scan_overview(xml_file_path=xml_file_path_for_ai, scan_id=scan_id)
                print(f"[{scan_id}] chat.test_scan_overview finished.")
            except Exception as e_overview:
                 print(f"[{scan_id}] Error during chat.test_scan_overview: {e_overview}")
                 # Optionally write this specific error to markdown too
                 try:
                    with open(md_file_path, 'a', encoding='utf-8') as f:
                        f.write(f"\n### AI Overview Error\n\nAn error occurred during the AI overview step: `{e_overview}`\n\n")
                 except IOError as e_write:
                     print(f"[{scan_id}] Error writing overview error to markdown: {e_write}")

            # --- Generate and Add Graphs ---
            # Graphs might depend on the XML, or might just need the scan_id/scan_dir
            # If generate_graphs needs the XML path, it should ideally take it as an argument.
            # Calling it here after finding the path, but before AI analysis.
            print(f"[{scan_id}] Starting graph generation...")
            add_graphs_to_markdown(scan_id=scan_id, scan_dir=scan_dir, md_file_path=md_file_path)
            print(f"[{scan_id}] Graph generation and markdown update finished.")


            try:
                print(f"[{scan_id}] Running main AI analysis (send_to_AI)...")
                # Main AI call
                send_to_AI(scan_id=scan_id, level=level, xml_file_path=xml_file_path_for_ai, md_file_path=md_file_path)
                print(f"[{scan_id}] Main AI analysis finished.")
            except Exception as e_main_ai:
                print(f"[{scan_id}] Error during send_to_AI: {e_main_ai}")
                # Error is already handled inside send_to_AI, but log here too if needed.

        else:
             # This condition is handled by the print statement during XML search
             print(f"[{scan_id}] Skipping AI processing (overview and main analysis) due to missing XML report.")


        # --- Final Markdown Update ---
        end_time = datetime.datetime.now()
        duration = end_time - start_time
        try:
            with open(md_file_path, 'a', encoding='utf-8') as f:
                f.write("\n## Scan Complete\n\n")
                f.write(f"Scan completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total duration: {str(duration).split('.')[0]}\n\n") # Show duration nicely
                # Add note about whether AI analysis ran
                if not xml_file_path_for_ai:
                     f.write("*Note: AI analysis was skipped due to missing scan data.*\n\n")
                f.write("You can now download the report as a PDF.\n")
            print(f"[{scan_id}] Updated markdown: Scan complete.")
        except IOError as e:
             print(f"[{scan_id}] Error updating markdown (scan complete): {e}")

    except Exception as e:
        print(f"[{scan_id}] CRITICAL ERROR in background scan process: {str(e)}")
        traceback.print_exc()
        # Record error in markdown if possible
        try:
            with open(md_file_path, 'a', encoding='utf-8') as f:
                f.write("\n## Error During Scan Process\n\n")
                f.write("A critical error occurred during the scan execution:\n")
                f.write(f"```\n{traceback.format_exc()}\n```\n") # Include traceback in MD
        except Exception as E_inner:
            print(f"[{scan_id}] Could not write critical error to markdown file: {E_inner}")

@app.route("/results")
def scan_results():
    """Dedicated page for viewing scan results"""
    scan_id = request.args.get('scan_id')
    domain = request.args.get('domain', 'Unknown Domain')
    level = request.args.get('level', 'Unknown Level') # Get level string back

    if not scan_id:
        flash("No scan ID provided.")
        return redirect(url_for("index"))

    # Validate scan_id format (optional but good practice)
    try:
        uuid.UUID(scan_id, version=4)
    except ValueError:
        flash("Invalid Scan ID format.")
        return redirect(url_for("index"))

    # Check if scan directory exists
    scan_dir = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
    if not os.path.isdir(scan_dir):
         flash(f"Scan results not found for ID: {scan_id}")
         return redirect(url_for("index"))


    return render_template("results.html", scan_id=scan_id, domain=domain, level=level)

def send_to_AI(scan_id, level, xml_file_path, md_file_path):
    """Sends data to the AI module and appends results to markdown."""
    try:
        print(f"[{scan_id}] Starting AI analysis with XML: {xml_file_path}")
        # Assuming chat.run_AI returns the markdown content or handles writing it
        # If it returns content, we need to append it. If it uses /update, that's handled elsewhere.
        # Let's assume chat.run_AI *appends* directly or via the /update endpoint.
        # If it returns text: ai_markdown = chat.run_AI(...)
        chat.run_AI(xml_file_path=xml_file_path, scan_id=scan_id, level=level)

        # If chat.run_AI returns markdown string:
        # if ai_markdown:
        #     try:
        #         with open(md_file_path, 'a', encoding='utf-8') as f:
        #             f.write("\n## AI Analysis Results\n\n")
        #             f.write(ai_markdown)
        #             f.write("\n\n---\n\n")
        #         print(f"[{scan_id}] Appended AI results to markdown.")
        #     except IOError as e:
        #         print(f"[{scan_id}] Error writing AI results to markdown: {e}")

        print(f"[{scan_id}] AI analysis function call completed.")
    except Exception as e:
        print(f"[{scan_id}] Error in send_to_AI: {str(e)}")
        traceback.print_exc()
        # Append error to markdown
        try:
            with open(md_file_path, 'a', encoding='utf-8') as f:
                f.write("\n## AI Analysis Error\n\n")
                f.write("An error occurred during the AI analysis phase:\n")
                f.write(f"```\n{traceback.format_exc()}\n```\n")
        except IOError as e_inner:
            print(f"[{scan_id}] Could not write AI error to markdown: {e_inner}")


@app.route("/get_markdown")
def get_markdown():
    """Returns markdown content for a specific scan ID (used by results page JS)"""
    scan_id = request.args.get('scan_id')

    if not scan_id:
        return jsonify({"markdown": "# Error\n\nNo scan ID provided."}), 400

    try:
        # Validate scan_id format
        uuid.UUID(scan_id, version=4)
    except ValueError:
        return jsonify({"markdown": f"# Error\n\nInvalid Scan ID format: {scan_id}"}), 400

    try:
        # Construct the path using the absolute base directory
        markdown_path = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id, 'vulnerability.md')

        if os.path.exists(markdown_path):
            with open(markdown_path, 'r', encoding='utf-8') as f:
                markdown_content = f.read()
            return jsonify({"markdown": markdown_content})
        else:
            # Handle case where MD file doesn't exist (maybe scan just started)
             return jsonify({"markdown": f"# Scan Initializing\n\nScan report for `{scan_id}` is being generated..."}), 404


    except Exception as e:
        print(f"Error getting markdown for {scan_id}: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e), "markdown": f"# Server Error\n\nError loading markdown content for scan {scan_id}."}), 500

@app.route("/update", methods=["POST"])
def update_results():
    """Endpoint for scanners (like ZAP callback) to post results"""
    try:
        vulnerability_data = request.get_json()
        scan_id = request.args.get('scan_id')

        if not scan_id:
            print("Update request received without scan_id")
            return jsonify({"error": "No scan ID provided in query parameter"}), 400

        if not vulnerability_data:
            print(f"[{scan_id}] Update request received with no JSON data")
            return jsonify({"error": "No JSON data provided in request body"}), 400

        # Validate scan_id format
        try:
            uuid.UUID(scan_id, version=4)
        except ValueError:
             print(f"Update request received with invalid scan_id format: {scan_id}")
             return jsonify({"error": "Invalid Scan ID format"}), 400


        print(f"[{scan_id}] Received update data via /update endpoint.")
        # print(vulnerability_data) # Can be verbose, uncomment if needed

        # Convert the vulnerability data to Markdown format
        markdown_chunk = convert_to_markdown(vulnerability_data)

        # Save the markdown to the scan-specific file
        scan_dir = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
        md_file_path = os.path.join(scan_dir, 'vulnerability.md')

        # Ensure directory exists (should already, but safe check)
        os.makedirs(scan_dir, exist_ok=True)

        try:
            with open(md_file_path, 'a', encoding='utf-8') as f:
                f.write(markdown_chunk)
            print(f"[{scan_id}] Appended received data to {md_file_path}")
        except IOError as e:
             print(f"[{scan_id}] Error appending data to markdown file {md_file_path}: {e}")
             return jsonify({"error": f"Failed to write update to report file: {e}"}), 500


        return jsonify({
            "status": "success",
            "message": f"Results received and appended to markdown for scan {scan_id}"
        })

    except Exception as e:
        print(f"Error processing /update request: {str(e)}")
        traceback.print_exc()
        return jsonify({"error": f"Internal server error processing update: {str(e)}"}), 500

def convert_to_markdown(data):
    """Converts vulnerability data (dict or specific structure) to markdown format"""
    markdown = "\n\n" # Start with spacing

    # Handle specific known structures first
    if isinstance(data, dict):
        # Nmap overview structure (example)
        if 'nmap_scan_summary' in data:
             markdown += "## Nmap Scan Summary\n\n"
             markdown += f"{data['nmap_scan_summary']}\n\n"
             markdown += "---\n"
             return markdown # Return early if it's just this summary

        # ZAP alert structure (example) - iterate through alerts if it's a list/dict
        if 'zap_alerts' in data and isinstance(data['zap_alerts'], list):
            markdown += "## ZAP Scan Alerts\n\n"
            for alert in data['zap_alerts']:
                 # Assuming alert is a dict with keys like 'name', 'risk', 'description', 'solution' etc.
                 name = alert.get('name', 'Unnamed Alert')
                 risk = alert.get('risk', 'Unknown Risk')
                 description = alert.get('description', 'No description provided.')
                 solution = alert.get('solution', 'No solution provided.')
                 # Add more fields as needed: confidence, url, param, evidence, etc.

                 markdown += f"### {name} (Risk: {risk})\n"
                 markdown += f"**Description:**\n{description}\n\n"
                 markdown += f"**Solution:**\n{solution}\n\n"
                 # Example: Add URL if available
                 if 'url' in alert:
                     markdown += f"**URL:** `{alert['url']}`\n\n"
                 markdown += "---\n" # Separator between alerts
            return markdown

        # Nikto item structure (example)
        if 'nikto_findings' in data and isinstance(data['nikto_findings'], list):
            markdown += "## Nikto Findings\n\n"
            for item in data['nikto_findings']:
                 # Assuming item is a dict with 'id', 'description', 'uri', etc.
                 desc = item.get('description', 'No description')
                 uri = item.get('uri', '')
                 markdown += f"- **{uri}**: {desc}\n"
            markdown += "\n---\n"
            return markdown


        # Fallback for generic dictionaries (like original structure)
        for key, details in data.items():
            # Replace underscores/etc in key for a cleaner title if needed
            title = key.replace('_', ' ').title()
            markdown += f"## {title}\n\n"
            if isinstance(details, dict):
                # Iterate through standard sub-sections if they exist
                for sub_key, value in details.items():
                     section_title = sub_key.replace('_', ' ').title()
                     markdown += f"### {section_title}\n{value}\n\n"
            elif isinstance(details, list):
                 markdown += "Items:\n"
                 for item in details:
                     markdown += f"- {item}\n"
                 markdown += "\n"
            else:
                markdown += f"{details}\n\n" # Simple key-value
            markdown += "---\n\n"
        return markdown

    # Handle plain string data (less likely from scanners but possible)
    elif isinstance(data, str):
         markdown += "## General Update\n\n"
         markdown += f"{data}\n\n"
         markdown += "---\n\n"
         return markdown

    # Handle list data (e.g., list of strings)
    elif isinstance(data, list):
         markdown += "## List Update\n\n"
         for item in data:
             markdown += f"- {item}\n"
         markdown += "\n---\n\n"
         return markdown


    # If data type is unknown
    print(f"Warning: Unknown data type received in convert_to_markdown: {type(data)}")
    markdown += f"## Unknown Data Format\n\nReceived data:\n```\n{str(data)}\n```\n\n---\n\n"
    return markdown


@app.route("/download_pdf/<scan_id>")
def download_pdf(scan_id):
    """Generates and serves the PDF report"""
    # Validate scan_id format
    try:
        uuid.UUID(scan_id, version=4)
    except ValueError:
        flash("Invalid Scan ID format.")
        return redirect(url_for("index")) # Or redirect to results page if appropriate

    scan_dir = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
    md_file = os.path.join(scan_dir, 'vulnerability.md')
    output_pdf = os.path.join(scan_dir, f"scan_report_{scan_id}.pdf") # More descriptive name

    if not os.path.exists(scan_dir):
         flash(f"Scan directory not found for ID: {scan_id}")
         return redirect(url_for('scan_results', scan_id=scan_id)) # Redirect back to results

    if not os.path.exists(md_file):
        flash("Scan report (markdown file) not found. PDF cannot be generated yet.")
        return redirect(url_for('scan_results', scan_id=scan_id))

    try:
        print(f"[{scan_id}] Generating PDF from {md_file} to {output_pdf}")
        # Ensure pdf_writer_module can handle image paths correctly
        # It might need the base directory (scan_dir) to resolve relative image paths
        pdf_writer_module.writeToPDF(md_file, output_pdf, base_path=scan_dir) # Pass base_path if needed
        print(f"[{scan_id}] PDF generation complete.")

        # Check if PDF was actually created
        if not os.path.exists(output_pdf):
             print(f"[{scan_id}] PDF generation failed - file not found: {output_pdf}")
             flash("PDF generation failed. Please check server logs.")
             return redirect(url_for('scan_results', scan_id=scan_id))


        return send_file(
            output_pdf,
            as_attachment=True,
            download_name=f"Vulnerability_Report_{scan_id}.pdf", # User-friendly download name
            mimetype='application/pdf'
        )
    except Exception as e:
        print(f"[{scan_id}] Error during PDF generation or sending: {e}")
        traceback.print_exc()
        flash(f"An error occurred during PDF generation: {str(e)}")
        return redirect(url_for('scan_results', scan_id=scan_id))


def add_graphs_to_markdown(scan_id, scan_dir, md_file_path):
    """
    Generates graphs, checks for their existence, and appends CORRECT
    markdown image links (using hardcoded relative URLs) to the markdown file.
    """
    print(f"[{scan_id}] --- Attempting to generate graphs and update markdown ---")
    graph_section = "\n\n## Visual Summary\n\n"
    graphs_added = 0
    graphs_failed = []

    # Define expected graphs (relative filenames within the output directory)
    graph_files_relative = {
        "0_summary_findings.png": "Overall Findings Summary",
        "1_zap_risk_distribution.png": "ZAP Unique Alerts by Risk",
        "2_zap_alert_counts.png": "ZAP Top Alerts by Occurrence",
        "4_nmap_port_status.png": "Nmap Port Status Summary",
        "5_nikto_findings.png": "Nikto Findings by Category"
    }

    graph_output_dir = None # Initialize variable

    try:
        # --- Call the graph generation function ---
        # Corrected log message to match the actual call
        print(f"[{scan_id}] Calling generate_graphs.generate_all_graphs_for_scan(scan_id='{scan_id}')")
        # Call the function which should return the output path on success, None on failure
        # Renamed 'success' to 'graph_output_dir' for clarity
        graph_output_dir = generate_graphs.generate_all_graphs_for_scan(scan_id)

        # --- Check if graph generation succeeded (returned a path) ---
        if graph_output_dir:
            # Ensure the path returned is actually a directory (basic check)
            if not os.path.isdir(graph_output_dir):
                 print(f"[{scan_id}] Warning: Graph generation function returned a non-directory path: {graph_output_dir}")
                 graph_section += f"Graph generation script indicated success but returned an invalid path: `{graph_output_dir}`.\n\n"
                 graph_output_dir = None # Treat as failure
            else:
                 print(f"[{scan_id}] Graph generation function reported success. Output directory: {graph_output_dir}")
                 # --- Check which graphs were actually created and build markdown ---
                 for filename, title in graph_files_relative.items():
                     # --- FIX 1: Use the returned graph_output_dir to check for files ---
                     full_image_path = os.path.join(graph_output_dir, filename)
                     print(f"[{scan_id}]   - Checking for graph file at: {full_image_path}") # Added print for debugging path

                     if os.path.exists(full_image_path):
                         # --- FIX 2: Construct URL manually to avoid application context error ---
                         image_url = f"/scan_results/{scan_id}/{filename}"

                         graph_section += f"### {title}\n"
                         graph_section += f"![{title}]({image_url})\n\n" # Embed using the relative URL
                         graphs_added += 1
                         print(f"[{scan_id}]   - Found graph: {filename}. Added link: {image_url}")
                     else:
                         graphs_failed.append(filename)
                         print(f"[{scan_id}]   - Graph file not found (expected): {filename} in {graph_output_dir}")
                 graph_section += "---\n\n"
        else:
            # This block executes if generate_graphs.generate_all_graphs_for_scan returned None
            print(f"[{scan_id}] Graph generation function failed or was skipped (returned None).")
            graph_section += "Graph generation failed or was skipped (e.g., required input data not found or error during generation).\n\n"

    except Exception as e:
        print(f"[{scan_id}] Error during graph generation process: {e}")
        traceback.print_exc()
        graph_section += f"An error occurred while processing graph generation:\n```\n{traceback.format_exc()}\n```\n\n"
        # Ensure graph_output_dir is None if exception happened before assignment
        if graph_output_dir is None and 'graph_output_dir' not in locals():
             graph_output_dir = None # Explicitly set if needed

    # --- Append the graph section (or status message) to the main markdown file ---
    try:
        with open(md_file_path, 'a', encoding='utf-8') as f:
            if graphs_added > 0:
                 print(f"[{scan_id}] Appending {graphs_added} graph links to markdown.")
                 f.write(graph_section)
            elif graphs_failed:
                 print(f"[{scan_id}] Appending graph status: Some graphs failed.")
                 # Make sure graph_section contains the failure message from the 'else' block above
                 if "Graph generation failed" not in graph_section:
                      graph_section += "Graph generation completed, but some expected graphs were not created.\n\n" # Add context if needed
                 f.write(graph_section) # Append the section anyway
                 f.write(f"Note: The following expected graph files were not found: `{'`, `'.join(graphs_failed)}`\n\n")
                 f.write("---\n\n") # Add separator even on partial failure
            else:
                 # This case handles if graph_output_dir was None OR if it existed but contained none of the expected files
                 print(f"[{scan_id}] No graphs generated or found to add to markdown.")
                 # Append a placeholder section if graph_section hasn't already indicated failure
                 if "Visual Summary" not in graph_section:
                     graph_section += "\n\n## Visual Summary\n\n" # Ensure header exists
                 if "Graph generation failed" not in graph_section: # Avoid duplicating failure messages
                     graph_section += "No visual summary graphs were generated or found for this scan.\n\n"
                 graph_section += "---\n\n"
                 f.write(graph_section)


    except IOError as e:
        print(f"[{scan_id}] Error writing graph section to markdown file {md_file_path}: {e}")
        # Don't crash the whole process, just log the error

@app.route('/scan_results/<scan_id>/<path:filename>') # Use <path:filename> to handle potential subdirs if needed
def serve_scan_image(scan_id, filename):
    """Serves image files (and potentially other static assets) from the specific scan results directory"""
    # Validate scan_id format
    try:
        uuid.UUID(scan_id, version=4)
    except ValueError:
        print(f"Invalid scan_id format requested in serve_scan_image: {scan_id}")
        return "Invalid Scan ID", 400

    # Construct the absolute path to the directory for this scan
    # Use app.config['SCAN_RESULTS_DIR'] which should be absolute
    directory = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)

    # Basic security check: prevent directory traversal attacks
    # Ensure the resolved path is still within the intended base directory
    requested_path = os.path.join(directory, filename)
    if not os.path.abspath(requested_path).startswith(os.path.abspath(directory)):
        print(f"Forbidden path requested: {filename} for scan {scan_id}")
        return "Forbidden", 403

    print(f"Attempting to serve file: {filename} from directory: {directory}") # Debug print
    if not os.path.exists(directory):
        print(f"Directory not found: {directory}")
        return "Scan directory not found", 404

    # Use Flask's send_from_directory for security and proper header handling
    # It requires directory path and filename separately
    try:
        return send_from_directory(directory, filename)
    except FileNotFoundError:
        print(f"File not found within directory: {os.path.join(directory, filename)}")
        return "File not found", 404
    except Exception as e:
        print(f"Error serving file {filename} from {directory}: {e}")
        traceback.print_exc()
        return "Error serving file", 500


if __name__ == "__main__":
    # Recommended: Use Gunicorn or Waitress for production instead of Flask's built-in server
    print("Starting Flask development server...")
    print(f"Access at: http://127.0.0.1:5000 or http://<your-ip>:5000")
    app.run(host='0.0.0.0', port=5000, debug=True) # debug=True is helpful for development