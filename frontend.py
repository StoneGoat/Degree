from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, send_file
from AI import chat
import scan
import uuid
import os
import datetime
import pdf_writer_module
import generate_graphs
from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, send_from_directory

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # required for flash messages
app.config['SCAN_RESULTS_DIR'] = 'scan_results'  # Directory to store scan results

# Ensure the scan results directory exists
os.makedirs(app.config['SCAN_RESULTS_DIR'], exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domain = request.form.get("domain")
        level = request.form.get("level")

        if level == "Manager":
            level = 0
        elif level == "Developer":
            level = 1
        elif level == "CyberSec":
            level = 2

        if not domain:
            flash("Please enter a domain.")
            return redirect(url_for("index"))
        try:
            # Generate a unique scan ID
            scan_id = str(uuid.uuid4())
            # scan_id = "6c303744-b134-4ffb-82fa-cada0b9bc074"

            print(f"Generated new scan ID: {scan_id}")
            
            # Create directory for this scan
            scan_dir = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
            os.makedirs(scan_dir, exist_ok=True)
            
            # Initialize the markdown file with minimal content
            with open(os.path.join(scan_dir, 'vulnerability.md'), 'w') as f:
                f.write(f"# Scan Results for {domain}\n\n")
                f.write(f"Scan started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write("Initializing scan... Please wait while we analyze the target.\n\n")
            
            # Redirect to results page immediately
            response = redirect(url_for('scan_results', scan_id=scan_id, domain=domain))
            
            # Start the scan process in a background thread to avoid blocking
            import threading
            scan_thread = threading.Thread(target=run_scan_process, args=(scan_id, domain, level))
            scan_thread.daemon = True
            scan_thread.start()
            
            return response
            
        except Exception as e:
            flash(f"An error occurred: {str(e)}")
            return redirect(url_for("index"))
    
    # For GET requests, just show the index page
    return render_template("index.html")

def run_scan_process(scan_id, domain, level):
    """Run the scan in a separate thread"""
    try:
        print(f"Starting scan process for {domain} with ID {scan_id}")
        
        # Add a note to the markdown file that scanning has begun
        scan_dir = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
        with open(os.path.join(scan_dir, 'vulnerability.md'), 'a') as f:
            f.write("\n## Scanning in progress\n\n")
            f.write("The scan is now running. Results will appear here as they are processed.\n\n")
        
        scan.run_scan(domain, scan_id)

        add_graphs_to_markdown(scan_id=scan_id, scan_dir=scan_dir)

        send_to_AI(scan_id, level)
        
        with open(os.path.join(scan_dir, 'vulnerability.md'), 'a') as f:
            f.write("\n## Scan Complete\n\n")
            f.write(f"Scan completed at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
    except Exception as e:
        print(f"Error in scan process: {str(e)}")
        import traceback
        traceback.print_exc()
        
        # Record error in markdown
        try:
            with open(os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id, 'vulnerability.md'), 'a') as f:
                f.write("\n## Error During Scan\n\n")
                f.write(f"An error occurred: {str(e)}\n\n")
        except:
            pass

@app.route("/results")
def scan_results():
    """Dedicated page for viewing scan results"""
    scan_id = request.args.get('scan_id')
    domain = request.args.get('domain', 'Unknown Domain')
    
    if not scan_id:
        flash("No scan ID provided.")
        return redirect(url_for("index"))
    
    return render_template("results.html", scan_id=scan_id, domain=domain)

def send_to_AI(scan_id, level):
    try:
        print(f"Starting AI analysis with scan ID: {scan_id}")
        chat.run_AI(xml_file_path=f"scan-report{scan_id}.xml", scan_id=scan_id, level=level)
        print(f"AI analysis completed for scan: {scan_id}")
    except Exception as e:
        print(f"Error in send_to_AI: {str(e)}")
        import traceback
        traceback.print_exc()

@app.route("/get_markdown")
def get_markdown():
    """Returns markdown for a specific scan ID"""
    scan_id = request.args.get('scan_id')
    
    if not scan_id:
        return jsonify({"markdown": "No scan ID provided"})
    
    try:
        # Get markdown content for this scan
        markdown_path = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id, 'vulnerability.md')
        
        try:
            with open(markdown_path, 'r') as f:
                markdown_content = f.read()
        except FileNotFoundError:
            markdown_content = f"# Scan {scan_id}\n\nInitializing scan... Please wait."
        
        return jsonify({"markdown": markdown_content})
    
    except Exception as e:
        return jsonify({"error": str(e), "markdown": "Error loading markdown content."}), 500

@app.route("/update", methods=["POST"])
def update_results():
    try:
        # Get data from the request
        vulnerability_data = request.get_json()
        
        if not vulnerability_data:
            return jsonify({"error": "No data provided"}), 400
        
        # Get scan ID from query parameter
        scan_id = request.args.get('scan_id')
        
        if not scan_id:
            return jsonify({"error": "No scan ID provided"}), 400
        
        print(f"\n\n\n\n New Results for scan {scan_id}: \n")
        print(vulnerability_data)
        print("\n\n\n\n")
        
        # Convert the vulnerability data to Markdown format
        markdown = convert_to_markdown(vulnerability_data)
        
        # Save the markdown to the scan-specific file
        scan_dir = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
        os.makedirs(scan_dir, exist_ok=True)
        
        with open(os.path.join(scan_dir, 'vulnerability.md'), 'a') as f:
            f.write(markdown)
        
        return jsonify({
            "status": "success", 
            "message": f"Results received and converted to markdown for scan {scan_id}"
        })
    
    except Exception as e:
        print(f"Error processing request: {str(e)}")
        return jsonify({"error": str(e)}), 500

def convert_to_markdown(vulnerability_data):
    """Converts vulnerability data to markdown format"""
    markdown = ""
    
    # If it's a single overview (like from Nmap)
    if len(vulnerability_data) == 1 and 'overview' in vulnerability_data:
        return vulnerability_data['overview']
    
    # If it's a dictionary of vulnerabilities (like from ZAP)
    for vuln_name, vuln_details in vulnerability_data.items():
        markdown += f"## {vuln_name}\n\n"
        
        if isinstance(vuln_details, dict):
            if "issue" in vuln_details:
                markdown += f"### Issue Explanation\n{vuln_details['issue']}\n\n"
            
            if "impact" in vuln_details:
                markdown += f"### Impact Analysis\n{vuln_details['impact']}\n\n"
            
            if "exploit" in vuln_details:
                markdown += f"### Exploitation Details\n{vuln_details['exploit']}\n\n"
            
            if "solution" in vuln_details:
                markdown += f"### Step-by-Step Remediation\n{vuln_details['solution']}\n\n"
            
            if "reference" in vuln_details:
                markdown += f"### References & Best Practices\n{vuln_details['reference']}\n\n"
        else:
            # Fallback for simple string or other types
            markdown += f"{vuln_details}\n\n"
        
        markdown += "---\n\n"
    
    return markdown

@app.route("/download_pdf/<scan_id>")
def download_pdf(scan_id):
    scan_dir = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
    md_file = os.path.join(scan_dir, 'vulnerability.md')

    if not os.path.exists(md_file):
        flash("PDF not ready yet – markdown missing.")
        return redirect(url_for('scan_results', scan_id=scan_id))

    output_pdf = os.path.join(scan_dir, f"{scan_id}.pdf")
    
    pdf_writer_module.writeToPDF(md_file, output_pdf)

    return send_file(
        output_pdf,
        as_attachment=True,
        download_name=f"scan_{scan_id}.pdf",
        mimetype='application/pdf'
    )


def add_graphs_to_markdown(scan_id, scan_dir):
    """Generates graphs and appends them to the markdown report."""
    print(f"--- Attempting to generate graphs and update markdown for scan {scan_id} ---")
    markdown_path = os.path.join(scan_dir, 'vulnerability.md')
    graph_section = "\n\n## Visual Summary\n\n"
    graphs_added = 0

    try:
        # Call the function from generate_graphs.py
        # It handles finding the XML and saving graphs inside scan_results/{scan_id}/
        graph_output_dir = generate_graphs.generate_all_graphs_for_scan(scan_id)

        if graph_output_dir:
            # Define expected graph filenames (relative to output_dir)
            graph_files = {
                "0_summary_findings.png": "Overall Findings Summary",
                "1_zap_risk_distribution.png": "ZAP Unique Alerts by Risk",
                "2_zap_alert_counts.png": "ZAP Top Alerts by Occurrence",
                "4_nmap_port_status.png": "Nmap Port Status Summary",
                "5_nikto_findings.png": "Nikto Findings by Category"
            }

            for filename, title in graph_files.items():
                # Check if the file actually exists in the expected output directory
                full_image_path = os.path.join(graph_output_dir, filename)
                if os.path.exists(full_image_path):
                    # Use relative path (just filename) for markdown embedding
                    # Assumes images served relative to the scan directory context
                    graph_section += f"### {title}\n"
                    graph_section += f"![{title}]({filename})\n\n" # Embed using relative path
                    graphs_added += 1
                else:
                    print(f"  - Graph file not found, skipping: {filename}")
            graph_section += "---\n\n"
        else:
            graph_section += "Graph generation failed or skipped (e.g., input XML not found).\n\n"

    except Exception as e:
        print(f"Error during graph generation or markdown update for scan {scan_id}: {e}")
        graph_section += f"An error occurred while generating graphs: {e}\n\n"

    # Append the graph section to the markdown file
    try:
        with open(markdown_path, 'a', encoding='utf-8') as f: # Add encoding
            if graphs_added > 0:
                 print(f"  - Adding {graphs_added} graphs to markdown.")
                 f.write(graph_section)
            else:
                 print("  - No graphs generated or found to add to markdown.")
                 f.write("\n\n## Visual Summary\n\nNo visual summary graphs were generated for this scan.\n\n")

    except Exception as e:
        print(f"Error writing graphs to markdown file {markdown_path}: {e}")

@app.route('/scan_results/<scan_id>/<filename>')
def serve_scan_image(scan_id, filename):
    """Serves image files from the specific scan results directory"""
    # Construct the directory path relative to the app's root
    # Make sure SCAN_RESULTS_DIR is correctly configured (relative or absolute)
    directory = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
    print(f"Attempting to serve image: {filename} from directory: {directory}") # Debug print
    try:
        # Use Flask's send_from_directory for security
        return send_from_directory(directory, filename)
    except FileNotFoundError:
         print(f"Image not found: {os.path.join(directory, filename)}")
         return "File not found", 404
    except Exception as e:
        print(f"Error serving file {filename} from {directory}: {e}")
        return "Error serving file", 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)