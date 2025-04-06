from flask import Flask, jsonify, render_template, request, redirect, url_for, flash
import uuid
import os
import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # required for flash messages
app.config['SCAN_RESULTS_DIR'] = 'scan_results'  # Directory to store scan results

# Ensure the scan results directory exists
os.makedirs(app.config['SCAN_RESULTS_DIR'], exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def index():
    scan_id = request.args.get('scan_id')
    
    if request.method == "POST":
        domain = request.form.get("domain")
        if not domain:
            flash("Please enter a domain.")
            return redirect(url_for("index"))
        try:
            # Generate a unique scan ID
            scan_id = str(uuid.uuid4())
            print(f"Generated new scan ID: {scan_id}")
            
            # Create directory for this scan
            scan_dir = os.path.join(app.config['SCAN_RESULTS_DIR'], scan_id)
            os.makedirs(scan_dir, exist_ok=True)
            
            # Initialize the markdown file for this scan
            with open(os.path.join(scan_dir, 'vulnerability.md'), 'w') as f:
                f.write(f"# Scan Results for {domain}\n\n")
                f.write(f"Scan started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write("Waiting for results...\n\n")
            
            # Run the scan and AI analysis
            send_to_AI(scan_id)
            
            # Redirect back to index with scan_id in URL
            return redirect(url_for('index', scan_id=scan_id))
        except Exception as e:
            flash(f"An error occurred: {str(e)}")
            return redirect(url_for("index"))
    
    # For GET requests, render the template with scan_id if available
    return render_template("index.html", scan_id=scan_id)

def send_to_AI(scan_id):
    try:
        print(f"Starting AI analysis with scan ID: {scan_id}")
        chat.test_alert_items(xml_file_path="scan-report.xml", scan_id=scan_id)
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
            markdown_content = f"# Scan {scan_id}\n\nNo results available for this scan yet. Please wait..."
        
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
    
    for vuln_name, vuln_details in vulnerability_data.items():
        markdown += f"## {vuln_name}\n\n"
        
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
        
        markdown += "---\n\n"
    
    return markdown

if __name__ == "__main__":
    app.run(debug=True)