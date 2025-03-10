from flask import Flask, render_template, request, redirect, url_for, flash
from scan import run_scan  # Import the run_scan function

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # required for flash messages

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domain = request.form.get("domain")
        if not domain:
            flash("Please enter a domain.")
            return redirect(url_for("index"))
        try:
            # Run the scan function with the provided domain
            report = run_scan(domain)
        except Exception as e:
            flash(f"An error occurred: {str(e)}")
            return redirect(url_for("index"))

        return render_template("report.html", domain=domain, report=report)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
