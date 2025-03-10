import markdown
from weasyprint import HTML

class MarkdownReport:
    def __init__(self, markdown_text, output_md="vulnerability_report.md", output_pdf="vulnerability_report.pdf", title="Vulnerability Analysis Report"):
        self.markdown_text = markdown_text
        self.output_md = output_md
        self.output_pdf = output_pdf
        self.title = title

    def save_md(self):
        """Save the raw Markdown to a file."""
        with open(self.output_md, "w", encoding="utf-8") as f:
            f.write(self.markdown_text)
        print(f"Markdown report saved as {self.output_md}")

    def convert_to_pdf(self):
        """Convert the Markdown text to HTML and then generate a PDF."""
        # Convert the Markdown to HTML
        html_body = markdown.markdown(self.markdown_text, output_format="html5")
        # Wrap the HTML in a full document with styling
        html_document = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{self.title}</title>
    <style>
        body {{
            font-family: sans-serif;
            margin: 40px;
            line-height: 1.6;
            color: #333;
        }}
        h1, h2, h3, h4, h5, h6 {{
            color: #2F4F4F;
        }}
        pre, code {{
            background-color: #f4f4f4;
            padding: 4px;
            border-radius: 4px;
        }}
        ul, ol {{
            margin-left: 20px;
        }}
    </style>
</head>
<body>
{html_body}
</body>
</html>
"""
        HTML(string=html_document).write_pdf(self.output_pdf)
        print(f"PDF report generated as {self.output_pdf}")

if __name__ == "__main__":
    # This is the raw Markdown response from your AI
    raw_md = """
1. **Issue Explanation:**

   The vulnerability alert indicates that the web/application server is leaking information via the "X-Powered-By" HTTP response header field(s). This header is used by web servers to indicate which software framework or server is being used. However, disclosing this information can be a security risk.

   Attackers can use this information to identify other frameworks or components that the web application is reliant upon and search for known vulnerabilities associated with those components. This can aid in crafting targeted attacks against the application.

2. **Impact Analysis:**

   The potential risks and security impact if this vulnerability is exploited include:
   - Increased Attack Surface: Disclosing the technology stack can provide attackers with more information about the application, increasing the attack surface.
   - Targeted Attacks: Attackers can focus their efforts on known vulnerabilities associated with the disclosed frameworks or components.
   - Easier Exploitation: Attackers can use the disclosed information to tailor their attacks more effectively, potentially bypassing security measures.

   This vulnerability can lead to unauthorized access, data breaches, and system compromise.

3. **Exploitation Details:**

   An attacker might exploit this vulnerability by using the disclosed information to search for known vulnerabilities in the identified frameworks or components. They could then attempt to exploit these vulnerabilities to gain unauthorized access or compromise the application.

4. **Step-by-Step Remediation:**

   To mitigate or resolve the issue, follow these steps:

   1. **Identify the HTTP Response Headers:**
      - Identify which HTTP response headers are being sent by the web server.

   2. **Suppress "X-Powered-By" Headers:**
      - Configure the web server to remove or suppress the "X-Powered-By" header.
      - Use server-specific configuration options or web server modules to achieve this.

   3. **Review Other Headers:**
      - Review other response headers to ensure no sensitive information is being leaked.

   4. **Implement a Custom Header:**
      - If necessary, implement a custom header that does not disclose sensitive information.

   5. **Regularly Update and Patch:**
      - Keep the web server software up to date with the latest security patches.

   6. **Use HTTPS:**
      - Ensure that the application uses HTTPS to encrypt the entire communication, reducing the risk of information leakage.

5. **References & Best Practices:**

   - OWASP Top 10: https://owasp.org/www-project-top-ten/
   - OWASP HTTP Header Cheat Sheet: https://www.owasp.org/index.php/HTTP_Headers_Cheat_Sheet
   - NIST SP 800-53: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53.pdf

6. **Risk Score:**

   The risk score for this vulnerability would be rated as medium, with a score of 5 out of 10. While the disclosure of the technology stack can aid attackers, it is not as severe as other vulnerabilities like SQL Injection or Cross-Site Scripting (XSS). However, it should still be addressed to reduce the attack surface and improve the overall security posture of the application.
"""
    # Create a report instance with the raw Markdown response.
    report = MarkdownReport(raw_md, output_md="vulnerability_report.md", output_pdf="vulnerability_report.pdf", title="Vulnerability Analysis Report")
    report.save_md()
    report.convert_to_pdf()
