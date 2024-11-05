import json
from jinja2 import Environment, FileSystemLoader
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime
from reportlab.lib.colors import HexColor

# Generate JSON report
def generate_json_report(vulnerabilities, output_file='report.json'):
    with open(output_file, 'w') as f:
        json.dump(vulnerabilities, f, indent=4)
    print(f"JSON report generated: {output_file}")

# Generate HTML report using Jinja2
def generate_html_report(vulnerabilities, output_file='report.html'):
    env = Environment(loader=FileSystemLoader(searchpath="./"))
    template = env.get_template("report_template.html")  # Ensure this template file exists
    
    html_content = template.render(vulnerabilities=vulnerabilities)
    
    with open(output_file, 'w') as f:
        f.write(html_content)

    print(f"HTML report generated: {output_file}")

# Generate PDF report using ReportLab
# def generate_pdf_report(vulnerabilities, output_file='report.pdf'):
#     c = canvas.Canvas(output_file, pagesize=letter)
#     width, height = letter

#     c.setFont("Helvetica", 12)
#     c.drawString(100, height - 100, "Static Code Analysis Report")

#     y = height - 150
#     for vulnerability in vulnerabilities:
#         c.drawString(100, y, f"File: {vulnerability['file']}")
#         c.drawString(100, y - 20, f"Line: {vulnerability['line']}")
#         c.drawString(100, y - 40, f"Vulnerability: {vulnerability['vulnerability']}")
#         c.drawString(100, y - 60, f"CWE ID: {vulnerability.get('cwe_id', 'N/A')}")
#         c.drawString(100, y - 80, f"Severity: {vulnerability['severity']}")
#         c.drawString(100, y - 100, f"Description: {vulnerability['description']}")
#         c.drawString(100, y - 120, f"Remediation: {vulnerability['remediation']}")
#         y -= 160

#         # Start new page if content exceeds page height
#         if y < 100:
#             c.showPage()
#             y = height - 150

#     else:
#         print(f"Unexpected vulnerability format: {vulnerability}")


#     c.save()
#     print(f"PDF report generated: {output_file}")


def generate_pdf_report(vulnerabilities):
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"report_{current_time}.pdf"
    
    c = canvas.Canvas(output_file, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica", 12)
    c.drawString(100, height - 100, "Static Code Analysis Report")

    y = height - 150
    for vulnerability in vulnerabilities:
        if isinstance(vulnerability, dict):  # Ensure it's a dictionary
            # Determine color based on severity
            severity = vulnerability.get('severity', 'N/A')
            if severity == 'Critical':
                c.setFillColor(HexColor('#8B0000'))  # Dark Red
            elif severity == 'High':
                c.setFillColor(HexColor('#FF0000'))  # Red
            elif severity == 'Medium':
                c.setFillColor(HexColor('#FFA500'))  # Orange
            elif severity == 'Low':
                c.setFillColor(HexColor('#00C04B'))  # Green
            else:
                c.setFillColor(HexColor('#000000'))  # Default to black for unknown severity

            # Draw the vulnerability details
            c.drawString(100, y, f"File: {vulnerability.get('file', 'N/A')}")
            c.drawString(100, y - 20, f"Line: {vulnerability.get('line', 'N/A')}")
            c.drawString(100, y - 40, f"Vulnerability: {vulnerability.get('vulnerability', 'N/A')}")
            c.drawString(100, y - 60, f"CWE ID: {vulnerability.get('cwe_id', 'N/A')}")
            c.drawString(100, y - 80, f"Severity: {vulnerability.get('severity', 'N/A')}")
            c.drawString(100, y - 100, f"Description: {vulnerability.get('description', 'N/A')}")
            c.drawString(100, y - 120, f"Remediation: {vulnerability.get('remediation', 'N/A')}")
            y -= 160

            # Start new page if content exceeds page height
            if y < 100:
                c.showPage()
                y = height - 150
        else:
            print(f"Unexpected vulnerability format: {vulnerability}")

    c.save()
    print(f"PDF report generated: {output_file}")