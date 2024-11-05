import argparse
from utils.zip_handler import extract_zip, get_all_files
from analyzers.python_analyzer import PythonAnalyzer
from analyzers.js_analyzer import JavaScriptAnalyzer
from analyzers.java_analyzer import JavaAnalyzer
from utils.report_generator import generate_json_report, generate_html_report, generate_pdf_report
from datetime import datetime

def main():
    # Command-line argument parser
    parser = argparse.ArgumentParser(description="Static Code Analysis Tool")
    parser.add_argument('zip_file', type=str, help="Path to the zip file containing the code")
    parser.add_argument('--output_format', type=str, choices=['json', 'html', 'pdf'], default='json', help="Report output format: json, html, or pdf")
    parser.add_argument('--depth', type=str, default='quick', help="Scan depth: quick or deep (not implemented in this example)")
    args = parser.parse_args()

    # Step 1: Extract the zip file
    extracted_dir = extract_zip(args.zip_file)

    # Step 2: Get all files in the extracted directory
    all_files = get_all_files(extracted_dir)

    vulnerabilities = []
    # Step 3: Analyze files by their extensions
    # for file_path in all_files:
    #     with open(file_path, 'r') as f:
    #         content = f.read().decode('utf-8')
    #         if file_path.endswith('.py'):
    #             analyzer = PythonAnalyzer()
    #             analyzer.analyze(content, file_path)
    #             vulnerabilities.extend(analyzer.vulnerabilities)
    #         elif file_path.endswith('.js'):
    #             analyzer = JavaScriptAnalyzer()
    #             analyzer.analyze(content, file_path)
    #             vulnerabilities.extend(analyzer.vulnerabilities)
    #         elif file_path.endswith('.java'):
    #             analyzer = JavaAnalyzer()
    #             analyzer.analyze(content, file_path)
    #             vulnerabilities.extend(analyzer.vulnerabilities)

    for file_path in all_files:
        with open(file_path, 'rb') as f:
            content = f.read().decode('utf-8', errors='ignore')
            if file_path.endswith('.py'):
                analyzer = PythonAnalyzer()
                analyzer.analyze(content, file_path)
                vulnerabilities.extend(analyzer.vulnerabilities)
            elif file_path.endswith('.js'):
                analyzer = JavaScriptAnalyzer()
                analyzer.analyze(content, file_path)
                vulnerabilities.extend(analyzer.vulnerabilities)
            elif file_path.endswith('.java'):
                analyzer = JavaAnalyzer()
                analyzer.analyze(content, file_path)
                vulnerabilities.extend(analyzer.vulnerabilities)

    # Get the current date and time for the report filename
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")


    # Step 4: Generate report based on user-specified output format
#     if args.output_format == 'json':
#         generate_json_report(vulnerabilities)
#     elif args.output_format == 'html':
#         generate_html_report(vulnerabilities)
#     elif args.output_format == 'pdf':
#         generate_html_report(vulnerabilities)  # HTML is required for PDF conversion
#         generate_pdf_report()

# if __name__ == "__main__":
#     main()


    if args.output_format == 'json':
        report_filename = f"report_{current_time}.json"
        generate_json_report(vulnerabilities, report_filename)
    elif args.output_format == 'html':
        report_filename = f"report_{current_time}.html"
        generate_html_report(vulnerabilities, report_filename)
    elif args.output_format == 'pdf':
        # html_report_filename = f"report_{current_time}.html"
        # generate_html_report(vulnerabilities, html_report_filename)  # Generate HTML first
        pdf_report_filename = f"report_{current_time}.pdf"
        generate_pdf_report(vulnerabilities)

if __name__ == "__main__":
    main()
