# import ast
# from cwe_mapping import CWE_DATABASE

# class PythonAnalyzer:
#     def __init__(self):
#         self.vulnerabilities = []

#     def analyze(self, file_content, file_name):
#         try:
#             tree = ast.parse(file_content)
#             self.visit(tree, file_name)
#         except SyntaxError as e:
#             print(f"SyntaxError in {file_name}: {e}")

#     def visit(self, node, file_name):
#         for child in ast.walk(node):
#             if isinstance(child, ast.Call) and hasattr(child.func, 'id') and child.func.id == 'eval':
#                 cwe_info = CWE_DATABASE['Insecure eval() function']
#                 self.vulnerabilities.append({
#                     "file": file_name,
#                     "line": child.lineno,
#                     "vulnerability": "Insecure eval() function",
#                     "cwe_id": cwe_info['cwe_id'],
#                     "description": cwe_info['description'],
#                     "severity": cwe_info['severity'],
#                     "remediation": cwe_info['remediation']
#                 })


import ast
import re
from cwe_mapping import CWE_DATABASE

class PythonAnalyzer:
    def __init__(self):
        self.vulnerabilities = []

    def analyze(self, file_content, file_name):
        try:
            tree = ast.parse(file_content)
            self.visit(tree, file_name)
        except SyntaxError as e:
            print(f"SyntaxError in {file_name}: {e}")





    def visit(self, node, file_name):
        for child in ast.walk(node):
            self.check_eval(child, file_name)
            self.check_path_traversal(child, file_name)
            self.check_hardcoded_credentials(child, file_name)
            self.check_server_info_exposure(child, file_name)
            self.check_debug_mode(child, file_name)
            self.check_input_validation(child, file_name)
            self.check_auth_flaws(child, file_name)
            self.check_data_encryption(child, file_name)
            self.check_exception_handling(child, file_name)
            self.check_dependency_management(child, file_name)
            self.check_api_usage(child, file_name)
            self.check_csrf_protection(child, file_name)
            self.check_server_side_execution(child, file_name)
            self.check_business_logic_errors(child, file_name)
            self.check_code_quality(child, file_name)
            self.check_insecure_crypto(child, file_name)

    def check_eval(self, child, file_name):
        if isinstance(child, ast.Call) and hasattr(child.func, 'id') and child.func.id == 'eval':
            cwe_info = CWE_DATABASE['Insecure eval() function']
            self.vulnerabilities.append({
                "file": file_name,
                "line": child.lineno,
                "vulnerability": "Insecure eval() function",
                "cwe_id": cwe_info['cwe_id'],
                "description": cwe_info['description'],
                "severity": cwe_info['severity'],
                "remediation": cwe_info['remediation']
            })

    # def check_path_traversal(self, child, file_name):
    #     # Check for open() with variable file paths
    #     if isinstance(child, ast.Call) and hasattr(child.func, 'id') and child.func.id == 'open':
    #         if any(isinstance(arg, ast.Name) for arg in child.args):
    #             cwe_info = CWE_DATABASE['Path Traversal']
    #             self.vulnerabilities.append({
    #                 "file": file_name,
    #                 "line": child.lineno,
    #                 "vulnerability": "Path Traversal",
    #                 "cwe_id": cwe_info['cwe_id'],
    #                 "description": cwe_info['description'],
    #                 "severity": cwe_info['severity'],
    #                 "remediation": cwe_info['remediation']
    #             })

    # //////////////////////

    def check_path_traversal(self, child, file_name):
    # Check for open() with variable file paths
        if isinstance(child, ast.Call) and hasattr(child.func, 'id') and child.func.id == 'open':
            if any(isinstance(arg, ast.Name) for arg in child.args):
                if 'Path Traversal' in CWE_DATABASE:
                    cwe_info = CWE_DATABASE['Path Traversal']
                    self.vulnerabilities.append({
                        "file": file_name,
                        "line": child.lineno,
                        "vulnerability": "Path Traversal",
                        "cwe_id": cwe_info['cwe_id'],
                        "description": cwe_info['description'],
                        "severity": cwe_info['severity'],
                        "remediation": cwe_info['remediation']
                    })
                else:
                    print("CWE entry for 'Path Traversal' not found.")


# ////////////////////// old


    # def check_hardcoded_credentials(self, child, file_name):
    #     # Look for strings that resemble credentials
    #     if isinstance(child, ast.Assign):
    #         for target in child.targets:
    #             if isinstance(target, ast.Name) and any(sub in child.value.s for sub in ['password', 'secret', 'apikey']):
    #                 cwe_info = CWE_DATABASE['Hardcoded Credentials']
    #                 self.vulnerabilities.append({
    #                     "file": file_name,
    #                     "line": child.lineno,
    #                     "vulnerability": "Hardcoded Credentials",
    #                     "cwe_id": cwe_info['cwe_id'],
    #                     "description": cwe_info['description'],
    #                     "severity": cwe_info['severity'],
    #                     "remediation": cwe_info['remediation']
    #                 })


    # ///////////////////////// another old


    def check_hardcoded_credentials(self, node, file_name):
        sensitive_keywords = ['user', 'username', 'password', 'credentials', 'database', 'host']
        
        # Debugging output to confirm node types are processed
        print(f"Processing node type: {type(node).__name__} on line {getattr(node, 'lineno', 'unknown')}")

        # Helper to add vulnerabilities with CWE details
        def add_vulnerability(line_number, vulnerability, line_content=None):
            cwe_info = CWE_DATABASE.get('Hardcoded Credentials', None)
            if cwe_info:
                self.vulnerabilities.append({
                    "file": file_name,
                    "line": line_number,
                    "vulnerability": vulnerability,
                    "cwe_id": cwe_info['cwe_id'],
                    "description": cwe_info['description'],
                    "severity": cwe_info['severity'],
                    "remediation": cwe_info['remediation'],
                    "line_content": line_content.strip() if line_content else None
                })
                print(f"Vulnerability added: {vulnerability} at line {line_number}")

        # Check for hardcoded credentials in assignments
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, (ast.Name, ast.Attribute)) and isinstance(node.value, ast.Str):
                    # Check if the assigned string contains sensitive information
                    if any(keyword in node.value.s.lower() for keyword in sensitive_keywords):
                        add_vulnerability(node.lineno, "Hardcoded Credentials in assignment", node.value.s)

        # Check for hardcoded credentials in function calls (e.g., pymysql.connect)
        elif isinstance(node, ast.Call):
            if hasattr(node.func, 'attr') and node.func.attr == 'connect':
                for keyword in node.keywords:
                    if isinstance(keyword, ast.keyword) and isinstance(keyword.value, ast.Str):
                        if keyword.arg.lower() in sensitive_keywords:
                            add_vulnerability(node.lineno, f"Hardcoded Credentials in {keyword.arg}", keyword.value.s)
                            print(f"Detected hardcoded credential in function call at line {node.lineno}")

        # General search for hardcoded credentials in any string literals
        for child in ast.walk(node):
            if isinstance(child, ast.Str) and any(keyword in child.s.lower() for keyword in sensitive_keywords):
                add_vulnerability(child.lineno, "Hardcoded Credentials in general string", child.s)
                print(f"Detected hardcoded credential in general string at line {child.lineno}")


    # ///////////////////////

    # def check_server_info_exposure(self, child, file_name):
    #     # Check for exposed server info, like version numbers
    #     if isinstance(child, ast.Assign) and 'VERSION' in child.targets[0].id:
    #         cwe_info = CWE_DATABASE['Server Information Exposure']
    #         self.vulnerabilities.append({
    #             "file": file_name,
    #             "line": child.lineno,
    #             "vulnerability": "Server Information Exposure",
    #             "cwe_id": cwe_info['cwe_id'],
    #             "description": cwe_info['description'],
    #             "severity": cwe_info['severity'],
    #             "remediation": cwe_info['remediation']
    #         })

    # ////////////////////////
    def check_server_info_exposure(self, child, file_name):
    # Check for exposed server info, like version numbers
        if isinstance(child, ast.Assign):
            for target in child.targets:
                if isinstance(target, ast.Name) and target.id == 'VERSION':
                    cwe_info = CWE_DATABASE['Server Information Exposure']
                    self.vulnerabilities.append({
                        "file": file_name,
                        "line": child.lineno,
                        "vulnerability": "Server Information Exposure",
                        "cwe_id": cwe_info['cwe_id'],
                        "description": cwe_info['description'],
                        "severity": cwe_info['severity'],
                        "remediation": cwe_info['remediation']
                    })
                elif isinstance(target, ast.Attribute) and target.attr == 'VERSION':
                    cwe_info = CWE_DATABASE['Server Information Exposure']
                    self.vulnerabilities.append({
                        "file": file_name,
                        "line": child.lineno,
                        "vulnerability": "Server Information Exposure",
                        "cwe_id": cwe_info['cwe_id'],
                        "description": cwe_info['description'],
                        "severity": cwe_info['severity'],
                        "remediation": cwe_info['remediation']
                    })
# /////////////////////

    def check_debug_mode(self, child, file_name):
        # Check for debug mode enabled (e.g., app.run(debug=True))
        if isinstance(child, ast.Call) and hasattr(child.func, 'id') and child.func.id == 'run':
            for keyword in child.keywords:
                if keyword.arg == 'debug' and keyword.value:
                    cwe_info = CWE_DATABASE['Debug Mode Enabled']
                    self.vulnerabilities.append({
                        "file": file_name,
                        "line": child.lineno,
                        "vulnerability": "Debug Mode Enabled",
                        "cwe_id": cwe_info['cwe_id'],
                        "description": cwe_info['description'],
                        "severity": cwe_info['severity'],
                        "remediation": cwe_info['remediation']
                    })

    def check_input_validation(self, child, file_name):
        # Check for lack of input validation (e.g., directly using input())
        if isinstance(child, ast.Call) and hasattr(child.func, 'id') and child.func.id == 'input':
            cwe_info = CWE_DATABASE['Input Validation Issues']
            self.vulnerabilities.append({
                "file": file_name,
                "line": child.lineno,
                "vulnerability": "Input Validation Issues",
                "cwe_id": cwe_info['cwe_id'],
                "description": cwe_info['description'],
                "severity": cwe_info['severity'],
                "remediation": cwe_info['remediation']
            })

    def check_auth_flaws(self, child, file_name):
        # Placeholder for authentication flaws detection
        pass  # Implement checks based on your criteria

    def check_data_encryption(self, child, file_name):
        # Placeholder for checking data encryption
        pass  # Implement checks based on your criteria

    def check_exception_handling(self, child, file_name):
        # Check for lack of exception handling
        if isinstance(child, ast.Try):
            if not child.handlers:
                cwe_info = CWE_DATABASE['Improper Exception Handling']
                self.vulnerabilities.append({
                    "file": file_name,
                    "line": child.lineno,
                    "vulnerability": "Improper Exception Handling",
                    "cwe_id": cwe_info['cwe_id'],
                    "description": cwe_info['description'],
                    "severity": cwe_info['severity'],
                    "remediation": cwe_info['remediation']
                })

    def check_dependency_management(self, child, file_name):
        # Check for missing requirements.txt or similar
        pass  # Implement checks based on your criteria

    def check_api_usage(self, child, file_name):
        # Placeholder for checking API usage
        pass  # Implement checks based on your criteria

    def check_csrf_protection(self, child, file_name):
        # Placeholder for CSRF protection checks
        pass  # Implement checks based on your criteria

    def check_server_side_execution(self, child, file_name):
        # Check for server-side code execution
        pass  # Implement checks based on your criteria

    def check_business_logic_errors(self, child, file_name):
        # Check for potential business logic errors
        pass  # Implement checks based on your criteria

    def check_code_quality(self, child, file_name):
        # Check for poor coding practices (e.g., long functions)
        pass  # Implement checks based on your criteria

    def check_insecure_crypto(self, child, file_name):
        # Check for insecure cryptographic practices
        pass  # Implement checks based on your criteria
