
# ///////////// very old //////////////

# from slimit.parser import Parser
# from slimit.visitors import nodevisitor
# from slimit import ast as js_ast
# from cwe_mapping import CWE_DATABASE


# class JavaScriptAnalyzer:
#     def __init__(self):
#         self.vulnerabilities = []

#     def analyze(self, file_content, file_name):
#         parser = Parser()
#         try:
#             tree = parser.parse(file_content)
#             self.visit(tree, file_name)
#         except:
#             print(f"Failed to parse {file_name}")

#     def visit(self, node, file_name):
#         for child in nodevisitor.visit(node):
#             if isinstance(child, js_ast.CallExpression) and isinstance(child.identifier, js_ast.Identifier) and child.identifier.value == 'eval':
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


# /////////////// alternative old /////////////////
# import rjsmin
# import js_ast
# from cwe_mapping import CWE_DATABASE

# class JavaScriptAnalyzer:
#     def __init__(self):
#         self.vulnerabilities = []

#     def analyze(self, file_content, file_name):
#         minified_js = rjsmin.jsmin(file_content)
#         parser = esprima.Parser()
#         try:
#             tree = parser.parseScript(minified_js)
#             self.visit(tree, file_name)
#         except:
#             print(f"Failed to parse {file_name}")

#     def visit(self, node, file_name):
#         for child in nodevisitor.visit(node):
#             if isinstance(child, js_ast.CallExpression) and isinstance(child.identifier, js_ast.Identifier) and child.identifier.value == 'eval':
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


# //////////////////////// another alternative ////////////////////

import esprima
from cwe_mapping import CWE_DATABASE

class JavaScriptAnalyzer:
    def __init__(self):
        self.vulnerabilities = []

    def analyze(self, file_content, file_name):
        try:
            tree = esprima.parseScript(file_content, loc=True)
            self.visit(tree, file_name)
        except Exception as e:
            print(f"Failed to parse {file_name}: {e}")

    def visit(self, node, file_name):
        # Recursively visit nodes in the AST
        for child in node['body']:
            if child['type'] == 'ExpressionStatement':
                expression = child['expression']
                if expression['type'] == 'CallExpression' and expression['callee']['name'] == 'eval':
                    cwe_info = CWE_DATABASE['Insecure eval() function']
                    self.vulnerabilities.append({
                        "file": file_name,
                        "line": child['loc']['start']['line'],
                        "vulnerability": "Insecure eval() function",
                        "cwe_id": cwe_info['cwe_id'],
                        "description": cwe_info['description'],
                        "severity": cwe_info['severity'],
                        "remediation": cwe_info['remediation']
                    })
