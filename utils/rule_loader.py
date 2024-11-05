import json
import os

class RuleLoader:
    def __init__(self, rules_file='rules.json'):
        self.rules_file = rules_file
        self.rules = self.load_rules()

    def load_rules(self):
        if not os.path.exists(self.rules_file):
            print(f"Rules file '{self.rules_file}' not found. Using default rules.")
            return self.default_rules()
        
        with open(self.rules_file, 'r') as f:
            return json.load(f)

    # def default_rules(self):
    #     # Define default rules if the rules file is not found
    #     return {
    #         "python": [
    #             {
    #                 "pattern": "eval",
    #                 "description": "Insecure use of eval()",
    #                 "severity": "High",
    #                 "remediation": "Avoid using eval() as it can execute arbitrary code."
    #             },
    #             # Add more default Python rules here
    #         ],
    #         "javascript": [
    #             {
    #                 "pattern": "eval",
    #                 "description": "Insecure use of eval()",
    #                 "severity": "High",
    #                 "remediation": "Avoid using eval() as it can execute arbitrary code."
    #             },
    #             # Add more default JavaScript rules here
    #         ],
    #         "java": [
    #             {
    #                 "pattern": "exec",
    #                 "description": "Insecure execution of system commands",
    #                 "severity": "High",
    #                 "remediation": "Avoid using exec() to execute system commands."
    #             },
    #             # Add more default Java rules here
    #         ]
    #     }



    # ...........................................................



    def default_rules(self):
        return {
            "python": [
                {
                    "pattern": "eval",
                    "description": "Insecure use of eval()",
                    "severity": "Critical",
                    "remediation": "Avoid using eval() as it can execute arbitrary code."
                },
                {
                    "pattern": "input",
                    "description": "Insecure use of input()",
                    "severity": "Medium",
                    "remediation": "Avoid using input() as it can lead to code injection."
                },
                {
                    "pattern": "print",
                    "description": "Insecure use of print()",
                    "severity": "Low",
                    "remediation": "Avoid using print() with user-input data."
                },
                # Add more default Python rules here
            ],
            "javascript": [
                {
                    "pattern": "eval",
                    "description": "Insecure use of eval()",
                    "severity": "Critical",
                    "remediation": "Avoid using eval() as it can execute arbitrary code."
                },
                {
                    "pattern": "innerHTML",
                    "description": "Insecure use of innerHTML",
                    "severity": "Medium",
                    "remediation": "Avoid using innerHTML as it can lead to XSS."
                },
                {
                    "pattern": "alert",
                    "description": "Insecure use of alert()",
                    "severity": "Low",
                    "remediation": "Avoid using alert() with user-input data."
                },
                # Add more default JavaScript rules here
            ],
            "java": [
                {
                    "pattern": "exec",
                    "description": "Insecure execution of system commands",
                    "severity": "Critical",
                    "remediation": "Avoid using exec() to execute system commands."
                },
                {
                    "pattern": "Runtime.exec",
                    "description": "Insecure use of Runtime.exec()",
                    "severity": "Medium",
                    "remediation": "Avoid using Runtime.exec() as it can lead to command injection."
                },
                {
                    "pattern": "System.out.println",
                    "description": "Insecure use of System.out.println()",
                    "severity": "Low",
                    "remediation": "Avoid using System.out.println() with user-input data."
                },
                # Add more default Java rules here
            ]
        }

    def get_rules(self, language):
        return self.rules.get(language, [])

# Example usage
if __name__ == "__main__":
    loader = RuleLoader()
    python_rules = loader.get_rules('python')
    print("Python Rules:", python_rules)
