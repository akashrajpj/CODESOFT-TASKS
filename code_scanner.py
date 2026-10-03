import ast
import re
import sys
import json

class SecurityScanner(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.findings = []

    def log_finding(self, line_no, category, severity, message):
        self.findings.append({
            "line": line_no,
            "category": category,
            "severity": severity,
            "message": message
        })

    def visit_Assign(self, node):
        # Scan for hardcoded API keys and secrets
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.upper()
                if any(kw in var_name for kw in ["SECRET", "PASSWORD", "KEY", "TOKEN", "AUTH"]):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        self.log_finding(
                            node.lineno,
                            "Hardcoded Secret",
                            "HIGH",
                            f"Potential sensitive hardcoded secret assigned to '{target.id}'."
                        )
        self.generic_visit(node)

    def visit_Call(self, node):
        # Scan for Command Injection (os.system, subprocess)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["system", "popen"] and getattr(node.func.value, 'id', '') == 'os':
                self.log_finding(
                    node.lineno,
                    "Command Injection",
                    "CRITICAL",
                    "Use of 'os.system' detected. Consider using 'subprocess.run' with shell=False."
                )
            # Scan for Unsafe Deserialization (pickle.loads)
            elif node.func.attr in ["loads", "load"] and getattr(node.func.value, 'id', '') == 'pickle':
                self.log_finding(
                    node.lineno,
                    "Unsafe Deserialization",
                    "HIGH",
                    "Use of 'pickle' for deserialization can lead to arbitrary code execution."
                )
            # Scan for SQL Injection patterns
            elif node.func.attr == "execute":
                if node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
                    self.log_finding(
                        node.lineno,
                        "SQL Injection",
                        "CRITICAL",
                        "Dynamic SQL query construction detected. Use parameterized queries instead."
                    )
        self.generic_visit(node)

def run_assessment(target_file):
    print("=======================================================")
    print("      CodSoft Task 3 - Secure Code Assessment          ")
    print("=======================================================")
    print(f"[*] Analyzing source file: {target_file}\n")

    try:
        with open(target_file, "r", encoding="utf-8") as f:
            code = f.read()
    except FileNotFoundError:
        print(f"[!] Error: Target file '{target_file}' not found.")
        return

    tree = ast.parse(code, filename=target_file)
    scanner = SecurityScanner(target_file)
    scanner.visit(tree)

    print(f"[+] Assessment Complete. Total Findings: {len(scanner.findings)}\n")
    print(f"{'LINE':<8} | {'SEVERITY':<10} | {'CATEGORY':<24} | {'DESCRIPTION'}")
    print("-" * 80)
    
    for issue in scanner.findings:
        print(f"{issue['line']:<8} | {issue['severity']:<10} | {issue['category']:<24} | {issue['message']}")
    
    print("-" * 80)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "target_vulnerable.py"
    run_assessment(target)