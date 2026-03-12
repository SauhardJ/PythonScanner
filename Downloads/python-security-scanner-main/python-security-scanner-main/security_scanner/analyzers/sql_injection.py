"""SQL Injection detection via AST analysis."""
import ast
import re
from typing import List
from ..models.finding import Finding, Severity, VulnerabilityType

SQL_KEYWORDS = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE)\b",
    re.IGNORECASE,
)

USER_INPUT_SOURCES = [
    "request.args", "request.form", "request.json",
    "request.values", "request.data",
]


class SQLInjectionAnalyzer:
    """Scans a view function's source code for SQL injection patterns."""

    def __init__(self, endpoint, file_path, source_code):
        self.endpoint = endpoint
        self.file_path = file_path
        self.source_code = source_code
        self.findings = []

    def analyze(self) -> List[Finding]:
        tree = ast.parse(self.source_code)
        visitor = _SQLVisitor(self)
        visitor.visit(tree)
        return self.findings

    def _has_user_input(self, var_name):
        """Check if a variable likely comes from user input."""
        for source in USER_INPUT_SOURCES:
            if f"{var_name} = {source}" in self.source_code or \
               f"{var_name} = request." in self.source_code:
                return True
        return False

    def _get_line_text(self, lineno):
        lines = self.source_code.splitlines()
        if 1 <= lineno <= len(lines):
            return lines[lineno - 1].strip()
        return ""

    def _add_finding(self, line, code, variable):
        self.findings.append(Finding(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            endpoint=self.endpoint,
            file=self.file_path,
            line=line,
            code_snippet=code,
            explanation=(
                f"Variable '{variable}' comes from user input and is inserted "
                f"directly into a SQL query. An attacker can send input like "
                f"' OR '1'='1 to manipulate the query and access all data."
            ),
            fix_recommendation="Use parameterized queries instead of string interpolation.",
            fix_before=f'cursor.execute(f"SELECT ... WHERE col = {{{variable}}}")',
            fix_after=f'cursor.execute("SELECT ... WHERE col = %s", ({variable},))',
            reference="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ))


class _SQLVisitor(ast.NodeVisitor):
    """Walks the AST looking for dangerous SQL patterns."""

    def __init__(self, analyzer):
        self.analyzer = analyzer

    def visit_JoinedStr(self, node):
        """Detect f-strings like f'SELECT * FROM users WHERE id = {user_id}'"""
        constant_parts = ""
        variables = []

        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                constant_parts += value.value
            elif isinstance(value, ast.FormattedValue):
                var_name = self._get_var_name(value.value)
                if var_name:
                    variables.append(var_name)

        if SQL_KEYWORDS.search(constant_parts) and variables:
            for var in variables:
                if self.analyzer._has_user_input(var):
                    self.analyzer._add_finding(
                        line=node.lineno,
                        code=self.analyzer._get_line_text(node.lineno),
                        variable=var,
                    )

        self.generic_visit(node)

    def visit_BinOp(self, node):
        """Detect string concatenation like 'SELECT ... ' + username + '...'"""
        if isinstance(node.op, ast.Add):
            full_string = self._get_string_parts(node)
            if SQL_KEYWORDS.search(full_string):
                variables = self._get_variables(node)
                for var in variables:
                    if self.analyzer._has_user_input(var):
                        self.analyzer._add_finding(
                            line=node.lineno,
                            code=self.analyzer._get_line_text(node.lineno),
                            variable=var,
                        )

        self.generic_visit(node)

    def _get_var_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        return ""

    def _get_string_parts(self, node):
        parts = []
        if isinstance(node.left, ast.Constant):
            parts.append(str(node.left.value))
        elif isinstance(node.left, ast.BinOp):
            parts.append(self._get_string_parts(node.left))
        if isinstance(node.right, ast.Constant):
            parts.append(str(node.right.value))
        return " ".join(parts)

    def _get_variables(self, node):
        variables = []
        for child in [node.left, node.right]:
            if isinstance(child, ast.Name):
                variables.append(child.id)
            elif isinstance(child, ast.BinOp):
                variables.extend(self._get_variables(child))
        return variables