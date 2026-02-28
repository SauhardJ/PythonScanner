"""XSS detection via AST analysis."""
import ast
import re
from typing import List
from ..models.finding import Finding, Severity, VulnerabilityType

HTML_TAG_PATTERN = re.compile(r"<[a-zA-Z][^>]*>")

USER_INPUT_SOURCES = [
    "request.args", "request.form", "request.json",
    "request.values", "request.data",
]


class XSSAnalyzer:
    """Scans a view function's source code for XSS patterns."""

    def __init__(self, endpoint, file_path, source_code):
        self.endpoint = endpoint
        self.file_path = file_path
        self.source_code = source_code
        self.findings = []

    def analyze(self) -> List[Finding]:
        tree = ast.parse(self.source_code)
        visitor = _XSSVisitor(self)
        visitor.visit(tree)
        return self.findings

    def _has_user_input(self, var_name):
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

    def _add_finding(self, line, code, variable, context):
        self.findings.append(Finding(
            vuln_type=VulnerabilityType.XSS,
            severity=Severity.CRITICAL,
            endpoint=self.endpoint,
            file=self.file_path,
            line=line,
            code_snippet=code,
            explanation=(
                f"Variable '{variable}' contains user input that is placed "
                f"directly into HTML output without escaping ({context}). "
                f"An attacker can inject <script>alert('XSS')</script> to "
                f"steal cookies or redirect users to malicious sites."
            ),
            fix_recommendation="Escape all user input before including in HTML.",
            fix_before=f'return f"<h1>{{{variable}}}</h1>"',
            fix_after=f'from markupsafe import escape\nreturn f"<h1>{{escape({variable})}}</h1>"',
            reference="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ))


class _XSSVisitor(ast.NodeVisitor):
    """Walks the AST looking for XSS patterns."""

    def __init__(self, analyzer):
        self.analyzer = analyzer

    def visit_JoinedStr(self, node):
        """Detect f-strings that output HTML with user variables."""
        constant_parts = ""
        variables = []

        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                constant_parts += value.value
            elif isinstance(value, ast.FormattedValue):
                var_name = self._get_var_name(value.value)
                if var_name:
                    variables.append(var_name)

        if HTML_TAG_PATTERN.search(constant_parts) and variables:
            for var in variables:
                if self.analyzer._has_user_input(var):
                    self.analyzer._add_finding(
                        line=node.lineno,
                        code=self.analyzer._get_line_text(node.lineno),
                        variable=var,
                        context="f-string containing HTML tags",
                    )

        self.generic_visit(node)

    def visit_Call(self, node):
        """Detect render_template_string() with user input."""
        if self._is_render_template_string(node):
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Name):
                    var_name = arg.id
                    if self.analyzer._has_user_input(var_name):
                        self.analyzer._add_finding(
                            line=node.lineno,
                            code=self.analyzer._get_line_text(node.lineno),
                            variable=var_name,
                            context="render_template_string with user input",
                        )
                elif isinstance(arg, ast.JoinedStr):
                    for value in arg.values:
                        if isinstance(value, ast.FormattedValue):
                            var_name = self._get_var_name(value.value)
                            if var_name and self.analyzer._has_user_input(var_name):
                                self.analyzer._add_finding(
                                    line=node.lineno,
                                    code=self.analyzer._get_line_text(node.lineno),
                                    variable=var_name,
                                    context="render_template_string with user input in f-string",
                                )

        self.generic_visit(node)

    def _is_render_template_string(self, node):
        if isinstance(node.func, ast.Name):
            return node.func.id == "render_template_string"
        if isinstance(node.func, ast.Attribute):
            return node.func.attr == "render_template_string"
        return False

    def _get_var_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        return ""