"""Configuration security checks — debug mode, secrets, CSRF, cookies."""
from typing import List
from ..models.finding import Finding, Severity, VulnerabilityType

WEAK_SECRETS = [
    "secret", "password", "password123", "123456", "changeme",
    "default", "admin", "test", "debug", "development",
    "super_secret", "mysecret", "flask-secret",
]


def check_flask_config(app) -> List[Finding]:
    """Run all configuration checks on a Flask app."""
    findings = []

    # Check 1: Debug mode
    if app.debug:
        findings.append(Finding(
            vuln_type=VulnerabilityType.DEBUG_MODE,
            severity=Severity.HIGH,
            endpoint="(global config)",
            file="app configuration",
            line=0,
            code_snippet="app.run(debug=True)",
            explanation=(
                "Debug mode is enabled. Flask's debugger allows "
                "anyone to execute arbitrary Python code on your server. "
                "If this is exposed to the internet, an attacker gets "
                "full control of your machine."
            ),
            fix_recommendation="Never run debug=True in production.",
            fix_before="app.run(debug=True)",
            fix_after="app.run(debug=False)",
            reference="https://flask.palletsprojects.com/en/stable/debugging/",
        ))

    # Check 2: Weak or hardcoded SECRET_KEY
    secret_key = app.config.get("SECRET_KEY", "")
    if secret_key:
        if isinstance(secret_key, str):
            if secret_key.lower() in WEAK_SECRETS or len(secret_key) < 16:
                findings.append(Finding(
                    vuln_type=VulnerabilityType.HARDCODED_SECRET,
                    severity=Severity.HIGH,
                    endpoint="(global config)",
                    file="app configuration",
                    line=0,
                    code_snippet=f'app.secret_key = "{secret_key}"',
                    explanation=(
                        f"SECRET_KEY is weak or easily guessable ('{secret_key}'). "
                        f"Flask uses this key to sign session cookies. An attacker "
                        f"who knows this key can forge sessions and impersonate "
                        f"any user, including admins."
                    ),
                    fix_recommendation="Use a long random secret key from environment variables.",
                    fix_before=f'app.secret_key = "{secret_key}"',
                    fix_after='import os\napp.secret_key = os.environ.get("SECRET_KEY")',
                    reference="https://flask.palletsprojects.com/en/stable/config/#SECRET_KEY",
                ))
    else:
        findings.append(Finding(
            vuln_type=VulnerabilityType.HARDCODED_SECRET,
            severity=Severity.MEDIUM,
            endpoint="(global config)",
            file="app configuration",
            line=0,
            code_snippet="SECRET_KEY not set",
            explanation=(
                "No SECRET_KEY is configured. Flask sessions and flash "
                "messages will not work, and any feature relying on "
                "cookie signing is insecure."
            ),
            fix_recommendation="Set a strong SECRET_KEY.",
            fix_before="# no secret key set",
            fix_after='import os\napp.secret_key = os.environ.get("SECRET_KEY")',
        ))

    # Check 3: CSRF protection
    has_csrf = False
    for ext_name in app.extensions:
        if "csrf" in ext_name.lower():
            has_csrf = True
            break

    if not has_csrf:
        findings.append(Finding(
            vuln_type=VulnerabilityType.CSRF_MISSING,
            severity=Severity.HIGH,
            endpoint="(global config)",
            file="app configuration",
            line=0,
            code_snippet="No CSRF protection detected",
            explanation=(
                "No CSRF protection (like Flask-WTF CSRFProtect) is active. "
                "Without CSRF tokens, an attacker can create a malicious webpage "
                "that submits forms to your app on behalf of logged-in users — "
                "for example, changing their password or making purchases."
            ),
            fix_recommendation="Add Flask-WTF CSRF protection.",
            fix_before="app = Flask(__name__)\n# no CSRF",
            fix_after="from flask_wtf.csrf import CSRFProtect\napp = Flask(__name__)\nCSRFProtect(app)",
            reference="https://owasp.org/www-community/attacks/csrf",
        ))

    return findings