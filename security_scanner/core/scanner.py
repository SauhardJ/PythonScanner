"""Main scanner orchestrator — the heart of the library."""
import time
from typing import List
from ..models.finding import Finding, Severity, VulnerabilityType
from ..models.scan_result import ScanResult
from .route_discovery import discover_flask_routes
from ..analyzers.sql_injection import SQLInjectionAnalyzer
from ..analyzers.xss import XSSAnalyzer
from ..analyzers.config import check_flask_config


def scan_app(app, dynamic=True):
    """
    Scan a web application for security vulnerabilities.

    Usage:
        from security_scanner import scan_app
        results = scan_app(app)

    Args:
        app: The Flask application object.
        dynamic: Whether to run dynamic payload testing (future feature).

    Returns:
        ScanResult containing all findings.
    """
    start_time = time.time()

    # Detect framework
    framework = _detect_framework(app)

    # Create result container
    result = ScanResult(app_name=_get_app_name(app))

    # Step 1: Discover routes
    if framework == "flask":
        routes = discover_flask_routes(app)
    else:
        raise NotImplementedError(f"Framework '{framework}' not yet supported.")

    result.routes_scanned = len(routes)

    # Step 2: Run static analyzers on each route
    for route in routes:
        if route.source_code:
            analyzers = [
                SQLInjectionAnalyzer(route.path, route.file_path or "unknown", route.source_code),
                XSSAnalyzer(route.path, route.file_path or "unknown", route.source_code),
            ]
            for analyzer in analyzers:
                result.findings.extend(analyzer.analyze())

    # Step 3: Global configuration checks
    if framework == "flask":
        result.findings.extend(check_flask_config(app))

    # Step 4: Deduplicate findings
    result.findings = _deduplicate(result.findings)

    result.scan_duration_seconds = time.time() - start_time
    return result


def _detect_framework(app):
    """Auto-detect which web framework the app uses."""
    module = type(app).__module__.lower()

    if "flask" in module:
        return "flask"
    elif "django" in module:
        return "django"
    elif "fastapi" in module or "starlette" in module:
        return "fastapi"
    else:
        raise ValueError(
            f"Cannot detect framework from {type(app).__name__}. "
            f"Currently supported: Flask, Django (planned), FastAPI (planned)."
        )


def _get_app_name(app):
    """Get a readable name for the application."""
    return getattr(app, "name", getattr(app, "import_name", "unknown_app"))


def _deduplicate(findings):
    """Remove duplicate findings (same type + endpoint + line)."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.vuln_type, f.endpoint, f.line, f.code_snippet)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique