"""Run the security scanner — using the clean public API."""
from examples.vulnerable_app import app
from security_scanner import scan_app

# This is it — one line to scan the entire app
result = scan_app(app)

# Print results
print("=" * 60)
print(f"  SECURITY SCAN REPORT — {result.app_name}")
print(f"  Routes scanned: {result.routes_scanned}")
print(f"  Scan time: {result.scan_duration_seconds:.3f}s")
print("=" * 60)

if not result.findings:
    print("\n  ✅ No vulnerabilities found. Great job!")
else:
    for i, finding in enumerate(result.findings, 1):
        icon = {
            "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🔵", "INFO": "⚪",
        }.get(finding.severity.value, "⚪")

        print(f"\n  {icon} [{i}] {finding.severity.value}: {finding.vuln_type.value}")
        print(f"      Endpoint: {finding.endpoint}")
        if finding.line > 0:
            print(f"      Line:     {finding.line}")
        print(f"      Code:     {finding.code_snippet}")
        print(f"      Why:      {finding.explanation}")
        print(f"      Fix:      {finding.fix_recommendation}")
        if finding.fix_before:
            print(f"      Before:   {finding.fix_before}")
        if finding.fix_after:
            print(f"      After:    {finding.fix_after}")
        if finding.reference:
            print(f"      Ref:      {finding.reference}")

print(f"\n  {'=' * 40}")
print(f"  Summary: {result.critical_count} Critical | {result.high_count} High | {result.medium_count} Medium")
print(f"  Total issues: {len(result.findings)}")
print("=" * 60)

# Save JSON report
from security_scanner.reporting.json_report import save_json_report
save_json_report(result, "scan_report.json")