import json
import csv
import html
from datetime import datetime
from typing import List, Dict, Any

class ReportGenerator:
    """Generate comprehensive reports for SQL injection scan results"""

    def __init__(self):
        self.scan_results: List[Dict[str, Any]] = []
        self.scan_metadata: Dict[str, Any] = {}

    def add_scan_result(self, result: Dict[str, Any]):
        """Add a scan result to the report data"""
        result['timestamp'] = datetime.now().isoformat()
        self.scan_results.append(result)

    def set_scan_metadata(self, metadata: Dict[str, Any]):
        """Set metadata for the scan (target, settings, etc.)"""
        self.scan_metadata = metadata
        if 'scan_start' not in self.scan_metadata:
            self.scan_metadata['scan_start'] = datetime.now().isoformat()

    def generate_text_report(self) -> str:
        """Generate a detailed text report"""
        report = []

        # Header
        report.append("=" * 80)
        report.append("SQL INJECTION TESTING REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")

        # Scan metadata
        if self.scan_metadata:
            report.append("SCAN CONFIGURATION")
            report.append("-" * 40)
            report.append(f"Target(s): {self.scan_metadata.get('target_url', self.scan_metadata.get('total_domains', 'N/A'))}")
            report.append(f"Scan Mode: {self.scan_metadata.get('scan_mode', 'N/A')}")
            report.append(f"Injection Types: {', '.join(self.scan_metadata.get('injection_types', []))}")
            report.append(f"Scan Start: {self.scan_metadata.get('scan_start', 'N/A')}")
            report.append("")

        # Summary
        vulnerabilities = [r for r in self.scan_results if r.get('vulnerable', False)]
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 40)
        report.append(f"Total Tests Performed: {len(self.scan_results)}")
        report.append(f"Vulnerabilities Found: {len(vulnerabilities)}")
        report.append(f"Risk Level: {'HIGH' if len(vulnerabilities) > 0 else 'LOW'}")
        report.append("")

        # Vulnerabilities section
        if vulnerabilities:
            report.append("VULNERABILITIES DETECTED")
            report.append("-" * 40)

            for i, vuln in enumerate(vulnerabilities, 1):
                report.append(f"\n{i}. VULNERABILITY FOUND")
                report.append(f"   Target URL: {vuln.get('target_url', 'N/A')}")
                report.append(f"   Parameter: {vuln.get('test_parameter', 'N/A')}")
                report.append(f"   Type: {vuln.get('injection_type', 'Unknown')}")
                report.append(f"   Payload: {vuln.get('payload', 'N/A')}")
                report.append(f"   Confidence: {vuln.get('confidence', 'N/A')}")
                report.append(f"   Evidence: {vuln.get('evidence', 'N/A')}")
                report.append("")
        else:
            report.append("NO VULNERABILITIES DETECTED")
            report.append("-" * 40)
            report.append("No SQL injection vulnerabilities were found during this scan.")
            report.append("")

        # Recommendations
        report.append("\n\nRECOMMENDATIONS")
        report.append("-" * 40)

        if vulnerabilities:
            report.append("IMMEDIATE ACTIONS REQUIRED:")
            report.append("1. Review and sanitize all user input validation for the vulnerable parameters.")
            report.append("2. Implement parameterized queries (prepared statements) to prevent SQLi.")
            report.append("3. Apply the principle of least privilege to database users.")
            report.append("4. Enable SQL injection protection in a Web Application Firewall (WAF).")
        else:
            report.append("MAINTENANCE RECOMMENDATIONS:")
            report.append("1. Continue regular security testing and code reviews.")
            report.append("2. Ensure input validation best practices are followed for all new features.")
            report.append("3. Monitor application logs for suspicious activity.")
            report.append("4. Keep database and application frameworks updated.")

        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)

        return "\n".join(report)


    def generate_html_report(self) -> str:
        """Generate an HTML report with styling"""
        vulnerabilities = [r for r in self.scan_results if r.get('vulnerable', False)]
        
        scan_duration_seconds = 0
        if self.scan_metadata.get('scan_start'):
             try:
                start_time = datetime.fromisoformat(self.scan_metadata['scan_start'])
                scan_duration_seconds = (datetime.now() - start_time).total_seconds()
             except:
                pass # Ignore if format is wrong

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Test Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background-color: #f5f5f5; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; padding-bottom: 20px; margin-bottom: 30px; border-bottom: 2px solid #3498db; }}
        .header h1 {{ color: #2c3e50; margin: 0; }}
        .header .subtitle {{ color: #7f8c8d; margin-top: 5px; }}
        .section {{ margin-bottom: 30px; }}
        .section-title {{ border-bottom: 1px solid #ddd; padding-bottom: 10px; margin-bottom: 15px; color: #3498db; }}
        .metadata {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 25px; }}
        .metadata-card {{ background: #f8f9fa; padding: 15px; border-radius: 6px; border-left: 4px solid #3498db; }}
        .metadata-card h3 {{ margin-top: 0; color: #2c3e50; }}
        .vulnerability {{ background: #fdf2f2; border-left: 4px solid #e74c3c; padding: 15px; margin-bottom: 15px; border-radius: 4px; }}
        .vulnerability-title {{ color: #e74c3c; margin-top: 0; }}
        .payload {{ font-family: monospace; background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }}
        .footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #ddd; text-align: center; font-size: 0.9em; color: #7f8c8d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SQL Injection Test Report</h1>
            <div class="subtitle">Generated on {datetime.now().strftime('%B %d, %Y at %H:%M')}</div>
        </div>

        <div class="section">
            <h2 class="section-title">Scan Overview</h2>
            <div class="metadata">
                <div class="metadata-card">
                    <h3>Target Information</h3>
                    <p><strong>Mode:</strong> {html.escape(str(self.scan_metadata.get('scan_mode', 'N/A')))}</p>
                    <p><strong>Domains Tested:</strong> {html.escape(str(self.scan_metadata.get('total_domains', 'N/A')))}</p>
                </div>
                <div class="metadata-card">
                    <h3>Scan Statistics</h3>
                    <p><strong>Duration:</strong> {scan_duration_seconds:.2f} seconds</p>
                    <p><strong>Vulnerabilities:</strong> {len(vulnerabilities)}</p>
                    <p><strong>Risk Level:</strong> <span style="color: {'HIGH': '#e74c3c', 'LOW': '#2ecc71'}.get( 'HIGH' if vulnerabilities else 'LOW' , '#333')">{'HIGH' if vulnerabilities else 'LOW'}</span></p>
                </div>
                <div class="metadata-card">
                    <h3>Test Coverage</h3>
                    <p><strong>Techniques:</strong> {html.escape(', '.join(self.scan_metadata.get('injection_types', ['N/A'])))}</p>
                </div>
            </div>
        </div>
"""

        if vulnerabilities:
            html_content += """
        <div class="section">
            <h2 class="section-title">Vulnerabilities Found</h2>
"""
            for i, vuln in enumerate(vulnerabilities, 1):
                html_content += f"""
            <div class="vulnerability">
                <h3 class="vulnerability-title">Vulnerability #{i}: {html.escape(str(vuln.get('injection_type', 'Unknown')).title())} Injection</h3>
                <p><strong>Target:</strong> {html.escape(str(vuln.get('target_url', 'N/A')))}</p>
                <p><strong>Parameter:</strong> {html.escape(str(vuln.get('test_parameter', 'N/A')))}</p>
                <p><strong>Confidence:</strong> {html.escape(str(vuln.get('confidence', 'N/A')))}</p>
                <p><strong>Evidence:</strong> {html.escape(str(vuln.get('evidence', 'N/A')))}</p>
                <p><strong>Payload:</strong></p>
                <div class="payload">{html.escape(str(vuln.get('payload', 'N/A')))}</div>
            </div>"""
            
            html_content += "</div>"

        html_content += """
        <div class="section">
            <h2 class="section-title">Recommendations</h2>
"""
        if vulnerabilities:
            html_content += """
            <h3>Critical Action Items</h3>
            <ol>
                <li>Immediately investigate and remediate the identified vulnerable endpoints.</li>
                <li>Implement parameterized queries (prepared statements) across the application to prevent all forms of SQL injection.</li>
                <li>Review application code for other similar vulnerabilities, especially in related functions.</li>
                <li>Configure and enable Web Application Firewall (WAF) rules specifically for SQL injection protection.</li>
            </ol>
"""
        else:
            html_content += """
            <p><strong>No vulnerabilities detected during this scan.</strong></p>
            <h3>General Security Recommendations</h3>
            <ul>
                <li>Continue regular automated and manual security testing.</li>
                <li>Enforce strict input validation and sanitization on all user-supplied data.</li>
                <li>Keep all database systems, application frameworks, and libraries up-to-date with security patches.</li>
                <li>Monitor database and application logs for any suspicious activity.</li>
            </ul>
"""

        html_content += """
        </div>
        <div class="footer">
            <p>This report was generated by the SQL Injection Testing Tool - Professional Edition</p>
            <p><em>For authorized security testing only</em></p>
        </div>
    </div>
</body>
</html>
"""
        return html_content

    def generate_json_report(self) -> str:
        """Generate a JSON report for programmatic use"""
        report_data = {
            "metadata": {
                "report_version": "2.0",
                "generated_at": datetime.now().isoformat(),
                "scan_parameters": self.scan_metadata or {},
                "summary": {
                    "total_tests": len(self.scan_results),
                    "vulnerabilities_found": len([r for r in self.scan_results if r.get('vulnerable', False)]),
                    "risk_level": "high" if any(r.get('vulnerable', False) for r in self.scan_results) else "low"
                }
            },
            "results": self.scan_results
        }
        
        return json.dumps(report_data, indent=2)

    def generate_csv_report(self) -> str:
        """Generate a CSV report for spreadsheet analysis"""
        if not self.scan_results:
            return "No data to export"
        
        # Use io.StringIO to build the CSV in memory
        import io
        output = io.StringIO()
        
        # Define CSV headers and field order
        fieldnames = [
            'timestamp', 'target_url', 'test_parameter', 'injection_type', 'vulnerable', 
            'payload', 'confidence', 'evidence', 'database_type', 'http_status'
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for result in self.scan_results:
            # Create a new dict with only the fields we want to write
            row_to_write = {field: result.get(field, '') for field in fieldnames}
            writer.writerow(row_to_write)
        
        return output.getvalue()

    def save_report(self, filename: str, format_type: str = 'html'):
        """Saves the generated report to a file."""
        report_content = ""
        try:
            if format_type == 'html':
                report_content = self.generate_html_report()
            elif format_type == 'json':
                report_content = self.generate_json_report()
            elif format_type == 'csv':
                report_content = self.generate_csv_report()
            elif format_type == 'txt':
                report_content = self.generate_text_report()
            else:
                raise ValueError(f"Unsupported report format: {format_type}")

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            return True

        except Exception as e:
            print(f"Error saving report to {filename}: {e}")
            raise e