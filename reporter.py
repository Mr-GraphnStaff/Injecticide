"""Professional security assessment report generation."""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import html


class ReportGenerator:
    """Generate professional security assessment reports."""
    
    def __init__(self, test_results: List[Dict[str, Any]], config: Dict[str, Any]):
        self.results = test_results
        self.config = config
        self.timestamp = datetime.now().isoformat()
        
    def generate(self, format: str = "html", output_file: Optional[str] = None) -> str:
        """Generate report in specified format."""
        if format == "json":
            report = self._generate_json()
        elif format == "html":
            report = self._generate_html()
        elif format == "csv":
            report = self._generate_csv()
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        if output_file:
            Path(output_file).write_text(report)
        
        return report
    
    def _generate_json(self) -> str:
        """Generate JSON format report."""
        report_data = {
            "metadata": {
                "timestamp": self.timestamp,
                "target": self.config.get("target_service"),
                "model": self.config.get("model"),
                "total_tests": len(self.results),
            },
            "summary": self._generate_summary(),
            "results": self.results,
        }
        return json.dumps(report_data, indent=2)
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate test summary statistics."""
        total = len(self.results)
        detections = sum(1 for r in self.results if any(r.get("flags", {}).values()))
        
        flag_counts = {}
        for result in self.results:
            for flag, value in result.get("flags", {}).items():
                if value:
                    flag_counts[flag] = flag_counts.get(flag, 0) + 1
        
        return {
            "total_tests": total,
            "vulnerabilities_detected": detections,
            "detection_rate": f"{(detections/total*100):.1f}%" if total > 0 else "0%",
            "flag_counts": flag_counts,
        }
    
    def _generate_html(self) -> str:
        """Generate HTML format report."""
        summary = self._generate_summary()
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Injecticide Security Assessment Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #d32f2f; border-bottom: 3px solid #d32f2f; padding-bottom: 10px; }}
        h2 {{ color: #1976d2; margin-top: 30px; }}
        .metadata {{ background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                   gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; 
                     box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .stat-value {{ font-size: 36px; font-weight: bold; color: #1976d2; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #1976d2; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 12px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f5f5f5; }}
        .detection {{ background: #ffebee; color: #c62828; padding: 2px 6px; 
                     border-radius: 3px; font-weight: bold; }}
        .safe {{ background: #e8f5e9; color: #2e7d32; padding: 2px 6px; 
                border-radius: 3px; }}
        .payload {{ font-family: 'Courier New', monospace; background: #f5f5f5; 
                   padding: 8px; border-radius: 4px; word-break: break-all; }}
    </style>
</head>
<body>
    <h1>🛡️ Injecticide Security Assessment Report</h1>
"""        
        # Add metadata section
        html_content += f"""
    <div class="metadata">
        <strong>Assessment Date:</strong> {datetime.fromisoformat(self.timestamp).strftime('%B %d, %Y at %I:%M %p')}<br>
        <strong>Target Service:</strong> {self.config.get('target_service', 'Unknown')}<br>
        <strong>Model:</strong> {self.config.get('model', 'Unknown')}<br>
        <strong>Test Categories:</strong> {', '.join(self.config.get('payload_categories', []))}
    </div>
    
    <h2>📊 Executive Summary</h2>
    <div class="summary">
        <div class="stat-card">
            <div class="stat-value">{summary['total_tests']}</div>
            <div class="stat-label">Total Tests</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{summary['vulnerabilities_detected']}</div>
            <div class="stat-label">Detections</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{summary['detection_rate']}</div>
            <div class="stat-label">Detection Rate</div>
        </div>
    </div>
"""        
        # Add detailed results table
        html_content += """
    <h2>🔍 Detailed Test Results</h2>
    <table>
        <thead>
            <tr>
                <th style="width: 40%">Payload</th>
                <th style="width: 20%">Category</th>
                <th style="width: 20%">Detection Flags</th>
                <th style="width: 20%">Status</th>
            </tr>
        </thead>
        <tbody>
"""
        
        for result in self.results:
            payload = html.escape(result.get('payload', ''))
            category = result.get('category', 'unknown')
            flags = result.get('flags', {})
            detected_flags = [k for k, v in flags.items() if v]
            
            status = '<span class="detection">DETECTED</span>' if detected_flags else '<span class="safe">SAFE</span>'
            flags_str = ', '.join(detected_flags) if detected_flags else 'None'
            
            html_content += f"""
            <tr>
                <td><div class="payload">{payload}</div></td>
                <td>{category}</td>
                <td>{flags_str}</td>
                <td>{status}</td>
            </tr>
"""
        
        html_content += """
        </tbody>
    </table>
    
    <h2>🎯 Recommendations</h2>
    <ul>
        <li>Review and strengthen input validation for detected vulnerability patterns</li>
        <li>Implement additional context-aware filtering for prompt manipulation attempts</li>
        <li>Consider rate limiting and anomaly detection for suspicious request patterns</li>
        <li>Regular security assessments to identify new attack vectors</li>
    </ul>
    
    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; text-align: center;">
        Generated by Injecticide Security Testing Framework<br>
        <a href="https://github.com/yourusername/injecticide">https://github.com/yourusername/injecticide</a>
    </div>
</body>
</html>
"""
        return html_content
    
    def _generate_csv(self) -> str:
        """Generate CSV format report."""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=['payload', 'category', 'flags', 'detected'])
        writer.writeheader()
        
        for result in self.results:
            flags = result.get('flags', {})
            detected_flags = [k for k, v in flags.items() if v]
            writer.writerow({
                'payload': result.get('payload', ''),
                'category': result.get('category', ''),
                'flags': ', '.join(detected_flags),
                'detected': 'Yes' if detected_flags else 'No'
            })
        
        return output.getvalue()
