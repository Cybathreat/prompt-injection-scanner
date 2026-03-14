#!/usr/bin/env python3
"""
Report Generator - PDF and JSON Report Generation

Generates professional security reports for prompt injection scan results.
"""
import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

from attacks import AttackResult, AttackSeverity


class ReportGenerator:
    """Generate PDF and JSON reports from scan results."""
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize report generator.
        
        Args:
            output_dir: Directory to save reports (defaults to ./reports)
        """
        self.output_dir = Path(output_dir) if output_dir else Path("./reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_json_report(self, target: str, results: List[AttackResult], 
                             config: Optional[Dict] = None) -> str:
        """
        Generate JSON report file.
        
        Args:
            target: Scanned target URL
            results: List of AttackResult objects
            config: Optional configuration dict
            
        Returns:
            Path to generated JSON file
        """
        timestamp = datetime.now().isoformat()
        report_id = f"scan_{timestamp.replace(':', '-')}"
        
        # Build report structure
        report = {
            "report_id": report_id,
            "generated_at": timestamp,
            "target": target,
            "summary": {
                "total_patterns": len(results),
                "vulnerabilities_found": len([r for r in results if r.success]),
                "clean_responses": len([r for r in results if not r.success]),
                "severity_breakdown": self._count_severities(results),
            },
            "configuration": config or {},
            "results": [
                {
                    "pattern_id": r.pattern_id,
                    "pattern_name": r.pattern_name,
                    "success": r.success,
                    "severity": r.severity.value,
                    "status_code": r.response_status,
                    "response_text": r.response_text[:500] if r.response_text else "",
                    "injection_payload": r.injection_payload,
                    "findings": r.findings,
                    "timestamp": r.timestamp,
                }
                for r in results
            ],
            "recommendations": self._generate_recommendations(results),
        }
        
        # Write JSON file
        output_path = self.output_dir / f"{report_id}.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return str(output_path)
    
    def generate_pdf_report(self, target: str, results: List[AttackResult],
                            config: Optional[Dict] = None) -> str:
        """
        Generate PDF report file.
        
        Args:
            target: Scanned target URL
            results: List of AttackResult objects
            config: Optional configuration dict
            
        Returns:
            Path to generated PDF file
        """
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
        except ImportError:
            raise ImportError("reportlab is required for PDF generation. Install with: pip install reportlab")
        
        timestamp = datetime.now().isoformat()
        report_id = f"scan_{timestamp.replace(':', '-')}"
        output_path = self.output_dir / f"{report_id}.pdf"
        
        # Create PDF document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch,
        )
        
        # Container for the 'Flowable' objects
        elements = []
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a2e'),
            spaceAfter=30,
        )
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#16213e'),
            spaceAfter=12,
        )
        
        # Title
        elements.append(Paragraph("Prompt Injection Security Report", title_style))
        elements.append(Spacer(1, 0.2*inch))
        
        # Metadata table
        meta_data = [
            ["Report ID:", report_id],
            ["Generated:", timestamp],
            ["Target:", target],
            ["Tool:", "Prompt Injection Scanner v1.0"],
            ["Author:", "Ahmed Chiboub (@cybathreat)"],
        ]
        meta_table = Table(meta_data, colWidths=[1.5*inch, 3.5*inch])
        meta_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Executive Summary
        elements.append(Paragraph("Executive Summary", heading_style))
        vulns = len([r for r in results if r.success])
        total = len(results)
        
        if vulns == 0:
            summary_text = f"<b>✅ SECURE:</b> No vulnerabilities detected. All {total} attack patterns were successfully blocked by the target."
        elif vulns < 3:
            summary_text = f"<b>⚠️ LOW RISK:</b> {vulns} vulnerabilities detected out of {total} patterns tested. Minor security improvements recommended."
        elif vulns < 6:
            summary_text = f"<b>🟠 MEDIUM RISK:</b> {vulns} vulnerabilities detected out of {total} patterns tested. Security improvements required."
        else:
            summary_text = f"<b>🔴 HIGH RISK:</b> {vulns} vulnerabilities detected out of {total} patterns tested. Immediate security action required."
        
        elements.append(Paragraph(summary_text, styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Severity breakdown
        severity_counts = self._count_severities(results)
        if severity_counts:
            elements.append(Paragraph("Severity Breakdown", heading_style))
            severity_data = [["Severity", "Count"]]
            for severity in ["critical", "high", "medium", "low"]:
                if severity in severity_counts:
                    severity_data.append([severity.upper(), str(severity_counts[severity])])
            
            severity_table = Table(severity_data, colWidths=[2*inch, 1*inch])
            severity_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            elements.append(severity_table)
            elements.append(Spacer(1, 0.3*inch))
        
        # Detailed Results
        elements.append(Paragraph("Detailed Findings", heading_style))
        
        for i, result in enumerate(results, 1):
            # Pattern header
            status_icon = "✅" if not result.success else "⚠️"
            elements.append(Paragraph(
                f"{status_icon} Pattern {result.pattern_id}: {result.pattern_name}",
                styles['Heading3']
            ))
            
            # Details
            details = [
                f"<b>Severity:</b> {result.severity.value.upper()}",
                f"<b>Success:</b> {'Yes' if result.success else 'No'}",
                f"<b>HTTP Status:</b> {result.response_status}",
            ]
            for detail in details:
                elements.append(Paragraph(detail, styles['Normal']))
            
            if result.findings:
                elements.append(Paragraph("<b>Findings:</b>", styles['Normal']))
                for finding in result.findings:
                    elements.append(Paragraph(f"  • {finding}", styles['Normal']))
            
            elements.append(Spacer(1, 0.2*inch))
        
        # Recommendations
        elements.append(Paragraph("Recommendations", heading_style))
        recommendations = self._generate_recommendations(results)
        for i, rec in enumerate(recommendations, 1):
            elements.append(Paragraph(f"{i}. {rec}", styles['Normal']))
        
        # Footer
        elements.append(Spacer(1, 0.5*inch))
        elements.append(Paragraph(
            "Generated by Prompt Injection Scanner | Cyberian Defenses | https://github.com/cybathreat",
            styles['Normal']
        ))
        
        # Build PDF
        doc.build(elements)
        
        return str(output_path)
    
    def _count_severities(self, results: List[AttackResult]) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {}
        for r in results:
            if r.success:
                sev = r.severity.value
                counts[sev] = counts.get(sev, 0) + 1
        return counts
    
    def _generate_recommendations(self, results: List[AttackResult]) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        vulns = [r for r in results if r.success]
        
        if not vulns:
            return ["Continue monitoring for new attack vectors", "Regular security audits recommended"]
        
        # Check for critical/high severity
        critical_high = [r for r in vulns if r.severity in [AttackSeverity.CRITICAL, AttackSeverity.HIGH]]
        if critical_high:
            recommendations.append("URGENT: Implement input validation and sanitization for all user prompts")
            recommendations.append("Deploy content filtering to block known injection patterns")
            recommendations.append("Implement rate limiting and request throttling")
        
        # Check for jailbreak/direct injection
        jailbreaks = [r for r in vulns if 'jailbreak' in r.pattern_name.lower() or 'direct' in r.pattern_name.lower()]
        if jailbreaks:
            recommendations.append("Strengthen system prompt boundaries and instruction hierarchy")
            recommendations.append("Implement prompt normalization before processing")
        
        # Check for data exfiltration
        exfil = [r for r in vulns if 'exfiltration' in r.pattern_name.lower()]
        if exfil:
            recommendations.append("Never expose system prompts or internal configuration to users")
            recommendations.append("Implement strict output filtering for sensitive data")
        
        # Generic recommendations
        recommendations.append("Regularly update attack pattern database")
        recommendations.append("Conduct periodic penetration testing")
        recommendations.append("Implement logging and monitoring for injection attempts")
        
        return recommendations


def generate_reports(target: str, results: List[AttackResult], 
                     output_dir: Optional[str] = None,
                     format: str = "both",
                     config: Optional[Dict] = None) -> Dict[str, str]:
    """
    Convenience function to generate reports.
    
    Args:
        target: Scanned target URL
        results: List of AttackResult objects
        output_dir: Output directory (default: ./reports)
        format: 'json', 'pdf', or 'both'
        config: Optional configuration dict
        
    Returns:
        Dict with paths to generated files
    """
    generator = ReportGenerator(output_dir)
    generated = {}
    
    if format in ["json", "both"]:
        generated["json"] = generator.generate_json_report(target, results, config)
    
    if format in ["pdf", "both"]:
        try:
            generated["pdf"] = generator.generate_pdf_report(target, results, config)
        except ImportError as e:
            generated["pdf_error"] = str(e)
    
    return generated
