import os
import re
import datetime
import json
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Flowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

from malware_analyzer.config import settings

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_elements(num_pages)
            super().showPage()
        super().save()

    def draw_page_elements(self, page_count):
        # Cover page (Page 1) does not get header or footer
        if self._pageNumber == 1:
            return
        
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#4a5568"))
        
        # Header text
        self.drawString(54, 750, "MALWARE ANALYSIS REPORT")
        self.setFont("Helvetica", 8)
        self.drawRightString(558, 750, datetime.datetime.now().strftime("%Y-%m-%d"))
        
        # Header Line
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 742, 558, 742)
        
        # Footer Line
        self.line(54, 50, 558, 50)
        self.drawString(54, 38, "CONFIDENTIAL - MALWARE ANALYSIS SYSTEM")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 38, page_text)
        
        self.restoreState()


class HeadingTracker(Flowable):
    def __init__(self, key, title_dict):
        super().__init__()
        self.key = key
        self.title_dict = title_dict
        
    def draw(self):
        self.title_dict[self.key] = self.canv._pageNumber


def clean_strings(str_list, category):
    cleaned = []
    for s in str_list:
        if isinstance(s, bytes):
            try:
                s = s.decode('utf-8', errors='ignore')
            except Exception:
                continue
        s = str(s).strip()
        if not s or len(s) < 4:
            continue
            
        if category == "urls":
            if s.lower().startswith(("http://", "https://")):
                cleaned.append(s)
        elif category == "domains":
            if s.lower().endswith((".dll", ".exe", ".sys", ".drv", ".ocx", ".manifest", ".ini", ".lnk")):
                continue
            if "." in s and not s.startswith(".") and not s.endswith("."):
                cleaned.append(s)
        elif category == "ips":
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s) or ":" in s:
                cleaned.append(s)
        elif category == "emails":
            if "@" in s and "." in s:
                cleaned.append(s)
        elif category == "registry":
            if s.upper().startswith(("HKLM", "HKCU", "HKEY_")):
                cleaned.append(s)
    return sorted(list(set(cleaned)))


class PDFGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        
        # Create standard layout colors
        self.primary_color = colors.HexColor("#1e3a8a") # Dark Blue
        self.secondary_color = colors.HexColor("#0f172a") # Dark Slate
        self.text_color = colors.HexColor("#1e293b")
        self.bg_light = colors.HexColor("#f8fafc")
        self.border_color = colors.HexColor("#e2e8f0")
        
        # Configure styles
        self.normal = ParagraphStyle('ReportNormal', parent=self.styles['Normal'], textColor=self.text_color, fontSize=9, leading=13)
        self.normal_bold = ParagraphStyle('ReportNormalBold', parent=self.normal, fontName='Helvetica-Bold')
        self.code_style = ParagraphStyle('ReportCode', parent=self.normal, fontName='Courier', fontSize=8, leading=10, wordWrap='CJK')
        
        self.title_style = ParagraphStyle('ReportTitle', fontName='Helvetica-Bold', fontSize=24, leading=28, textColor=self.primary_color, alignment=1)
        self.subtitle_style = ParagraphStyle('ReportSubtitle', fontName='Helvetica', fontSize=12, leading=16, textColor=colors.HexColor("#475569"), alignment=1)
        
        self.h1_style = ParagraphStyle('ReportH1', fontName='Helvetica-Bold', fontSize=14, leading=18, textColor=self.primary_color, spaceBefore=12, spaceAfter=8, keepWithNext=True)
        self.h2_style = ParagraphStyle('ReportH2', fontName='Helvetica-Bold', fontSize=11, leading=15, textColor=self.secondary_color, spaceBefore=8, spaceAfter=4, keepWithNext=True)
        self.bullet_style = ParagraphStyle('ReportBullet', parent=self.normal, leftIndent=15, bulletIndent=5, spaceAfter=3)
        
        # Ensure reports dir exists
        os.makedirs(settings.REPORTS_DIR, exist_ok=True)

    def format_size(self, size_bytes):
        if not size_bytes:
            return "0 Bytes"
        for unit in ['Bytes', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"

    def group_findings_by_severity(self, aggregated_data):
        findings = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": []
        }
        
        # 1. YARA matches
        yara = aggregated_data["results"].get("yara_analysis")
        if yara and yara.status == "success":
            for m in yara.findings.get("matches", []):
                sev = m.get("severity", "MEDIUM").upper()
                rule = m.get("rule_name")
                desc = m.get("description")
                msg = f"YARA rule matched: {rule} - {desc}"
                if sev in findings:
                    findings[sev].append(msg)
                else:
                    findings["MEDIUM"].append(msg)
                    
        # 2. Suspicious Imports
        imp = aggregated_data["results"].get("import_analysis")
        if imp and imp.status == "success":
            for f in imp.findings.get("imports", []):
                api = f.get("api")
                finding = f.get("finding")
                msg = f"Suspicious API import: {api} ({finding})"
                findings["HIGH"].append(msg)
                
        # 3. Entropy
        ent = aggregated_data["results"].get("entropy_analysis")
        if ent and ent.status == "success":
            for sect in ent.findings.get("sections", []):
                if sect.get("entropy", 0) >= 7.0:
                    msg = f"High entropy section '{sect['name']}' ({sect['entropy']:.2f}) indicates potential packing/obfuscation."
                    findings["MEDIUM"].append(msg)
                    
        # 4. Security Mitigations
        sec = aggregated_data["results"].get("security_analysis")
        if sec and sec.status == "success":
            for mit, status in sec.findings.items():
                if status in ["Disabled", "Unknown/Disabled", "Unknown"]:
                    msg = f"Security mitigation {mit} is not enabled (status: {status})."
                    findings["LOW"].append(msg)
                    
        # 5. Manifest privileges
        man = aggregated_data["results"].get("manifest_analysis")
        if man and man.status == "success":
            lvl = man.findings.get("requestedExecutionLevel")
            if lvl in ["requireAdministrator", "highestAvailable"]:
                msg = f"Manifest requests elevated execution privilege level: {lvl}."
                findings["MEDIUM"].append(msg)
                
        return findings

    def generate_report(self, aggregated_data: dict, file_path: str):
        filename = os.path.basename(file_path)
        
        # Strip UUID prefix if present to get clean exename
        clean_filename = filename
        if len(filename) > 37 and filename[36] == '_':
            # UUID is 36 chars + 1 underscore
            clean_filename = filename[37:]
            
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        report_filename = f"{timestamp}-{clean_filename}.pdf"
        report_path = os.path.join(settings.REPORTS_DIR, report_filename)
        
        # Check if dynamic analysis report
        if aggregated_data.get("is_dynamic"):
            # Build phase 1: Dry run to populate page map
            page_map = {}
            story_dry = self.build_dynamic_story_flow(aggregated_data, file_path, page_map)
            doc_dry = SimpleDocTemplate(report_path, pagesize=letter, leftMargin=54, rightMargin=54, topMargin=72, bottomMargin=72)
            doc_dry.build(story_dry, canvasmaker=NumberedCanvas)
            
            # Build phase 2: Real run using populated page map
            story_real = self.build_dynamic_story_flow(aggregated_data, file_path, page_map)
            doc_real = SimpleDocTemplate(report_path, pagesize=letter, leftMargin=54, rightMargin=54, topMargin=72, bottomMargin=72)
            
            safe_data = {
                "filename": filename,
                "timestamp": timestamp,
                "is_dynamic": True,
                "analysis_id": aggregated_data.get("analysis_id", "N/A"),
                "findings": aggregated_data.get("findings", [])
            }
            doc_real.subject = json.dumps(safe_data)
            doc_real.build(story_real, canvasmaker=NumberedCanvas)
            return report_path

        # Build phase 1: Dry run to populate page map
        page_map = {}
        story_dry = self.build_story_flow(aggregated_data, file_path, page_map)
        doc_dry = SimpleDocTemplate(report_path, pagesize=letter, leftMargin=54, rightMargin=54, topMargin=72, bottomMargin=72)
        doc_dry.build(story_dry, canvasmaker=NumberedCanvas)
        
        # Build phase 2: Real run using populated page map
        story_real = self.build_story_flow(aggregated_data, file_path, page_map)
        doc_real = SimpleDocTemplate(report_path, pagesize=letter, leftMargin=54, rightMargin=54, topMargin=72, bottomMargin=72)
        
        # Build safe dict for metadata embedding
        risk_assessment = aggregated_data.get("risk_assessment", {})
        if aggregated_data.get("is_package"):
            safe_data = {
                "filename": filename,
                "timestamp": timestamp,
                "risk_assessment": risk_assessment,
                "is_package": True,
                "discovered_files": aggregated_data.get("discovered_files", []),
                "analysis_id": aggregated_data.get("analysis_id", "N/A"),
                "tool_version": "1.0.0"
            }
        else:
            safe_data = {
                "filename": filename,
                "timestamp": timestamp,
                "risk_assessment": risk_assessment,
                "key_findings": aggregated_data.get("key_findings", []),
                "modules_run": aggregated_data.get("modules_run", 0),
                "successful_modules": aggregated_data.get("successful_modules", []),
                "analysis_id": aggregated_data.get("analysis_id", "N/A"),
                "tool_version": "1.0.0"
            }
        
        doc_real.subject = json.dumps(safe_data)
        doc_real.build(story_real, canvasmaker=NumberedCanvas)
        
        return report_path

    def build_story_flow(self, aggregated_data: dict, file_path: str, page_map: dict) -> list:
        if aggregated_data.get("is_package"):
            return self.build_package_story_flow(aggregated_data, file_path, page_map)
        story = []
        filename = os.path.basename(file_path)
        
        # Intake/Basic Info
        intake = aggregated_data["results"].get("intake_analysis")
        file_type = "Unknown"
        file_size_bytes = 0
        sha256_val = "Unknown"
        md5_val = "Unknown"
        sha1_val = "Unknown"
        sha512_val = "Unknown"
        created_date = "Unknown"
        modified_date = "Unknown"
        
        if intake and intake.status == "success":
            file_type = intake.findings.get("magic_mime", "Unknown")
            file_size_bytes = intake.findings.get("size_bytes", 0)
            created_date = intake.findings.get("created_timestamp", "Unknown")
            modified_date = intake.findings.get("modified_timestamp", "Unknown")
            hashes = intake.findings.get("hashes", {})
            sha256_val = hashes.get("sha256", "Unknown")
            md5_val = hashes.get("md5", "Unknown")
            sha1_val = hashes.get("sha1", "Unknown")
            sha512_val = hashes.get("sha512", "Unknown")
            
        risk_assessment = aggregated_data.get("risk_assessment", {})
        verdict = risk_assessment.get("verdict", "UNKNOWN")
        score = risk_assessment.get("score", 0)
        
        # Verdict color styling
        verdict_color = "#16a34a" # Green
        if score > 60:
            verdict_color = "#dc2626" # Red
        elif score > 20:
            verdict_color = "#ea580c" # Orange

        # ==================================================
        # 1. COVER PAGE
        # ==================================================
        story.append(Spacer(1, 100))
        story.append(Paragraph("MALWARE ANALYSIS REPORT", self.title_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph("STATIC TRIAGE & SIGNATURE DETECTION", self.subtitle_style))
        story.append(Spacer(1, 40))
        
        # Cover info table
        cover_data = [
            [Paragraph("<b>Analysis Date</b>", self.normal_bold), Paragraph(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.normal)],
            [Paragraph("<b>Sample Name</b>", self.normal_bold), Paragraph(filename, self.normal)],
            [Paragraph("<b>File Type</b>", self.normal_bold), Paragraph(file_type, self.normal)],
            [Paragraph("<b>File Size</b>", self.normal_bold), Paragraph(self.format_size(file_size_bytes), self.normal)],
            [Paragraph("<b>SHA256</b>", self.normal_bold), Paragraph(sha256_val, self.code_style)],
            [Paragraph("<b>Final Verdict</b>", self.normal_bold), Paragraph(f"<font color='{verdict_color}'><b>{verdict}</b></font>", self.normal_bold)],
            [Paragraph("<b>Risk Score</b>", self.normal_bold), Paragraph(f"<b>{score}/100</b>", self.normal_bold)]
        ]
        
        cover_table = Table(cover_data, colWidths=[130, 374])
        cover_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
            ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        
        story.append(cover_table)
        story.append(PageBreak())

        # ==================================================
        # 2. EXECUTIVE SUMMARY
        # ==================================================
        story.append(HeadingTracker("EXECUTIVE_SUMMARY", page_map))
        story.append(Paragraph("1. Executive Summary", self.h1_style))
        
        # Overview Assessment Paragraph
        overall_assessment = ""
        yara_matches = 0
        yara_res = aggregated_data["results"].get("yara_analysis")
        if yara_res and yara_res.status == "success":
            yara_matches = yara_res.findings.get("total_matches", 0)
            
        findings_grouped = self.group_findings_by_severity(aggregated_data)
        suspicious_findings_count = sum(len(lst) for lst in findings_grouped.values())
        
        if score > 60:
            overall_assessment = f"The sample exhibits highly suspicious or malicious characteristics associated with potential threats. Critical/High severity indicators, including matched YARA signatures or specialized API usage, warrant direct quarantine. Execution on production systems is strictly discouraged."
        elif score > 20:
            overall_assessment = f"The sample exhibits multiple indicators associated with process execution and anti-debugging behavior. While no direct malware family was identified, several suspicious characteristics warrant further investigation."
        else:
            overall_assessment = f"Static analysis did not identify any definitive malicious indicators. The sample possesses basic standard characteristics and matches no known security alerts or signatures."
            
        summary_table_data = [
            [Paragraph("<b>Sample Analyzed</b>", self.normal_bold), Paragraph(filename, self.normal)],
            [Paragraph("<b>Risk Score</b>", self.normal_bold), Paragraph(f"<b>{score}/100</b>", self.normal_bold)],
            [Paragraph("<b>Verdict</b>", self.normal_bold), Paragraph(f"<font color='{verdict_color}'><b>{verdict}</b></font>", self.normal_bold)],
            [Paragraph("<b>Total YARA Matches</b>", self.normal_bold), Paragraph(str(yara_matches), self.normal)],
            [Paragraph("<b>Suspicious Findings</b>", self.normal_bold), Paragraph(str(suspicious_findings_count), self.normal)]
        ]
        
        summary_table = Table(summary_table_data, colWidths=[150, 354])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
            ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 15))
        story.append(Paragraph("<b>Overall Assessment:</b>", self.h2_style))
        story.append(Paragraph(overall_assessment, self.normal))
        
        # Dynamic Table of Contents Page
        story.append(PageBreak())
        story.append(Paragraph("Table of Contents", self.h1_style))
        story.append(Spacer(1, 10))
        
        toc_items = [
            ("1. Executive Summary", "EXECUTIVE_SUMMARY"),
            ("2. Risk Overview", "RISK_OVERVIEW"),
            ("3. Key Findings", "KEY_FINDINGS"),
            ("4. YARA Detections", "YARA_DETECTIONS"),
            ("5. Suspicious Imports", "SUSPICIOUS_IMPORTS"),
            ("6. Strings & Indicators", "STRINGS_INDICATORS"),
            ("7. PE Analysis", "PE_ANALYSIS"),
            ("8. Security Mitigations", "SECURITY_MITIGATIONS"),
            ("9. Entropy Analysis", "ENTROPY_ANALYSIS"),
            ("10. Manifest Analysis", "MANIFEST_ANALYSIS"),
            ("11. Sample Information", "SAMPLE_INFORMATION"),
            ("12. Module Execution Summary", "MODULE_EXECUTION_SUMMARY"),
            ("13. Final Verdict", "FINAL_VERDICT"),
            ("14. Recommendations", "RECOMMENDATIONS")
        ]
        
        toc_table_data = []
        for name, key in toc_items:
            page_num_str = str(page_map.get(key, ""))
            # Use visual dot leaders
            toc_table_data.append([
                Paragraph(f"<b>{name}</b>", self.normal),
                Paragraph(". " * 35, ParagraphStyle('LeaderStyle', parent=self.normal, textColor=colors.HexColor("#94a3b8"))),
                Paragraph(page_num_str, ParagraphStyle('RightStyle', parent=self.normal, alignment=2))
            ])
            
        toc_table = Table(toc_table_data, colWidths=[180, 280, 44])
        toc_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'BOTTOM'),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(toc_table)
        story.append(PageBreak())

        # ==================================================
        # 3. RISK OVERVIEW
        # ==================================================
        story.append(HeadingTracker("RISK_OVERVIEW", page_map))
        story.append(Paragraph("2. Risk Overview", self.h1_style))
        story.append(Spacer(1, 5))
        
        risk_overview_data = [
            [Paragraph("<b>Risk Score:</b>", self.normal_bold), Paragraph(f"<b>{score}/100</b>", self.normal_bold)],
            [Paragraph("<b>Severity Level:</b>", self.normal_bold), Paragraph(f"<font color='{verdict_color}'><b>{verdict}</b></font>", self.normal_bold)]
        ]
        
        risk_table = Table(risk_overview_data, colWidths=[150, 354])
        risk_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 10))
        
        story.append(Paragraph("<b>Contributing Factors:</b>", self.h2_style))
        factors = risk_assessment.get("breakdown", [])
        if factors:
            for factor in factors:
                factor_score = factor.get("score", 0)
                factor_desc = factor.get("factor", "Unknown factor")
                story.append(Paragraph(f"• +{factor_score} {factor_desc}", self.bullet_style))
        else:
            story.append(Paragraph("No significant risk factors contributed to the score.", self.normal))
            
        story.append(Spacer(1, 15))

        # ==================================================
        # 4. KEY FINDINGS
        # ==================================================
        story.append(HeadingTracker("KEY_FINDINGS", page_map))
        story.append(Paragraph("3. Key Findings", self.h1_style))
        story.append(Paragraph("Key security indicators categorized by severity level:", self.normal))
        story.append(Spacer(1, 5))
        
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        findings_added = False
        for sev in severities:
            sev_findings = findings_grouped[sev]
            if sev_findings:
                findings_added = True
                sev_color = "#dc2626" if sev in ["CRITICAL", "HIGH"] else ("#ea580c" if sev == "MEDIUM" else "#1e3a8a")
                story.append(Paragraph(f"<b><font color='{sev_color}'>{sev}</font></b>", self.h2_style))
                for f in sev_findings:
                    story.append(Paragraph(f"• {f}", self.bullet_style))
                story.append(Spacer(1, 5))
                
        if not findings_added:
            story.append(Paragraph("No dynamic finding categorization available.", self.normal))
            
        story.append(Spacer(1, 15))

        # ==================================================
        # 5. YARA DETECTIONS
        # ==================================================
        story.append(HeadingTracker("YARA_DETECTIONS", page_map))
        story.append(Paragraph("4. Yara Detections", self.h1_style))
        story.append(Paragraph(f"Total Matched YARA Rules: <b>{yara_matches}</b>", self.normal))
        story.append(Spacer(1, 8))
        
        if yara_res and yara_res.status == "success" and yara_matches > 0:
            yara_data = [[
                Paragraph("<b>Rule Name</b>", self.normal_bold),
                Paragraph("<b>Category</b>", self.normal_bold),
                Paragraph("<b>Severity</b>", self.normal_bold),
                Paragraph("<b>Description</b>", self.normal_bold)
            ]]
            
            for m in yara_res.findings.get("matches", []):
                sev = m.get("severity", "MEDIUM")
                sev_color = "#dc2626" if sev in ["CRITICAL", "HIGH"] else ("#ea580c" if sev == "MEDIUM" else "#1e3a8a")
                yara_data.append([
                    Paragraph(m.get("rule_name", ""), self.normal),
                    Paragraph(m.get("category", ""), self.normal),
                    Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", self.normal),
                    Paragraph(m.get("description", ""), self.normal)
                ])
                
            yara_table = Table(yara_data, colWidths=[120, 100, 70, 214])
            yara_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.bg_light),
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(yara_table)
        else:
            story.append(Paragraph("No YARA rule matches detected.", self.normal))
            
        story.append(Spacer(1, 15))

        # ==================================================
        # 6. SUSPICIOUS IMPORTS
        # ==================================================
        story.append(HeadingTracker("SUSPICIOUS_IMPORTS", page_map))
        story.append(Paragraph("5. Suspicious Imports", self.h1_style))
        
        imp = aggregated_data["results"].get("import_analysis")
        has_suspicious_imports = False
        
        if imp and imp.status == "success":
            imports = imp.findings.get("imports", [])
            
            # Map into groups
            groups = {
                "Process Injection": ["createremotethread", "virtualallocex", "writeprocessmemory"],
                "Process Execution": ["winexec", "shellexecute"],
                "Network Activity": ["internetopen"]
            }
            
            grouped_findings = {g: [] for g in groups}
            
            for f in imports:
                api = f.get("api", "")
                api_lower = api.lower()
                for group_name, apis in groups.items():
                    for target in apis:
                        if target in api_lower:
                            grouped_findings[group_name].append(api)
                            has_suspicious_imports = True
                            
            if has_suspicious_imports:
                for group_name, apis in grouped_findings.items():
                    if apis:
                        story.append(Paragraph(f"<b>{group_name}</b>", self.h2_style))
                        for api in sorted(list(set(apis))):
                            story.append(Paragraph(f"• {api}", self.bullet_style))
                        story.append(Spacer(1, 5))
            
        if not has_suspicious_imports:
            story.append(Paragraph("No suspicious imports detected.", self.normal))
            
        story.append(Spacer(1, 15))

        # ==================================================
        # 7. STRINGS & INDICATORS
        # ==================================================
        story.append(HeadingTracker("STRINGS_INDICATORS", page_map))
        story.append(Paragraph("6. Strings & Indicators", self.h1_style))
        
        str_res = aggregated_data["results"].get("strings_analysis")
        has_indicators = False
        
        if str_res and str_res.status == "success":
            mapping = {
                "URLs": ("urls", "urls"),
                "Domains": ("domains", "domains"),
                "IP Addresses": ("ips", "ipv4"),
                "Email Addresses": ("emails", "emails"),
                "Registry Paths": ("registry", "registry_keys")
            }
            
            for label, (cat, key) in mapping.items():
                raw_list = str_res.findings.get(key, [])
                cleaned_list = clean_strings(raw_list, cat)
                if cleaned_list:
                    has_indicators = True
                    story.append(Paragraph(f"<b>{label}</b>", self.h2_style))
                    for item in cleaned_list:
                        story.append(Paragraph(item, self.code_style))
                    story.append(Spacer(1, 5))
                    
        if not has_indicators:
            story.append(Paragraph("No strings or domain/IP/URL indicators extracted.", self.normal))
            
        story.append(PageBreak())

        # ==================================================
        # 8. PE ANALYSIS
        # ==================================================
        story.append(HeadingTracker("PE_ANALYSIS", page_map))
        story.append(Paragraph("7. PE Analysis", self.h1_style))
        
        pe = aggregated_data["results"].get("pe_analysis")
        if pe and pe.status == "success":
            pe_data = [
                [Paragraph("<b>Machine Type</b>", self.normal_bold), Paragraph(pe.findings.get("machine_type", "Unknown"), self.normal)],
                [Paragraph("<b>Entry Point</b>", self.normal_bold), Paragraph(pe.findings.get("entry_point", "Unknown"), self.code_style)],
                [Paragraph("<b>Compile Timestamp</b>", self.normal_bold), Paragraph(pe.findings.get("compile_timestamp", "Unknown"), self.normal)],
                [Paragraph("<b>Characteristics</b>", self.normal_bold), Paragraph(pe.findings.get("characteristics", "Unknown"), self.code_style)]
            ]
            pe_table = Table(pe_data, colWidths=[150, 354])
            pe_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(pe_table)
        else:
            story.append(Paragraph("PE analysis not run or failed.", self.normal))
            
        story.append(Spacer(1, 15))

        # ==================================================
        # 9. SECURITY MITIGATIONS
        # ==================================================
        story.append(HeadingTracker("SECURITY_MITIGATIONS", page_map))
        story.append(Paragraph("8. Security Mitigations", self.h1_style))
        
        sec = aggregated_data["results"].get("security_analysis")
        if sec and sec.status == "success":
            sec_data = [[
                Paragraph("<b>Mitigation</b>", self.normal_bold),
                Paragraph("<b>Status</b>", self.normal_bold)
            ]]
            
            for mit in ["DEP", "ASLR", "CFG", "SafeSEH"]:
                status = sec.findings.get(mit, "Unknown")
                status_color = "#16a34a" if status == "Enabled" else ("#dc2626" if status == "Disabled" else "#475569")
                sec_data.append([
                    Paragraph(mit, self.normal),
                    Paragraph(f"<font color='{status_color}'><b>{status}</b></font>", self.normal_bold)
                ])
                
            sec_table = Table(sec_data, colWidths=[200, 304])
            sec_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.bg_light),
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(sec_table)
        else:
            story.append(Paragraph("Security mitigation analysis not run or failed.", self.normal))
            
        story.append(Spacer(1, 15))

        # ==================================================
        # 10. ENTROPY ANALYSIS
        # ==================================================
        story.append(HeadingTracker("ENTROPY_ANALYSIS", page_map))
        story.append(Paragraph("9. Entropy Analysis", self.h1_style))
        
        ent = aggregated_data["results"].get("entropy_analysis")
        if ent and ent.status == "success":
            # Filter to show only sections exceeding or highlighting threshold
            ent_data = [[
                Paragraph("<b>Section</b>", self.normal_bold),
                Paragraph("<b>Entropy</b>", self.normal_bold),
                Paragraph("<b>Assessment</b>", self.normal_bold)
            ]]
            
            high_entropy_sections = []
            for sect in ent.findings.get("sections", []):
                ent_val = sect.get("entropy", 0.0)
                is_high = ent_val >= 7.0
                assessment = "Possible Packing / Obfuscation" if is_high else "Normal"
                
                # Check threshold
                if is_high:
                    high_entropy_sections.append(sect)
                    
                ent_data.append([
                    Paragraph(sect["name"], self.normal),
                    Paragraph(f"{ent_val:.4f}", self.normal),
                    Paragraph(f"<font color='#dc2626'><b>{assessment}</b></font>" if is_high else assessment, self.normal)
                ])
                
            ent_table = Table(ent_data, colWidths=[150, 100, 254])
            ent_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.bg_light),
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(ent_table)
            
            if high_entropy_sections:
                story.append(Spacer(1, 8))
                story.append(Paragraph("<b>Note:</b> Sections exceeding entropy threshold of 7.0 indicate high randomness, suggesting code packing or binary compression is present.", self.normal))
        else:
            story.append(Paragraph("Entropy analysis not run or failed.", self.normal))
            
        story.append(Spacer(1, 15))

        # ==================================================
        # 11. MANIFEST ANALYSIS
        # ==================================================
        story.append(HeadingTracker("MANIFEST_ANALYSIS", page_map))
        story.append(Paragraph("10. Manifest Analysis", self.h1_style))
        
        man = aggregated_data["results"].get("manifest_analysis")
        if man and man.status == "success":
            exec_level = man.findings.get("requestedExecutionLevel", "Unknown")
            ui_access = man.findings.get("uiAccess", "Unknown")
            
            privilege_explanation = ""
            if exec_level in ["requireAdministrator", "highestAvailable"]:
                privilege_explanation = "The application requests elevated administrator permissions. This allows it to modify system registry keys, install kernel-mode files, or access system files."
            else:
                privilege_explanation = "The application executes with standard user privileges, restricting direct administration edits."
                
            man_data = [
                [Paragraph("<b>Requested Execution Level</b>", self.normal_bold), Paragraph(exec_level, self.normal)],
                [Paragraph("<b>UI Access</b>", self.normal_bold), Paragraph(ui_access, self.normal)],
                [Paragraph("<b>Privilege Requirements</b>", self.normal_bold), Paragraph(privilege_explanation, self.normal)]
            ]
            man_table = Table(man_data, colWidths=[180, 324])
            man_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(man_table)
        else:
            story.append(Paragraph("No embedded manifest found.", self.normal))
            
        story.append(PageBreak())

        # ==================================================
        # 12. SAMPLE INFORMATION
        # ==================================================
        story.append(HeadingTracker("SAMPLE_INFORMATION", page_map))
        story.append(Paragraph("11. Sample Information", self.h1_style))
        
        sample_info_data = [
            [Paragraph("<b>Filename</b>", self.normal_bold), Paragraph(filename, self.normal)],
            [Paragraph("<b>Extension</b>", self.normal_bold), Paragraph(os.path.splitext(filename)[1], self.normal)],
            [Paragraph("<b>Size</b>", self.normal_bold), Paragraph(f"{self.format_size(file_size_bytes)} ({file_size_bytes} Bytes)", self.normal)],
            [Paragraph("<b>Creation Date</b>", self.normal_bold), Paragraph(created_date, self.normal)],
            [Paragraph("<b>Modified Date</b>", self.normal_bold), Paragraph(modified_date, self.normal)],
            [Paragraph("<b>MD5</b>", self.normal_bold), Paragraph(md5_val, self.code_style)],
            [Paragraph("<b>SHA1</b>", self.normal_bold), Paragraph(sha1_val, self.code_style)],
            [Paragraph("<b>SHA256</b>", self.normal_bold), Paragraph(sha256_val, self.code_style)],
            [Paragraph("<b>SHA512</b>", self.normal_bold), Paragraph(sha512_val, self.code_style)]
        ]
        
        sample_table = Table(sample_info_data, colWidths=[120, 384])
        sample_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
            ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(sample_table)
        story.append(Spacer(1, 15))

        # ==================================================
        # 13. MODULE EXECUTION SUMMARY
        # ==================================================
        story.append(HeadingTracker("MODULE_EXECUTION_SUMMARY", page_map))
        story.append(Paragraph("12. Module Execution Summary", self.h1_style))
        
        mod_data = [[
            Paragraph("<b>Module Name</b>", self.normal_bold),
            Paragraph("<b>Execution Status</b>", self.normal_bold)
        ]]
        
        for mod in aggregated_data.get("successful_modules", []):
            mod_data.append([
                Paragraph(mod, self.normal),
                Paragraph("<font color='#16a34a'><b>SUCCESS</b></font>", self.normal_bold)
            ])
            
        for mod_fail in aggregated_data.get("failed_modules", []):
            err_msg = ", ".join(mod_fail.get("errors", []))
            mod_data.append([
                Paragraph(mod_fail.get("module", ""), self.normal),
                Paragraph(f"<font color='#dc2626'><b>FAILED</b></font> ({err_msg})", self.normal_bold)
            ])
            
        mod_table = Table(mod_data, colWidths=[200, 304])
        mod_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.bg_light),
            ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(mod_table)
        story.append(Spacer(1, 15))

        # ==================================================
        # 14. FINAL VERDICT
        # ==================================================
        story.append(HeadingTracker("FINAL_VERDICT", page_map))
        story.append(Paragraph("13. Final Verdict", self.h1_style))
        
        # Highlighted verdict box
        verdict_para = f"""
        <b>Risk Score:</b> {score}/100<br/>
        <b>Severity Level:</b> {verdict}<br/>
        <b>Verdict:</b> {verdict}
        """
        
        verdict_cell = [
            Paragraph(verdict_para, ParagraphStyle('VerdStyle', parent=self.normal, fontSize=11, leading=16)),
            Spacer(1, 8),
            Paragraph(overall_assessment, self.normal)
        ]
        
        verdict_box_table = Table([[verdict_cell]], colWidths=[504])
        verdict_box_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#fee2e2") if score > 60 else (colors.HexColor("#ffedd5") if score > 20 else colors.HexColor("#dcfce7"))),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#fca5a5") if score > 60 else (colors.HexColor("#fed7aa") if score > 20 else colors.HexColor("#86efac"))),
            ('PADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(verdict_box_table)
        story.append(Spacer(1, 15))

        # ==================================================
        # 15. RECOMMENDATIONS
        # ==================================================
        story.append(HeadingTracker("RECOMMENDATIONS", page_map))
        story.append(Paragraph("14. Recommendations", self.h1_style))
        
        if score > 60:
            story.append(Paragraph("<b>HIGH RISK Action Plan:</b>", self.h2_style))
            story.append(Paragraph("• Do not execute on production systems", self.bullet_style))
            story.append(Paragraph("• Perform dynamic analysis", self.bullet_style))
            story.append(Paragraph("• Isolate the sample", self.bullet_style))
            story.append(Paragraph("• Review extracted indicators", self.bullet_style))
        elif score > 20:
            story.append(Paragraph("<b>MEDIUM RISK Action Plan:</b>", self.h2_style))
            story.append(Paragraph("• Proceed with caution", self.bullet_style))
            story.append(Paragraph("• Investigate suspicious findings", self.bullet_style))
            story.append(Paragraph("• Monitor behavior if executed", self.bullet_style))
        else:
            story.append(Paragraph("<b>LOW RISK Action Plan:</b>", self.h2_style))
            story.append(Paragraph("• Verify source authenticity", self.bullet_style))
            story.append(Paragraph("• Continue standard monitoring", self.bullet_style))
            
        return story

    def build_package_story_flow(self, aggregated_data: dict, file_path: str, page_map: dict) -> list:
        story = []
        filename = os.path.basename(file_path)
        
        archive_name = aggregated_data.get("archive_name", filename)
        archive_size = aggregated_data.get("archive_size", 0)
        discovered_files = aggregated_data.get("discovered_files", [])
        files_extracted = len(discovered_files)
        extraction_depth = aggregated_data.get("extraction_depth", 1)
        
        risk_assessment = aggregated_data.get("risk_assessment", {})
        verdict = risk_assessment.get("verdict", "UNKNOWN")
        score = risk_assessment.get("score", 0)
        highest_risk_file = risk_assessment.get("highest_risk_file", "None")
        
        # Verdict color styling
        verdict_color = "#16a34a" # Green
        if score > 60:
            verdict_color = "#dc2626" # Red
        elif score > 20:
            verdict_color = "#ea580c" # Orange
            
        # ==================================================
        # 1. COVER PAGE
        # ==================================================
        story.append(Spacer(1, 100))
        story.append(Paragraph("PACKAGE ANALYSIS REPORT", self.title_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph("CONTAINER STATIC ANALYSIS & TRIAGE", self.subtitle_style))
        story.append(Spacer(1, 40))
        
        cover_data = [
            [Paragraph("<b>Analysis Date</b>", self.normal_bold), Paragraph(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.normal)],
            [Paragraph("<b>Archive Name</b>", self.normal_bold), Paragraph(archive_name, self.normal)],
            [Paragraph("<b>Archive Size</b>", self.normal_bold), Paragraph(self.format_size(archive_size), self.normal)],
            [Paragraph("<b>Files Extracted</b>", self.normal_bold), Paragraph(str(files_extracted), self.normal)],
            [Paragraph("<b>Extraction Depth</b>", self.normal_bold), Paragraph(str(extraction_depth), self.normal)],
            [Paragraph("<b>Package Verdict</b>", self.normal_bold), Paragraph(f"<font color='{verdict_color}'><b>{verdict}</b></font>", self.normal_bold)],
            [Paragraph("<b>Package Risk Score</b>", self.normal_bold), Paragraph(f"<b>{score}/100</b>", self.normal_bold)]
        ]
        
        cover_table = Table(cover_data, colWidths=[150, 354])
        cover_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
            ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        
        story.append(cover_table)
        story.append(PageBreak())
        
        # ==================================================
        # 2. EXECUTIVE SUMMARY
        # ==================================================
        story.append(HeadingTracker("EXECUTIVE_SUMMARY", page_map))
        story.append(Paragraph("1. Executive Summary", self.h1_style))
        
        if score > 60:
            overall_assessment = f"The package contains one or more files with critical or high-risk static findings. The highest risk file is '{highest_risk_file}' with a score of {score}. Direct execution of extracted contents is strongly discouraged."
        elif score > 20:
            overall_assessment = f"The package contains files with moderate risk findings. Proceed with caution and perform isolated testing before execution."
        else:
            overall_assessment = f"No significant static analysis threats were identified inside the package files. All discovered executables have low risk scores."
            
        summary_table_data = [
            [Paragraph("<b>Archive Name</b>", self.normal_bold), Paragraph(archive_name, self.normal)],
            [Paragraph("<b>Package Risk Score</b>", self.normal_bold), Paragraph(f"<b>{score}/100</b>", self.normal_bold)],
            [Paragraph("<b>Verdict</b>", self.normal_bold), Paragraph(f"<font color='{verdict_color}'><b>{verdict}</b></font>", self.normal_bold)],
            [Paragraph("<b>Highest Risk File</b>", self.normal_bold), Paragraph(highest_risk_file, self.normal)],
            [Paragraph("<b>Total Files Extracted</b>", self.normal_bold), Paragraph(str(files_extracted), self.normal)]
        ]
        
        summary_table = Table(summary_table_data, colWidths=[150, 354])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
            ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 15))
        story.append(Paragraph("<b>Overall Assessment:</b>", self.h2_style))
        story.append(Paragraph(overall_assessment, self.normal))
        
        # Table of Contents
        story.append(PageBreak())
        story.append(Paragraph("Table of Contents", self.h1_style))
        story.append(Spacer(1, 10))
        
        toc_items = [
            ("1. Executive Summary", "EXECUTIVE_SUMMARY"),
            ("2. Package Details & Extraction", "PACKAGE_DETAILS"),
            ("3. Discovered Files & Lineage", "DISCOVERED_FILES_LIST"),
            ("4. Package Verdict & Risk Overview", "PACKAGE_VERDICT_RISK")
        ]
        
        targets = aggregated_data.get("analysis_targets", {}).get("targets", [])
        for idx, target in enumerate(targets, 1):
            toc_items.append((f"5.{idx} Analysis: {target['filename']}", f"TARGET_ANALYSIS_{idx}"))
            
        toc_table_data = []
        for name, key in toc_items:
            page_num_str = str(page_map.get(key, ""))
            toc_table_data.append([
                Paragraph(f"<b>{name}</b>", self.normal),
                Paragraph(". " * 35, ParagraphStyle('LeaderStyle', parent=self.normal, textColor=colors.HexColor("#94a3b8"))),
                Paragraph(page_num_str, ParagraphStyle('RightStyle', parent=self.normal, alignment=2))
            ])
            
        toc_table = Table(toc_table_data, colWidths=[200, 260, 44])
        toc_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'BOTTOM'),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(toc_table)
        story.append(PageBreak())
        
        # ==================================================
        # 3. PACKAGE DETAILS & EXTRACTION
        # ==================================================
        story.append(HeadingTracker("PACKAGE_DETAILS", page_map))
        story.append(Paragraph("2. Package Details & Extraction", self.h1_style))
        story.append(Spacer(1, 10))
        
        details_data = [
            [Paragraph("<b>Archive Name</b>", self.normal_bold), Paragraph(archive_name, self.normal)],
            [Paragraph("<b>Archive Size</b>", self.normal_bold), Paragraph(self.format_size(archive_size), self.normal)],
            [Paragraph("<b>Files Extracted</b>", self.normal_bold), Paragraph(str(files_extracted), self.normal)],
            [Paragraph("<b>Extraction Depth Limit</b>", self.normal_bold), Paragraph("3", self.normal)],
            [Paragraph("<b>Actual Depth Reached</b>", self.normal_bold), Paragraph(str(extraction_depth), self.normal)]
        ]
        details_table = Table(details_data, colWidths=[180, 324])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
            ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(details_table)
        story.append(Spacer(1, 15))
        
        # ==================================================
        # 4. DISCOVERED FILES & LINEAGE
        # ==================================================
        story.append(HeadingTracker("DISCOVERED_FILES_LIST", page_map))
        story.append(Paragraph("3. Discovered Files & Lineage", self.h1_style))
        story.append(Spacer(1, 5))
        
        if targets:
            files_data = [[
                Paragraph("<b>Filename</b>", self.normal_bold),
                Paragraph("<b>Size</b>", self.normal_bold),
                Paragraph("<b>Lineage Path</b>", self.normal_bold)
            ]]
            for target in targets:
                lineage_str = " -> ".join(target.get("lineage", []))
                files_data.append([
                    Paragraph(target.get("filename", ""), self.normal),
                    Paragraph(self.format_size(target.get("size", 0)), self.normal),
                    Paragraph(lineage_str, self.normal)
                ])
            files_table = Table(files_data, colWidths=[150, 80, 274])
            files_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.bg_light),
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(files_table)
        else:
            story.append(Paragraph("No executable files (.exe, .dll) discovered in the archive.", self.normal))
            
        story.append(Spacer(1, 15))
        
        # ==================================================
        # 5. PACKAGE VERDICT & RISK
        # ==================================================
        story.append(HeadingTracker("PACKAGE_VERDICT_RISK", page_map))
        story.append(Paragraph("4. Package Verdict & Risk Overview", self.h1_style))
        story.append(Spacer(1, 5))
        
        verdict_para = f"""
        <b>Package Risk Score:</b> {score}/100<br/>
        <b>Verdict:</b> {verdict}<br/>
        <b>Highest Risk File:</b> {highest_risk_file}
        """
        
        verdict_cell = [
            Paragraph(verdict_para, ParagraphStyle('PackageVerdStyle', parent=self.normal, fontSize=11, leading=16)),
            Spacer(1, 8),
            Paragraph(overall_assessment, self.normal)
        ]
        
        verdict_box_table = Table([[verdict_cell]], colWidths=[504])
        verdict_box_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#fee2e2") if score > 60 else (colors.HexColor("#ffedd5") if score > 20 else colors.HexColor("#dcfce7"))),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#fca5a5") if score > 60 else (colors.HexColor("#fed7aa") if score > 20 else colors.HexColor("#86efac"))),
            ('PADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(verdict_box_table)
        story.append(PageBreak())
        
        # ==================================================
        # 6. EXECUTABLE ANALYSIS RESULTS
        # ==================================================
        story.append(Paragraph("5. Executable Analysis Results", self.h1_style))
        story.append(Paragraph("Detailed static analysis results for each discovered executable file:", self.normal))
        story.append(Spacer(1, 10))
        
        for idx, target in enumerate(targets, 1):
            story.append(HeadingTracker(f"TARGET_ANALYSIS_{idx}", page_map))
            story.append(Paragraph(f"5.{idx} {target['filename']}", self.h1_style))
            
            res_data = target.get("analysis_results", {})
            t_risk = res_data.get("risk_assessment", {})
            t_score = t_risk.get("score", 0)
            t_verdict = t_risk.get("verdict", "UNKNOWN")
            
            t_verdict_color = "#16a34a" # Green
            if t_score > 60:
                t_verdict_color = "#dc2626"
            elif t_score > 20:
                t_verdict_color = "#ea580c"
                
            lineage_str = " -> ".join(target.get("lineage", []))
            
            info_data = [
                [Paragraph("<b>Risk Score</b>", self.normal_bold), Paragraph(f"<b>{t_score}/100</b>", self.normal_bold)],
                [Paragraph("<b>Verdict</b>", self.normal_bold), Paragraph(f"<font color='{t_verdict_color}'><b>{t_verdict}</b></font>", self.normal_bold)],
                [Paragraph("<b>Lineage Path</b>", self.normal_bold), Paragraph(lineage_str, self.normal)],
                [Paragraph("<b>SHA256</b>", self.normal_bold), Paragraph(target.get("sha256", ""), self.code_style)]
            ]
            info_table = Table(info_data, colWidths=[130, 374])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(info_table)
            story.append(Spacer(1, 10))
            
            story.append(Paragraph("<b>Key Findings</b>", self.h2_style))
            key_findings = res_data.get("key_findings", [])
            if key_findings:
                for kf in key_findings:
                    story.append(Paragraph(f"• {kf}", self.bullet_style))
            else:
                story.append(Paragraph("No significant high/critical findings.", self.normal))
            story.append(Spacer(1, 8))
            
            story.append(Paragraph("<b>YARA Matches</b>", self.h2_style))
            yara_analysis = res_data.get("results", {}).get("yara_analysis", {})
            yara_matches = []
            if isinstance(yara_analysis, dict):
                yara_matches = yara_analysis.get("findings", {}).get("matches", [])
            elif hasattr(yara_analysis, "findings"):
                yara_matches = yara_analysis.findings.get("matches", [])
                
            if yara_matches:
                yara_tbl_data = [[
                    Paragraph("<b>Rule Name</b>", self.normal_bold),
                    Paragraph("<b>Severity</b>", self.normal_bold),
                    Paragraph("<b>Description</b>", self.normal_bold)
                ]]
                for m in yara_matches:
                    m_sev = m.get("severity", "MEDIUM")
                    m_sev_color = "#dc2626" if m_sev in ["CRITICAL", "HIGH"] else ("#ea580c" if m_sev == "MEDIUM" else "#1e3a8a")
                    yara_tbl_data.append([
                        Paragraph(m.get("rule_name", ""), self.normal),
                        Paragraph(f"<font color='{m_sev_color}'><b>{m_sev}</b></font>", self.normal),
                        Paragraph(m.get("description", ""), self.normal)
                    ])
                yara_table = Table(yara_tbl_data, colWidths=[150, 80, 274])
                yara_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self.bg_light),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                    ('PADDING', (0, 0), (-1, -1), 5),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                story.append(yara_table)
            else:
                story.append(Paragraph("No YARA rule matches detected.", self.normal))
            story.append(Spacer(1, 8))
                
            story.append(Paragraph("<b>Entropy Findings</b>", self.h2_style))
            entropy_analysis = res_data.get("results", {}).get("entropy_analysis", {})
            high_entropy_sections = []
            if isinstance(entropy_analysis, dict):
                high_entropy_sections = [
                    s for s in entropy_analysis.get("findings", {}).get("sections", [])
                    if s.get("entropy", 0.0) >= 7.0
                ]
            elif hasattr(entropy_analysis, "findings"):
                high_entropy_sections = [
                    s for s in entropy_analysis.findings.get("sections", [])
                    if s.get("entropy", 0.0) >= 7.0
                ]
                
            if high_entropy_sections:
                for sect in high_entropy_sections:
                    story.append(Paragraph(f"• Section <b>{sect['name']}</b> has high entropy: <b>{sect['entropy']:.4f}</b> (possible packing/obfuscation).", self.bullet_style))
            else:
                story.append(Paragraph("No high entropy sections (>7.0) detected.", self.normal))
                
            if idx < len(targets):
                story.append(Spacer(1, 15))
                story.append(Paragraph("<font color='#cbd5e1'>______________________________________________________________________________________</font>", self.normal))
                story.append(PageBreak())
                
        return story

    def build_dynamic_story_flow(self, dynamic_data: dict, file_path: str, page_map: dict) -> list:
        story = []
        filename = os.path.basename(file_path)
        analysis_id = dynamic_data.get("analysis_id", "N/A")
        
        processes = dynamic_data.get("processes", [])
        files = dynamic_data.get("files", [])
        registry = dynamic_data.get("registry", [])
        network = dynamic_data.get("network", [])
        findings = dynamic_data.get("findings", [])
        
        # Calculate dynamic severity
        has_critical = any(f.get("severity") == "CRITICAL" for f in findings)
        has_high = any(f.get("severity") == "HIGH" for f in findings)
        has_medium = any(f.get("severity") == "MEDIUM" for f in findings)
        
        if has_critical:
            verdict = "CRITICAL RISK"
            score = 90
            verdict_color = "#dc2626"
        elif has_high:
            verdict = "HIGH RISK"
            score = 75
            verdict_color = "#dc2626"
        elif has_medium:
            verdict = "MEDIUM RISK"
            score = 50
            verdict_color = "#ea580c"
        else:
            verdict = "LOW RISK"
            score = 25
            verdict_color = "#16a34a"

        # ==================================================
        # 1. COVER PAGE
        # ==================================================
        story.append(Spacer(1, 100))
        story.append(Paragraph("DYNAMIC ANALYSIS REPORT", self.title_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph("SANDBOX BEHAVIORAL ANALYSIS & THREAT DETECTION", self.subtitle_style))
        story.append(Spacer(1, 40))
        
        cover_data = [
            [Paragraph("<b>Analysis Date</b>", self.normal_bold), Paragraph(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.normal)],
            [Paragraph("<b>Sample Name</b>", self.normal_bold), Paragraph(filename, self.normal)],
            [Paragraph("<b>Analysis ID</b>", self.normal_bold), Paragraph(analysis_id, self.code_style)],
            [Paragraph("<b>Analysis Type</b>", self.normal_bold), Paragraph("Sandbox Dynamic Run", self.normal)],
            [Paragraph("<b>Tool Version</b>", self.normal_bold), Paragraph("1.0.0", self.normal)],
            [Paragraph("<b>Final Verdict</b>", self.normal_bold), Paragraph(f"<font color='{verdict_color}'><b>{verdict}</b></font>", self.normal_bold)],
            [Paragraph("<b>Risk Score</b>", self.normal_bold), Paragraph(f"<b>{score}/100</b>", self.normal_bold)]
        ]
        
        cover_table = Table(cover_data, colWidths=[150, 354])
        cover_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
            ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        
        story.append(cover_table)
        story.append(PageBreak())

        # ==================================================
        # 2. EXECUTIVE SUMMARY & TOC
        # ==================================================
        story.append(HeadingTracker("EXECUTIVE_SUMMARY", page_map))
        story.append(Paragraph("1. Executive Summary", self.h1_style))
        
        overall_assessment = f"Dynamic execution of the sample in an isolated Windows 10 environment recorded {len(processes)} processes, {len(files)} file modifications, {len(registry)} registry operations, and {len(network)} network events. The behavioral engine generated {len(findings)} security findings."
        
        summary_table_data = [
            [Paragraph("<b>Sample Analyzed</b>", self.normal_bold), Paragraph(filename, self.normal)],
            [Paragraph("<b>Risk Score</b>", self.normal_bold), Paragraph(f"<b>{score}/100</b>", self.normal_bold)],
            [Paragraph("<b>Verdict</b>", self.normal_bold), Paragraph(f"<font color='{verdict_color}'><b>{verdict}</b></font>", self.normal_bold)],
            [Paragraph("<b>Behavioral Findings</b>", self.normal_bold), Paragraph(str(len(findings)), self.normal)]
        ]
        
        summary_table = Table(summary_table_data, colWidths=[150, 354])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
            ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 15))
        story.append(Paragraph("<b>Overall Assessment:</b>", self.h2_style))
        story.append(Paragraph(overall_assessment, self.normal))
        
        # TOC Page
        story.append(PageBreak())
        story.append(Paragraph("Table of Contents", self.h1_style))
        story.append(Spacer(1, 10))
        
        toc_items = [
            ("1. Executive Summary", "EXECUTIVE_SUMMARY"),
            ("2. Behavioral Findings", "BEHAVIORAL_FINDINGS"),
            ("3. Process Activity", "PROCESS_ACTIVITY"),
            ("4. File Activity", "FILE_ACTIVITY"),
            ("5. Registry Activity", "REGISTRY_ACTIVITY"),
            ("6. Dropped / Loaded DLLs", "DLL_ACTIVITY"),
            ("7. Network Activity", "NETWORK_ACTIVITY")
        ]
        
        toc_table_data = []
        for name, key in toc_items:
            page_num_str = str(page_map.get(key, ""))
            toc_table_data.append([
                Paragraph(f"<b>{name}</b>", self.normal),
                Paragraph(". " * 35, ParagraphStyle('LeaderStyle', parent=self.normal, textColor=colors.HexColor("#94a3b8"))),
                Paragraph(page_num_str, ParagraphStyle('RightStyle', parent=self.normal, alignment=2))
            ])
            
        toc_table = Table(toc_table_data, colWidths=[200, 260, 44])
        toc_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'BOTTOM'),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(toc_table)
        story.append(PageBreak())

        # ==================================================
        # 3. BEHAVIORAL FINDINGS (MUST APPEAR BEFORE RAW EVIDENCE)
        # ==================================================
        story.append(HeadingTracker("BEHAVIORAL_FINDINGS", page_map))
        story.append(Paragraph("2. Behavioral Findings", self.h1_style))
        
        if findings:
            for f in findings:
                f_sev = f.get("severity", "MEDIUM")
                f_sev_color = "#dc2626" if f_sev in ["CRITICAL", "HIGH"] else ("#ea580c" if f_sev == "MEDIUM" else "#1e3a8a")
                
                finding_text = f"""
                <b>Finding:</b> {f.get('name')}<br/>
                <b>Category:</b> {f.get('category')}<br/>
                <b>Severity:</b> <font color='{f_sev_color}'><b>{f_sev}</b></font><br/>
                <b>Evidence:</b> {f.get('evidence')}<br/>
                <b>Description:</b> {f.get('description')}
                """
                
                finding_box_table = Table([[Paragraph(finding_text, self.normal)]], colWidths=[504])
                finding_box_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor(f_sev_color)),
                    ('PADDING', (0, 0), (-1, -1), 8),
                ]))
                story.append(finding_box_table)
                story.append(Spacer(1, 10))
        else:
            story.append(Paragraph("No behavioral findings were generated by the rule engine.", self.normal))
        
        story.append(PageBreak())

        # ==================================================
        # 4. PROCESS ACTIVITY
        # ==================================================
        story.append(HeadingTracker("PROCESS_ACTIVITY", page_map))
        story.append(Paragraph("3. Process Activity", self.h1_style))
        
        if processes:
            proc_data = [[
                Paragraph("<b>Name</b>", self.normal_bold),
                Paragraph("<b>PID</b>", self.normal_bold),
                Paragraph("<b>Parent PID</b>", self.normal_bold),
                Paragraph("<b>Command Line</b>", self.normal_bold)
            ]]
            for p in processes:
                proc_data.append([
                    Paragraph(p.get("name", "Unknown"), self.normal),
                    Paragraph(str(p.get("pid")), self.normal),
                    Paragraph(str(p.get("parent_pid")), self.normal),
                    Paragraph(p.get("command_line", ""), self.code_style)
                ])
            proc_table = Table(proc_data, colWidths=[110, 50, 60, 284])
            proc_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.bg_light),
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(proc_table)
        else:
            story.append(Paragraph("No process activity recorded.", self.normal))
            
        story.append(PageBreak())

        # ==================================================
        # 5. FILE ACTIVITY
        # ==================================================
        story.append(HeadingTracker("FILE_ACTIVITY", page_map))
        story.append(Paragraph("4. File Activity", self.h1_style))
        
        # Compute File System Counts
        fs_created_cnt = 0
        fs_deleted_cnt = 0
        fs_modified_cnt = 0

        if "file_system_monitoring" in dynamic_data:
            fs_data = dynamic_data.get("file_system_monitoring", {})
            fs_created_cnt = len(fs_data.get("files_created", []))
            fs_deleted_cnt = len(fs_data.get("files_deleted", []))
            fs_modified_cnt = len(fs_data.get("files_modified", [])) + len(fs_data.get("files_renamed", []))
        elif files:
            for f in files:
                act = f.get("action", "").upper()
                if "CREAT" in act or "DROP" in act or "NEW" in act:
                    fs_created_cnt += 1
                elif "DELET" in act:
                    fs_deleted_cnt += 1
                elif "MODIFY" in act or "WRIT" in act or "RENAM" in act:
                    fs_modified_cnt += 1
                else:
                    fs_modified_cnt += 1

        if files:
            story.append(Paragraph(
                f"Summary of file system activity: <b>{fs_created_cnt}</b> created, <b>{fs_modified_cnt}</b> modified, and <b>{fs_deleted_cnt}</b> deleted.",
                self.normal
            ))
            story.append(Spacer(1, 8))

            file_data = [[
                Paragraph("<b>Action</b>", self.normal_bold),
                Paragraph("<b>Path</b>", self.normal_bold),
                Paragraph("<b>Type Classification</b>", self.normal_bold)
            ]]
            for f in files:
                file_data.append([
                    Paragraph(f.get("action", "").upper(), self.normal),
                    Paragraph(f.get("path", ""), self.code_style),
                    Paragraph(f.get("category", "Other"), self.normal)
                ])
            file_table = Table(file_data, colWidths=[80, 324, 100])
            file_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.bg_light),
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(file_table)
        else:
            story.append(Paragraph("No file system activity recorded.", self.normal))
            
        story.append(Spacer(1, 15))

        # ==================================================
        # 6. REGISTRY ACTIVITY
        # ==================================================
        story.append(HeadingTracker("REGISTRY_ACTIVITY", page_map))
        story.append(Paragraph("5. Registry Activity", self.h1_style))
        
        # Compute Registry Counts
        reg_created_cnt = 0
        reg_deleted_cnt = 0
        reg_modified_cnt = 0

        if "registry_monitoring" in dynamic_data:
            reg_mon_data = dynamic_data.get("registry_monitoring", {})
            reg_created_cnt = len(reg_mon_data.get("values_added", []))
            reg_deleted_cnt = len(reg_mon_data.get("keys_deleted", [])) + len(reg_mon_data.get("values_deleted", []))
            reg_modified_cnt = len(reg_mon_data.get("values_modified", []))
        elif registry:
            for r in registry:
                act = r.get("action", "").upper()
                if "CREAT" in act or "ADD" in act or "WRITE" in act:
                    reg_created_cnt += 1
                elif "DELET" in act:
                    reg_deleted_cnt += 1
                elif "MODIFY" in act or "MUTAT" in act:
                    reg_modified_cnt += 1
                else:
                    reg_modified_cnt += 1

        if registry:
            story.append(Paragraph(
                f"Summary of registry activity: <b>{reg_created_cnt}</b> created/added, <b>{reg_modified_cnt}</b> modified, and <b>{reg_deleted_cnt}</b> deleted.",
                self.normal
            ))
            story.append(Spacer(1, 8))

            reg_table_data = [[
                Paragraph("<b>Action</b>", self.normal_bold),
                Paragraph("<b>Registry Path</b>", self.normal_bold)
            ]]
            for r in registry:
                reg_table_data.append([
                    Paragraph(r.get("action", "").upper(), self.normal),
                    Paragraph(r.get("path", ""), self.code_style)
                ])
            reg_table = Table(reg_table_data, colWidths=[100, 404])
            reg_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.bg_light),
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(reg_table)
        else:
            story.append(Paragraph("No registry activity recorded.", self.normal))
            
        story.append(Spacer(1, 15))

        # ==================================================
        # 6b. DROPPED / LOADED DLLs
        # ==================================================
        dll_info = dynamic_data.get("dll_signature_monitoring", {})
        dll_details = dll_info.get("details", [])

        story.append(HeadingTracker("DLL_ACTIVITY", page_map))
        story.append(Paragraph("6. Dropped / Loaded DLLs", self.h1_style))

        unsigned_count = dll_info.get("unsigned_dlls_count", 0)
        if unsigned_count:
            story.append(Paragraph(
                f"<font color='#dc2626'><b>{unsigned_count} unsigned DLL(s)</b></font> detected during execution.",
                self.normal
            ))
            story.append(Spacer(1, 8))

        if dll_details:
            dll_table_data = [[
                Paragraph("<b>DLL Name</b>", self.normal_bold),
                Paragraph("<b>Path</b>", self.normal_bold),
                Paragraph("<b>Signature</b>", self.normal_bold),
                Paragraph("<b>Risk Indicators</b>", self.normal_bold),
            ]]
            for dll in dll_details:
                sig_status = dll.get("signature_status", "UNKNOWN")
                sig_color = "#dc2626" if sig_status == "UNSIGNED" else "#16a34a"
                risk_text = ", ".join(dll.get("risk_indicators", [])) or "None"
                
                dll_name = dll.get("dll_name", "Unknown")
                if sig_status == "UNSIGNED":
                    name_p = Paragraph(f"<font color='#dc2626'><b>[!] {dll_name}</b></font>", self.normal_bold)
                else:
                    name_p = Paragraph(dll_name, self.normal)

                dll_table_data.append([
                    name_p,
                    Paragraph(dll.get("dll_path", "N/A"), self.code_style),
                    Paragraph(f"<font color='{sig_color}'><b>{sig_status}</b></font>", self.normal),
                    Paragraph(risk_text, self.normal),
                ])

            dll_table = Table(dll_table_data, colWidths=[90, 190, 74, 150])
            dll_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.bg_light),
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(dll_table)

            # SHA256 detail sub-table
            story.append(Spacer(1, 8))
            story.append(Paragraph("<b>DLL Hashes</b>", self.h2_style))
            hash_data = [[
                Paragraph("<b>DLL Name</b>", self.normal_bold),
                Paragraph("<b>SHA256</b>", self.normal_bold),
            ]]
            for dll in dll_details:
                hash_data.append([
                    Paragraph(dll.get("dll_name", "Unknown"), self.normal),
                    Paragraph(dll.get("sha256", "N/A"), self.code_style),
                ])
            hash_table = Table(hash_data, colWidths=[120, 384])
            hash_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.bg_light),
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(hash_table)
        else:
            story.append(Paragraph("No DLLs were dropped or loaded during execution.", self.normal))

        story.append(Spacer(1, 15))

        # ==================================================
        # 7. NETWORK ACTIVITY
        # ==================================================
        story.append(HeadingTracker("NETWORK_ACTIVITY", page_map))
        story.append(Paragraph("7. Network Activity", self.h1_style))
        
        if network:
            net_data = [[
                Paragraph("<b>DNS Query</b>", self.normal_bold),
                Paragraph("<b>Dest IP</b>", self.normal_bold),
                Paragraph("<b>Port</b>", self.normal_bold),
                Paragraph("<b>Protocol</b>", self.normal_bold),
                Paragraph("<b>Attempts</b>", self.normal_bold)
            ]]
            for n in network:
                net_data.append([
                    Paragraph(n.get("dns_query") or "N/A", self.normal),
                    Paragraph(n.get("dest_ip") or "N/A", self.normal),
                    Paragraph(str(n.get("dest_port") or "N/A"), self.normal),
                    Paragraph(n.get("protocol", "TCP"), self.normal),
                    Paragraph(str(n.get("connection_attempts", 1)), self.normal)
                ])
            net_table = Table(net_data, colWidths=[150, 114, 60, 100, 80])
            net_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.bg_light),
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(net_table)
        else:
            story.append(Paragraph("No network activity recorded.", self.normal))
            
        return story

