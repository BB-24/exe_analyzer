"""
MARS — Report Generator (ReportLab · format matching pdf_generator.py)
"""

import os
import re
import datetime
import json
from pubsub import pub

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Flowable, Image, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

# ═══════════════════════════════════════════════════════════════════════════
# NUMBERED CANVAS (matching pdf_generator.py)
# ═══════════════════════════════════════════════════════════════════════════
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


# ═══════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
def _safe(v) -> str:
    return str(v).encode("latin-1", "replace").decode("latin-1")


def _clean_hash(v: str) -> str:
    v = v.strip()
    half = len(v) // 2
    if half >= 32 and v[:half] == v[half:]:
        v = v[:half]
    if len(v) > 64:
        v = v[:64]
    return v


def _is_hash_key(key: str) -> bool:
    k = key.upper()
    return any(tok in k for tok in ("SHA", "MD5", "HASH"))


def _resolve_filename(meta: dict) -> str:
    for key in ("Original File Name", "Filename", "filename"):
        v = str(meta.get(key) or "").strip()
        if v and v not in ("N/A", "?", ""):
            return v
    return "Unknown Sample"


def clean_strings(str_list, category):
    cleaned = []
    for s in str_list:
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
        elif category == "registry":
            if s.upper().startswith(("HKLM", "HKCU", "HKEY_")):
                cleaned.append(s)
    return sorted(list(set(cleaned)))[:10]


# ═══════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════
class ReportGenerator:
    def __init__(self, config: dict):
        self.reports_dir = config.get("system", {}).get("reports_dir", "./workspace/reports")
        os.makedirs(self.reports_dir, exist_ok=True)
        
        self.styles = getSampleStyleSheet()
        self.primary_color = colors.HexColor("#1e3a8a") # Dark Blue
        self.secondary_color = colors.HexColor("#0f172a") # Dark Slate
        self.text_color = colors.HexColor("#1e293b")
        self.bg_light = colors.HexColor("#f8fafc")
        self.border_color = colors.HexColor("#e2e8f0")
        
        self.normal = ParagraphStyle('ReportNormal', parent=self.styles['Normal'], textColor=self.text_color, fontSize=9, leading=13)
        self.normal_bold = ParagraphStyle('ReportNormalBold', parent=self.normal, fontName='Helvetica-Bold')
        self.code_style = ParagraphStyle('ReportCode', parent=self.normal, fontName='Courier', fontSize=8, leading=10, wordWrap='CJK')
        
        self.title_style = ParagraphStyle('ReportTitle', fontName='Helvetica-Bold', fontSize=24, leading=28, textColor=self.primary_color, alignment=1)
        self.subtitle_style = ParagraphStyle('ReportSubtitle', fontName='Helvetica', fontSize=12, leading=16, textColor=colors.HexColor("#475569"), alignment=1)
        
        self.h1_style = ParagraphStyle('ReportH1', fontName='Helvetica-Bold', fontSize=14, leading=18, textColor=self.primary_color, spaceBefore=12, spaceAfter=8, keepWithNext=True)
        self.h2_style = ParagraphStyle('ReportH2', fontName='Helvetica-Bold', fontSize=11, leading=15, textColor=self.secondary_color, spaceBefore=8, spaceAfter=4, keepWithNext=True)
        self.bullet_style = ParagraphStyle('ReportBullet', parent=self.normal, leftIndent=15, bulletIndent=5, spaceAfter=3)

    def format_size(self, size_bytes):
        if not size_bytes:
            return "0 Bytes"
        try:
            size_bytes = float(size_bytes)
        except Exception:
            return str(size_bytes)
        for unit in ['Bytes', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"

    def generate_reports(
        self,
        metadata:        dict,
        package_data:    list,
        static_data:     dict,
        dynamic_data:    dict | None = None,
        dynamic_summary: dict | None = None,
        scoring_results: dict | None = None,
    ):
        pub.sendMessage("gui.log", msg="\n[*] --- Starting Reporting Module ---")
        analysis_id = metadata.get("Analysis ID", f"MARS_UNKNOWN_{datetime.datetime.now().strftime('%H%M%S')}")
        base = os.path.join(self.reports_dir, f"{analysis_id}_Report")
        scoring_results = scoring_results or {}

        compiled = {
            "Analysis_Summary":         metadata,
            "Package_Extraction":       package_data,
            "Static_Analysis_Results":  static_data,
            "Dynamic_Analysis_Results": dynamic_data  or {},
            "Dynamic_Summary":          dynamic_summary or {},
            "Scoring_Results":          {t: sr.to_dict() for t, sr in scoring_results.items()},
        }

        # Save JSON
        json_path = f"{base}.json"
        with open(json_path, "w") as fh:
            json.dump(compiled, fh, indent=4)
        pub.sendMessage("gui.log", msg=f"  [+] JSON Report Saved: {json_path}")

        # Save PDF
        pdf_path = f"{base}.pdf"
        try:
            self._build_pdf(compiled, pdf_path, scoring_results=scoring_results)
            pub.sendMessage("gui.log", msg=f"  [+] PDF Report Saved: {pdf_path}")
        except Exception as exc:
            pub.sendMessage("gui.log", msg=f"  [!] PDF generation failed (proceeding with JSON report): {exc}")

    def _build_pdf(self, data: dict, path: str, *, scoring_results: dict | None = None):
        # Two-pass build to build the table of contents page map
        page_map = {}
        
        # Pass 1: Dry run
        story_dry = self.build_story_flow(data, page_map)
        doc_dry = SimpleDocTemplate(path, pagesize=letter, leftMargin=54, rightMargin=54, topMargin=72, bottomMargin=72)
        doc_dry.build(story_dry, canvasmaker=NumberedCanvas)

        # Pass 2: Real run
        story_real = self.build_story_flow(data, page_map)
        doc_real = SimpleDocTemplate(path, pagesize=letter, leftMargin=54, rightMargin=54, topMargin=72, bottomMargin=72)
        doc_real.build(story_real, canvasmaker=NumberedCanvas)

    def build_story_flow(self, data: dict, page_map: dict) -> list:
        story = []
        meta = data.get("Analysis_Summary", {})
        filename = _resolve_filename(meta)
        
        # Extract basic info
        file_size_bytes = meta.get("File Size (Bytes)", 0)
        sha256_val = _clean_hash(str(meta.get("SHA256", "N/A")))
        
        verdict = "CLEAN"
        score = 0.0
        
        # Pull verdict and score from scoring results if available
        scoring_results_dict = data.get("Scoring_Results", {})
        if scoring_results_dict:
            primary_target = list(scoring_results_dict.keys())[0]
            sr = scoring_results_dict[primary_target]
            verdict = sr.get("verdict", "CLEAN")
            score = sr.get("total_score", 0.0)
            
        verdict_color = "#16a34a" # Green
        if score >= 7.5:
            verdict_color = "#dc2626" # Red
        elif score >= 3.0:
            verdict_color = "#ea580c" # Orange

        # ==================================================
        # 1. COVER PAGE
        # ==================================================
        story.append(Spacer(1, 100))
        story.append(Paragraph("MALWARE ANALYSIS REPORT", self.title_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph("STATIC TRIAGE & SIGNATURE DETECTION", self.subtitle_style))
        story.append(Spacer(1, 40))

        cover_data = [
            [Paragraph("<b>Analysis Date</b>", self.normal_bold), Paragraph(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.normal)],
            [Paragraph("<b>Sample Name</b>", self.normal_bold), Paragraph(filename, self.normal)],
            [Paragraph("<b>File Type</b>", self.normal_bold), Paragraph(meta.get("MIME/Format Guess", "application/x-dosexec"), self.normal)],
            [Paragraph("<b>Magic Bytes (Hex)</b>", self.normal_bold), Paragraph(meta.get("Magic Bytes (Hex)", "N/A"), self.normal)],
            [Paragraph("<b>File Size</b>", self.normal_bold), Paragraph(self.format_size(file_size_bytes), self.normal)],
            [Paragraph("<b>SHA256</b>", self.normal_bold), Paragraph(sha256_val, self.code_style)],
            [Paragraph("<b>Final Verdict</b>", self.normal_bold), Paragraph(f"<font color='{verdict_color}'><b>{verdict}</b></font>", self.normal_bold)],
            [Paragraph("<b>Risk Score</b>", self.normal_bold), Paragraph(f"<b>{score * 10.0:.0f}/100</b>", self.normal_bold)]
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

        # Overall assessment
        overall_assessment = ""
        yara_matches = 0
        static_results = data.get("Static_Analysis_Results", {})
        for t, res in static_results.items():
            yara_analysis = res.get("YARA Signatures", {})
            yara_matches = max(yara_matches, int(yara_analysis.get("Hits", 0) or 0))

        if score >= 7.5:
            overall_assessment = "The sample exhibits strong malicious characteristics and posed a high level of threat threat indicators during both static and dynamic analysis. Key findings include critical YARA signatures firing and high risk operations. Quarantine and threat hunting across the system is strongly advised."
        elif score >= 3.0:
            overall_assessment = "The sample raised indicators of potentially suspicious behavior. Anti-analysis techniques and unexpected imports are present, warranting manual inspection and validation."
        else:
            overall_assessment = "No significant threat indicators were identified. The sample appears clean based on static heuristics and signature matches; standard caution is advised."

        summary_table_data = [
            [Paragraph("<b>Sample Analyzed</b>", self.normal_bold), Paragraph(filename, self.normal)],
            [Paragraph("<b>Risk Score</b>", self.normal_bold), Paragraph(f"<b>{score * 10.0:.0f}/100</b>", self.normal_bold)],
            [Paragraph("<b>Verdict</b>", self.normal_bold), Paragraph(f"<font color='{verdict_color}'><b>{verdict}</b></font>", self.normal_bold)],
            [Paragraph("<b>Total YARA Matches</b>", self.normal_bold), Paragraph(str(yara_matches), self.normal)]
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
        
        # Custom dots-leaders Table of Contents
        story.append(Spacer(1, 20))
        story.append(Paragraph("Table of Contents", self.h1_style))
        story.append(Spacer(1, 10))

        toc_items = [
            ("1. Executive Summary", "EXECUTIVE_SUMMARY"),
            ("2. Static Analysis Details", "STATIC_ANALYSIS"),
            ("3. Dynamic Sandbox Analysis Details", "DYNAMIC_ANALYSIS")
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
        # 3. STATIC ANALYSIS (SCHEMA-COMPLIANT)
        # ==================================================
        story.append(HeadingTracker("STATIC_ANALYSIS", page_map))
        story.append(Paragraph("2. Static Analysis", self.h1_style))
        story.append(Spacer(1, 5))

        package_ext = data.get("Package_Extraction", [])

        # 1. Package Hashes
        story.append(Paragraph("Package Hashes", self.h2_style))
        hashes_tbl_data = [
            [Paragraph("<b>MD5</b>", self.normal_bold), Paragraph(_clean_hash(str(meta.get("MD5", "N/A"))), self.code_style)],
            [Paragraph("<b>SHA-1</b>", self.normal_bold), Paragraph(_clean_hash(str(meta.get("SHA1", "N/A"))), self.code_style)],
            [Paragraph("<b>SHA-256</b>", self.normal_bold), Paragraph(_clean_hash(str(meta.get("SHA256", "N/A"))), self.code_style)],
            [Paragraph("<b>SHA-512</b>", self.normal_bold), Paragraph(_clean_hash(str(meta.get("SHA512", "N/A"))), self.code_style)]
        ]
        t_hashes = Table(hashes_tbl_data, colWidths=[120, 384])
        t_hashes.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
            ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t_hashes)
        story.append(Spacer(1, 10))

        # 2. Hash of Unzipped Package
        story.append(Paragraph("Hash of Unzipped Package", self.h2_style))
        if package_ext:
            unzip_rows = []
            for item in package_ext:
                rel_path = item.get("Relative_Path", "Unknown")
                sha256 = item.get("SHA256", "N/A")
                unzip_rows.append([Paragraph(rel_path, self.normal), Paragraph(_clean_hash(sha256), self.code_style)])
            t_unzip = Table(unzip_rows, colWidths=[150, 354])
            t_unzip.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(t_unzip)
        else:
            story.append(Paragraph("N/A - Not an archive/package file", self.normal))
        story.append(Spacer(1, 10))

        # 3. Executable Binaries List
        story.append(Paragraph("Executable Binaries List", self.h2_style))
        binaries = []
        if package_ext:
            for item in package_ext:
                if item.get("Is_Flagged") or str(item.get("Extension", "")).lower() in (".exe", ".dll", ".sys", ".drv"):
                    binaries.append(item.get("Relative_Path", "Unknown"))
        else:
            fname = _resolve_filename(meta)
            if fname and fname != "Unknown Sample":
                binaries.append(fname)
        
        if binaries:
            for b in binaries:
                story.append(Paragraph(f"• {b}", self.normal))
        else:
            story.append(Paragraph("N/A", self.normal))
        story.append(Spacer(1, 10))

        # 4. PE Section Table & details
        for target_name, file_data in static_results.items():
            # Section Analysis
            story.append(Paragraph("Section Analysis (Permissions & Entropy)", self.h2_style))
            sections_data = file_data.get("Sections", {})
            sect_rows = []
            for sect_name, info in sections_data.items():
                perms = "N/A"
                entropy = "N/A"
                info_str = str(info)
                p_match = re.search(r"Perms:\s*([^\s|]+)", info_str)
                if p_match:
                    perms = p_match.group(1)
                e_match = re.search(r"Entropy:\s*([^\s|]+)", info_str)
                if e_match:
                    entropy = e_match.group(1)
                sect_rows.append([
                    Paragraph(sect_name.replace("Section:", "").strip(), self.normal),
                    Paragraph(perms, self.code_style),
                    Paragraph(entropy, self.code_style)
                ])
            if sect_rows:
                t_sect = Table(sect_rows, colWidths=[150, 150, 204])
                t_sect.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                    ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                    ('PADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(t_sect)
            else:
                story.append(Paragraph("N/A - Section analysis not performed", self.normal))
            story.append(Spacer(1, 10))

            # PE Headers
            story.append(Paragraph("PE Headers", self.h2_style))
            pe_headers_data = file_data.get("PE Headers", {})
            if pe_headers_data:
                pe_rows = [[Paragraph(f"<b>{k}</b>", self.normal_bold), Paragraph(str(v), self.normal)] for k, v in pe_headers_data.items()]
                t_pe = Table(pe_rows, colWidths=[200, 304])
                t_pe.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                    ('PADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(t_pe)
            else:
                story.append(Paragraph("N/A", self.normal))
            story.append(Spacer(1, 10))

            # Mitigations
            story.append(Paragraph("Security Mitigations", self.h2_style))
            mit_data = file_data.get("Mitigations", {})
            if mit_data:
                mit_rows = [[Paragraph(f"<b>{k}</b>", self.normal_bold), Paragraph(str(v), self.normal)] for k, v in mit_data.items()]
                t_mit = Table(mit_rows, colWidths=[200, 304])
                t_mit.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                    ('PADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(t_mit)
            else:
                story.append(Paragraph("N/A", self.normal))
            story.append(Spacer(1, 10))

            # Suspicious Imports
            story.append(Paragraph("Suspicious Imports", self.h2_style))
            imp_data = file_data.get("Suspicious Imports", {})
            if imp_data:
                imp_rows = [[Paragraph(f"<b>{k}</b>", self.normal_bold), Paragraph(str(v), self.normal)] for k, v in imp_data.items()]
                t_imp = Table(imp_rows, colWidths=[150, 354])
                t_imp.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                    ('PADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(t_imp)
            else:
                story.append(Paragraph("N/A", self.normal))
            story.append(Spacer(1, 10))

            # Strings Analytics
            story.append(Paragraph("Strings Analytics", self.h2_style))
            str_data = file_data.get("Strings Analytics", {})
            if str_data:
                str_rows = []
                for k, v in str_data.items():
                    if k.lower() in ("email", "emails"):
                        continue
                    str_rows.append([Paragraph(f"<b>{k}</b>", self.normal_bold), Paragraph(str(v), self.normal)])
                t_str = Table(str_rows, colWidths=[150, 354])
                t_str.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                    ('PADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(t_str)
            else:
                story.append(Paragraph("N/A", self.normal))
            story.append(Spacer(1, 10))

            # Extracted Artifacts
            story.append(Paragraph("Extracted Artifacts", self.h2_style))
            art_data = file_data.get("Extracted Artifacts", {})
            if art_data:
                art_rows = []
                for k, v in art_data.items():
                    if k.lower() in ("email", "emails"):
                        continue
                    if isinstance(v, list):
                        v_clean = [str(x) for x in v if not ("@" in str(x) and "." in str(x))]
                        v_str = ", ".join(v_clean)
                    else:
                        v_str = str(v)
                    art_rows.append([Paragraph(f"<b>{k}</b>", self.normal_bold), Paragraph(v_str, self.code_style)])
                t_art = Table(art_rows, colWidths=[150, 354])
                t_art.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                    ('PADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(t_art)
            else:
                story.append(Paragraph("N/A", self.normal))
            story.append(Spacer(1, 10))

            # YARA Signatures
            story.append(Paragraph("YARA Signatures", self.h2_style))
            yara_data = file_data.get("YARA Signatures", {})
            if yara_data:
                yara_rows = [[Paragraph(f"<b>{k}</b>", self.normal_bold), Paragraph(str(v), self.normal)] for k, v in yara_data.items()]
                t_yara = Table(yara_rows, colWidths=[150, 354])
                t_yara.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                    ('PADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(t_yara)
            else:
                story.append(Paragraph("N/A", self.normal))
            story.append(Spacer(1, 10))

        # 5. Manifest Analysis
        story.append(Paragraph("Manifest Analysis", self.h2_style))
        has_manifest = False
        for target_name, file_data in static_results.items():
            man_data = file_data.get("Manifest Data", {})
            if man_data:
                has_manifest = True
                manifest_status = man_data.get("Manifest Status", "Parsed Successfully")
                exec_level = man_data.get("Requested Execution Level", "Unknown")
                man_rows = [
                    [Paragraph("<b>XML Manifest Status</b>", self.normal_bold), Paragraph(manifest_status, self.normal)],
                    [Paragraph("<b>Requested Execution Level</b>", self.normal_bold), Paragraph(exec_level, self.normal)]
                ]
                t_man = Table(man_rows, colWidths=[180, 324])
                t_man.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                    ('PADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(t_man)
                break
        if not has_manifest:
            story.append(Paragraph("N/A - Manifest analysis not performed", self.normal))

        story.append(PageBreak())

        # ==================================================
        # 5. DYNAMIC ANALYSIS (SCHEMA-COMPLIANT)
        # ==================================================
        story.append(HeadingTracker("DYNAMIC_ANALYSIS", page_map))
        story.append(Paragraph("3. Dynamic Sandbox Analysis", self.h1_style))
        story.append(Spacer(1, 5))

        dyn_results = data.get("Dynamic_Analysis_Results", {})
        if not dyn_results:
            story.append(Paragraph("N/A - Sandbox analysis was not performed.", self.normal))
            return story

        target_name = list(dyn_results.keys())[0]
        telemetry = dyn_results.get(target_name, {})

        # Compute Registry Counts
        reg_added_cnt = 0
        reg_deleted_cnt = 0
        reg_modified_cnt = 0

        if "process_tree_generation" in telemetry:
            reg_data = telemetry.get("registry_monitoring", {})
            reg_added_cnt = len(reg_data.get("values_added", []))
            reg_deleted_cnt = len(reg_data.get("keys_deleted", [])) + len(reg_data.get("values_deleted", []))
            reg_modified_cnt = len(reg_data.get("values_modified", []))
        else:
            for ev in telemetry.get("Registry", []):
                ev_upper = str(ev).upper()
                if "DELETE" in ev_upper:
                    reg_deleted_cnt += 1
                elif "WRITE" in ev_upper or "ADD" in ev_upper or "CREATE" in ev_upper:
                    reg_added_cnt += 1
                elif "MODIFY" in ev_upper or "MUTATED" in ev_upper:
                    reg_modified_cnt += 1
                else:
                    reg_modified_cnt += 1

        # 1. Registry Entry Made by the Application
        story.append(Paragraph("Registry Entry Made by the Application", self.h2_style))
        story.append(Paragraph(
            f"Summary of registry activity: <b>{reg_added_cnt}</b> created/added, <b>{reg_modified_cnt}</b> modified, and <b>{reg_deleted_cnt}</b> deleted.",
            self.normal
        ))
        story.append(Spacer(1, 5))

        reg_rows = []
        if "process_tree_generation" in telemetry:
            reg_data = telemetry.get("registry_monitoring", {})
            for k in reg_data.get("keys_deleted", []):
                reg_rows.append([Paragraph(k, self.code_style), Paragraph("KEY DELETED", self.normal)])
            for v in reg_data.get("values_deleted", []):
                reg_rows.append([Paragraph(v, self.code_style), Paragraph("VALUE DELETED", self.normal)])
            for val in reg_data.get("values_added", []):
                reg_rows.append([Paragraph(val.get("path", ""), self.code_style), Paragraph(f"VALUE ADDED ({val.get('type')})", self.normal)])
            for val in reg_data.get("values_modified", []):
                reg_rows.append([Paragraph(val.get("path", ""), self.code_style), Paragraph(f"VALUE MODIFIED ({val.get('type')})", self.normal)])
        else:
            for ev in telemetry.get("Registry", []):
                reg_rows.append([Paragraph(str(ev), self.code_style), Paragraph("MUTATED", self.normal)])

        if reg_rows:
            t_reg = Table(reg_rows, colWidths=[384, 120])
            t_reg.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(t_reg)
        else:
            story.append(Paragraph("N/A - No registry mutations captured", self.normal))
        story.append(Spacer(1, 10))

        # Compute File System Counts
        fs_created_cnt = 0
        fs_deleted_cnt = 0
        fs_modified_cnt = 0

        if "process_tree_generation" in telemetry:
            fs_data = telemetry.get("file_system_monitoring", {})
            fs_created_cnt = len(fs_data.get("files_created", []))
            fs_deleted_cnt = len(fs_data.get("files_deleted", []))
            fs_modified_cnt = len(fs_data.get("files_modified", [])) + len(fs_data.get("files_renamed", []))
        else:
            for ev in telemetry.get("Filesystem", []):
                ev_upper = str(ev).upper()
                if "CREATE" in ev_upper or "DROP" in ev_upper:
                    fs_created_cnt += 1
                elif "DELETE" in ev_upper:
                    fs_deleted_cnt += 1
                elif "MODIFY" in ev_upper or "RENAME" in ev_upper or "MUTATED" in ev_upper:
                    fs_modified_cnt += 1
                else:
                    fs_modified_cnt += 1

        story.append(PageBreak())
        # 2. Folder Changes Made During Installation
        story.append(Paragraph("Folder Changes Made During Installation", self.h2_style))
        story.append(Paragraph(
            f"Summary of file system activity: <b>{fs_created_cnt}</b> created, <b>{fs_modified_cnt}</b> modified, and <b>{fs_deleted_cnt}</b> deleted.",
            self.normal
        ))
        story.append(Spacer(1, 5))

        fs_rows = []
        if "process_tree_generation" in telemetry:
            fs_data = telemetry.get("file_system_monitoring", {})
            for f in fs_data.get("files_created", []):
                fs_rows.append([Paragraph(f, self.code_style), Paragraph("CREATED", self.normal)])
            for f in fs_data.get("files_modified", []):
                fs_rows.append([Paragraph(f, self.code_style), Paragraph("MODIFIED", self.normal)])
            for f in fs_data.get("files_deleted", []):
                fs_rows.append([Paragraph(f, self.code_style), Paragraph("DELETED", self.normal)])
            for f in fs_data.get("files_renamed", []):
                fs_rows.append([Paragraph(f, self.code_style), Paragraph("RENAMED", self.normal)])
        else:
            for ev in telemetry.get("Filesystem", []):
                fs_rows.append([Paragraph(str(ev), self.code_style), Paragraph("MUTATED", self.normal)])

        if fs_rows:
            t_fs = Table(fs_rows, colWidths=[384, 120])
            t_fs.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(t_fs)
        else:
            story.append(Paragraph("N/A - No file system changes captured", self.normal))
        story.append(Spacer(1, 10))

        story.append(PageBreak())
        # 3. Persistence Check During the Execution
        story.append(Paragraph("Persistence Check During the Execution", self.h2_style))
        
        # Phase 4: High-Confidence and Low-Confidence Noise Tables
        has_new_schema = False
        high_conf = []
        low_conf = []
        
        if "process_tree_generation" in telemetry:
            pers_data = telemetry.get("persistence_analysis", {})
            if "high_confidence_persistence" in pers_data or "low_confidence_noise" in pers_data:
                has_new_schema = True
                high_conf = pers_data.get("high_confidence_persistence", [])
                low_conf = pers_data.get("low_confidence_noise", [])
        
        def is_user_directory(s):
            if not s:
                return False
            s_lower = str(s).lower()
            return any(dir_name in s_lower for dir_name in ["appdata", "roaming", "local\\temp", "\\temp\\", "users\\public", "programdata", "desktop", "downloads"])

        if has_new_schema:
            # 1. High Confidence Persistence Table
            story.append(Paragraph("<b>High-Confidence Persistence Entries</b>", self.normal_bold))
            story.append(Spacer(1, 3))
            
            high_rows = [[
                Paragraph("<b>Category</b>", self.normal_bold),
                Paragraph("<b>Mechanism</b>", self.normal_bold),
                Paragraph("<b>Target Path / Artifact</b>", self.normal_bold)
            ]]
            
            for item in high_conf:
                target = item.get("target_path", "N/A")
                cmd = item.get("command", "N/A")
                target_styled = target
                if is_user_directory(target) or is_user_directory(cmd):
                    target_styled = f"<font color='#dc2626'><b>[!] {target}</b></font>"
                    if cmd and cmd != "N/A":
                        target_styled += f"<br/><font color='#b45309'>Cmd: {cmd}</font>"
                else:
                    if cmd and cmd != "N/A":
                        target_styled += f"<br/><font color='#6B7280'>Cmd: {cmd}</font>"
                        
                high_rows.append([
                    Paragraph(item.get("category", "N/A"), self.normal),
                    Paragraph(item.get("mechanism", "N/A"), self.normal),
                    Paragraph(target_styled, self.code_style)
                ])
                
            if len(high_rows) > 1:
                t_high = Table(high_rows, colWidths=[110, 140, 254])
                t_high.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self.bg_light),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                    ('PADDING', (0, 0), (-1, -1), 6),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                story.append(t_high)
            else:
                story.append(Paragraph("No high-confidence persistence mechanisms established.", self.normal))
                
            story.append(Spacer(1, 8))
            
            # 2. Low Confidence / System Noise Table
            story.append(Paragraph("<b>System Noise / Low Confidence Entries</b>", self.normal_bold))
            story.append(Spacer(1, 3))
            
            low_rows = [[
                Paragraph("<b>Category</b>", self.normal_bold),
                Paragraph("<b>Mechanism</b>", self.normal_bold),
                Paragraph("<b>System Target / Binary Path</b>", self.normal_bold)
            ]]
            
            for item in low_conf:
                target = item.get("target_path", "N/A")
                cmd = item.get("command", "N/A")
                target_styled = target
                if cmd and cmd != "N/A":
                    target_styled += f"<br/><font color='#6B7280'>Cmd: {cmd}</font>"
                    
                low_rows.append([
                    Paragraph(item.get("category", "N/A"), self.normal),
                    Paragraph(item.get("mechanism", "N/A"), self.normal),
                    Paragraph(target_styled, self.code_style)
                ])
                
            if len(low_rows) > 1:
                t_low = Table(low_rows, colWidths=[110, 140, 254])
                t_low.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self.bg_light),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                    ('PADDING', (0, 0), (-1, -1), 6),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                story.append(t_low)
            else:
                story.append(Paragraph("No low-confidence system noise/lingering modifications detected.", self.normal))
                
            story.append(Spacer(1, 8))
            
        else:
            # Fallback legacy layout
            pers_rows = []
            if "process_tree_generation" in telemetry:
                pers_data = telemetry.get("persistence_analysis", {})
                for detail in pers_data.get("details", []):
                    pers_rows.append([
                        Paragraph(detail.get("category", "N/A"), self.normal),
                        Paragraph(detail.get("mechanism", "N/A"), self.normal),
                        Paragraph(detail.get("target_path", "N/A"), self.code_style)
                    ])
            else:
                for ev in telemetry.get("Persistence", []):
                    pers_rows.append([Paragraph("Mechanism", self.normal), Paragraph(str(ev), self.normal), Paragraph("N/A", self.code_style)])
            
            if pers_rows:
                t_pers = Table(pers_rows, colWidths=[120, 150, 234])
                t_pers.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                    ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                    ('PADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(t_pers)
            else:
                story.append(Paragraph("N/A - No persistence mechanisms established", self.normal))
            story.append(Spacer(1, 10))

        story.append(PageBreak())
        # 4. Process Initialization
        story.append(Paragraph("Process Initialization", self.h2_style))
        
        # Embed WMI Process Tree Visual Graph
        img_path = telemetry.get("analysis_metadata", {}).get("process_tree_image_path", "")
        if img_path and os.path.exists(img_path):
            story.append(KeepTogether([
                Image(img_path, width=460, height=276),
                Spacer(1, 10)
            ]))
            
        has_proc = False
        if "process_tree_generation" in telemetry:
            tree_root = telemetry.get("process_tree_generation", {}).get("tree", {})
            tree_lines = []
            def build_tree_lines(node, level=0):
                indent = "&nbsp;" * (level * 4)
                prefix = "|-- " if level > 0 else ""
                line = f"{indent}{prefix}<b>{node.get('process_name')}</b> (PID: {node.get('pid')})"
                if node.get("command_line"):
                    line += f" <font color='#6B7280'>[Cmd: {node.get('command_line')}]</font>"
                tree_lines.append(line)
                for child in node.get("children", []):
                    build_tree_lines(child, level + 1)
            
            if tree_root:
                has_proc = True
                build_tree_lines(tree_root)
                tree_str = "<br/>".join(tree_lines)
                story.append(Paragraph(tree_str, self.code_style))
        else:
            proc_events = telemetry.get("Processes", [])
            if proc_events:
                has_proc = True
                for ev in proc_events:
                    story.append(Paragraph(f"• {ev}", self.normal))

        if not has_proc:
            story.append(Paragraph("N/A - No process initialization recorded", self.normal))
        story.append(Spacer(1, 10))

        story.append(PageBreak())
        # 7. Resource Utility
        story.append(Paragraph("Resource Utility", self.h2_style))
        has_res = False
        if "process_tree_generation" in telemetry:
            res_data = telemetry.get("resource_utility_monitoring", {})
            peak = res_data.get("summary", {})
            if peak:
                has_res = True
                peak_rows = [
                    [Paragraph("<b>Peak CPU Usage</b>", self.normal_bold), Paragraph(f"{peak.get('peak_cpu_percent', 0)}%", self.normal)],
                    [Paragraph("<b>Peak Memory Footprint</b>", self.normal_bold), Paragraph(f"{peak.get('peak_memory_bytes', 0) / (1024 * 1024):.2f} MB", self.normal)]
                ]
                t_res = Table(peak_rows, colWidths=[180, 324])
                t_res.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                    ('PADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(t_res)
                
                # Render CPU utilization profile graph if present
                cpu_img = peak.get("cpu_graph_image_path", "")
                if cpu_img and os.path.exists(cpu_img):
                    story.append(Spacer(1, 10))
                    story.append(KeepTogether([
                        Image(cpu_img, width=460, height=184),
                        Spacer(1, 5)
                    ]))
        
        if not has_res:
            story.append(Paragraph("N/A - Resource utility monitoring not performed", self.normal))
        story.append(Spacer(1, 10))

        story.append(PageBreak())
        # 8. Dropped / Loaded DLLs
        story.append(Paragraph("Dropped / Loaded DLLs", self.h2_style))
        dll_info = telemetry.get("dll_signature_monitoring", {})
        dll_details = dll_info.get("details", [])
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
                dll_name = dll.get("dll_name", "Unknown")
                sig_status = dll.get("signature_status", "UNKNOWN")
                if sig_status == "UNSIGNED":
                    name_p = Paragraph(f"<font color='#dc2626'><b>[!] {dll_name}</b></font>", self.normal_bold)
                else:
                    name_p = Paragraph(dll_name, self.normal)
                hash_data.append([
                    name_p,
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

        # 9. Network Communication Analysis
        story.append(PageBreak())
        story.append(Paragraph("Network Communication Analysis", self.h2_style))
        net_info = telemetry.get("network_communication_analysis", {})
        net_details = net_info.get("details", [])
        total_connections = net_info.get("summary", {}).get("total_connections", 0)
        
        story.append(Paragraph(
            f"Total connections/requests captured: <b>{total_connections}</b>",
            self.normal
        ))
        story.append(Spacer(1, 8))
        
        if net_details:
            net_table_data = [[
                Paragraph("<b>Protocol</b>", self.normal_bold),
                Paragraph("<b>Port</b>", self.normal_bold),
                Paragraph("<b>Direction</b>", self.normal_bold),
                Paragraph("<b>Activity / Domain / Command</b>", self.normal_bold),
            ]]
            
            for conn in net_details:
                proto = conn.get("protocol", "N/A")
                port = str(conn.get("dst_port", "N/A"))
                direct = conn.get("direction", "OUTBOUND")
                action = conn.get("scapy_action", "") or conn.get("domain", "") or "N/A"
                
                net_table_data.append([
                    Paragraph(proto, self.normal),
                    Paragraph(port, self.normal),
                    Paragraph(direct, self.normal),
                    Paragraph(action, self.code_style),
                ])
                
            net_table = Table(net_table_data, colWidths=[64, 54, 74, 312])
            net_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.bg_light),
                ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(net_table)
        else:
            net_events = telemetry.get("Network", [])
            if net_events:
                net_table_data = [[
                    Paragraph("<b>Activity Log</b>", self.normal_bold)
                ]]
                for ev in net_events:
                    net_table_data.append([
                        Paragraph(str(ev), self.code_style)
                    ])
                net_table = Table(net_table_data, colWidths=[504])
                net_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self.bg_light),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.border_color),
                    ('PADDING', (0, 0), (-1, -1), 6),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                story.append(net_table)
            else:
                story.append(Paragraph("No network activity captured during execution.", self.normal))

        return story


    def _extract_iocs_data(self, data: dict) -> dict:
        iocs = {"hashes": [], "domains": [], "ips": [], "file_paths": []}
        seen = set()

        def _add(bucket, val):
            val = val.strip()
            if val and val not in seen and val not in ("N/A", "?", "-", "\u2014"):
                seen.add(val)
                iocs[bucket].append(val)

        # Hashes
        meta = data.get("Analysis_Summary", {})
        for htype in ("MD5", "SHA1", "SHA256"):
            v = str(meta.get(htype, "")).strip()
            if v and v not in ("N/A", "?"):
                v = _clean_hash(v)
                key = f"{htype}:{v}"
                if key not in seen:
                    seen.add(key)
                    iocs["hashes"].append((htype, v))

        # Extracted domains/URLs/IPs from strings analysis
        static = data.get("Static_Analysis_Results", {})
        for tgt, file_data in static.items():
            artifacts = file_data.get("Extracted Artifacts", {})
            if isinstance(artifacts, dict):
                for dom in artifacts.get("URL", []):
                    _add("domains", dom)
                for ip in artifacts.get("IPv4", []):
                    _add("ips", ip)

        # File paths from extracted packages
        for pkg in data.get("Package_Extraction", []):
            _add("file_paths", pkg.get("Relative_Path", ""))

        return iocs
