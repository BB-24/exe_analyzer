"""
MARS — Report Generator (ReportLab · format matching pdf_generator.py)
"""

import os
import re
import datetime
import json
from typing import List, Dict, Any, Optional, Tuple, Set, Union
from pubsub import pub

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    Flowable,
    Image,
    KeepTogether,
    LongTable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

# ═══════════════════════════════════════════════════════════════════════════
# DATA CLEANER & UTILITIES
# ═══════════════════════════════════════════════════════════════════════════
class DataCleaner:
    """
    Utility class for data sanitization, formatting, and analysis.
    """

    @staticmethod
    def safe_text(v: Any) -> str:
        """Sanitizes text to ensure compatibility with latin-1 encoding."""
        return str(v).encode("latin-1", "replace").decode("latin-1")

    @staticmethod
    def clean_hash(v: str) -> str:
        """Cleans and standardizes hash strings to avoid duplicates or overflow."""
        if not isinstance(v, str):
            v = str(v)
        v = v.strip()
        half = len(v) // 2
        if half >= 32 and v[:half] == v[half:]:
            v = v[:half]
        if len(v) > 64:
            v = v[:64]
        return v

    @staticmethod
    def is_hash_key(key: str) -> bool:
        """Determines if a key represents a hash value based on naming heuristics."""
        if not isinstance(key, str):
            return False
        k = key.upper()
        return any(tok in k for tok in ("SHA", "MD5", "HASH"))

    @staticmethod
    def resolve_filename(meta: dict) -> str:
        """Resolves the standard target filename from metadata entries."""
        for key in ("Original File Name", "Filename", "filename"):
            v = str(meta.get(key) or "").strip()
            if v and v not in ("N/A", "?", ""):
                return v
        return "Unknown Sample"

    @staticmethod
    def clean_strings(str_list: List[Any], category: str) -> List[str]:
        """Cleans and filters strings based on heuristic patterns (e.g., URLs, domains, IPs)."""
        cleaned: List[str] = []
        for raw_s in str_list:
            s = str(raw_s).strip()
            if not s or len(s) < 4:
                continue
            s_lower = s.lower()
            if category == "urls":
                if s_lower.startswith(("http://", "https://")):
                    cleaned.append(s)
            elif category == "domains":
                if s_lower.endswith((".dll", ".exe", ".sys", ".drv", ".ocx", ".manifest", ".ini", ".lnk")):
                    continue
                if "." in s and not s.startswith(".") and not s.endswith("."):
                    cleaned.append(s)
            elif category == "ips":
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s) or ":" in s:
                    cleaned.append(s)
            elif category == "registry":
                if s_lower.startswith(("hklm", "hkcu", "hkey_")):
                    cleaned.append(s)
        return sorted(list(set(cleaned)))[:10]

    @staticmethod
    def format_size(size_bytes: Any) -> str:
        """Formats file size in bytes to a human-readable string representation."""
        if not size_bytes:
            return "0 Bytes"
        try:
            val = float(size_bytes)
        except Exception:
            return str(size_bytes)
        for unit in ['Bytes', 'KB', 'MB', 'GB']:
            if val < 1024.0:
                return f"{val:.2f} {unit}"
            val /= 1024.0
        return f"{val:.2f} TB"


# ═══════════════════════════════════════════════════════════════════════════
# TABLE FORMATTING & PAGINATION UTILITIES
# ═══════════════════════════════════════════════════════════════════════════
class TableFormatter:
    """
    Format and structure data tables for ReportLab flow.
    Handles cell wrapping, paragraph conversion, styling, and multi-page splits.
    """

    @staticmethod
    def wrap_cell_data(
        data: List[List[Any]],
        default_style: ParagraphStyle,
        bold_first_row: bool = False,
        bold_style: Optional[ParagraphStyle] = None,
        code_cols: Optional[List[int]] = None,
        code_style: Optional[ParagraphStyle] = None
    ) -> List[List[Any]]:
        """
        Ensures all text elements in a 2D array are flowables (Paragraph) so they wrap
        properly and do not cause truncation or bad split issues across page breaks.
        """
        wrapped_data = []
        for r_idx, row in enumerate(data):
            wrapped_row = []
            for c_idx, cell in enumerate(row):
                if isinstance(cell, (Paragraph, Image, KeepTogether, Flowable)):
                    wrapped_row.append(cell)
                elif cell is None:
                    wrapped_row.append(Paragraph("N/A", default_style))
                else:
                    cell_str = str(cell)
                    style = default_style
                    
                    if r_idx == 0 and bold_first_row:
                        style = bold_style or default_style
                        if not cell_str.startswith("<b>"):
                            cell_str = f"<b>{cell_str}</b>"
                    elif code_cols and c_idx in code_cols:
                        style = code_style or default_style
                    
                    wrapped_row.append(Paragraph(cell_str, style))
            wrapped_data.append(wrapped_row)
        return wrapped_data

    @staticmethod
    def build_table(
        data: List[List[Any]],
        col_widths: List[float],
        bg_color: Optional[colors.Color] = None,
        border_color: Optional[colors.Color] = None,
        is_long: bool = True,
        repeat_rows: int = 1,
        valign: str = 'TOP',
        header_bg: Optional[colors.Color] = None,
        padding: int = 6
    ) -> Table:
        """
        Creates a styled Table or LongTable with explicit styles and repeating headers.
        Automatically converts headers to white text if header_bg is provided.
        Applies alternating row background colors for data rows.
        """
        table_cls = LongTable if is_long else Table
        
        tbl_styles = [
            ('PADDING', (0, 0), (-1, -1), padding),
            ('VALIGN', (0, 0), (-1, -1), valign),
        ]
        
        if border_color:
            tbl_styles.append(('GRID', (0, 0), (-1, -1), 0.5, border_color))
            
        if bg_color:
            tbl_styles.append(('BACKGROUND', (0, 0), (-1, -1), bg_color))
            
        if header_bg:
            tbl_styles.append(('BACKGROUND', (0, 0), (-1, repeat_rows - 1), header_bg))
            for r_idx in range(repeat_rows):
                if r_idx < len(data):
                    for c_idx in range(len(data[r_idx])):
                        cell = data[r_idx][c_idx]
                        if isinstance(cell, Paragraph):
                            text = getattr(cell, "text", "")
                            old_style = getattr(cell, "style", None)
                            if old_style:
                                new_style = ParagraphStyle(
                                    name=f"{old_style.name}_HeaderWhite",
                                    parent=old_style,
                                    textColor=colors.white
                                )
                                data[r_idx][c_idx] = Paragraph(text, new_style)
                                
        if len(data) > repeat_rows + 1:
            for i in range(repeat_rows, len(data)):
                if i == len(data) - 1 and len(data) > 3 and getattr(data[i][0], "text", "").strip() == "<b>...</b>":
                    tbl_styles.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor("#fef08a")))
                    continue
                bg = colors.white if i % 2 == 0 else colors.HexColor("#f8fafc")
                tbl_styles.append(('BACKGROUND', (0, i), (-1, i), bg))

        t = table_cls(data, colWidths=col_widths, repeatRows=repeat_rows)
        t.setStyle(TableStyle(tbl_styles))
        return t


# ═══════════════════════════════════════════════════════════════════════════
# NUMBERED CANVAS (matching pdf_generator.py)
# ═══════════════════════════════════════════════════════════════════════════
class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas implementation to determine total pages and print dynamic
    headers and footers ("Page X of Y") on all pages except the cover page.
    """
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[Dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_elements(num_pages)
            super().showPage()
        super().save()

    def draw_page_elements(self, page_count: int) -> None:
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
    """
    Custom Flowable to track heading page numbers during the dry-run PDF build phase.
    """
    def __init__(self, key: str, title_dict: Dict[str, int]) -> None:
        super().__init__()
        self.key = key
        self.title_dict = title_dict
        
    def draw(self) -> None:
        self.title_dict[self.key] = self.canv._pageNumber


# ═══════════════════════════════════════════════════════════════════════════
# PDF REPORT BUILDER
# ═══════════════════════════════════════════════════════════════════════════
class PDFReportBuilder:
    """
    Modern PDF report orchestrator using ReportLab.
    Manages document schemas, page styles, flowables, dynamic footer counting, and TOC.
    """

    def __init__(self, config: dict) -> None:
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

    def generate_reports(
        self,
        metadata: dict,
        package_data: list,
        static_data: dict,
        dynamic_data: Optional[dict] = None,
        dynamic_summary: Optional[dict] = None,
        scoring_results: Optional[dict] = None,
    ) -> None:
        """Main entry point to serialize data and generate JSON and PDF reports."""
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

    def _build_pdf(self, data: dict, path: str, *, scoring_results: Optional[dict] = None) -> None:
        """Runs a two-pass layout compiler to establish exact table of contents pages."""
        page_map: Dict[str, int] = {}
        
        # Pass 1: Dry run
        story_dry = self.build_story_flow(data, page_map)
        doc_dry = SimpleDocTemplate(path, pagesize=letter, leftMargin=54, rightMargin=54, topMargin=72, bottomMargin=72)
        doc_dry.build(story_dry, canvasmaker=NumberedCanvas)

        # Pass 2: Real run
        story_real = self.build_story_flow(data, page_map)
        doc_real = SimpleDocTemplate(path, pagesize=letter, leftMargin=54, rightMargin=54, topMargin=72, bottomMargin=72)
        doc_real.build(story_real, canvasmaker=NumberedCanvas)

    def build_story_flow(self, data: dict, page_map: dict) -> list:
        """Assembles the Flowables hierarchy list for the PDF rendering pipeline."""
        story = []

        def get_divider():
            t = Table([['']], colWidths=[504], rowHeights=[1])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#cbd5e1')),
                ('TOPPADDING', (0,0), (-1,-1), 0),
                ('BOTTOMPADDING', (0,0), (-1,-1), 0),
            ]))
            return t
        meta = data.get("Analysis_Summary", {})
        filename = DataCleaner.resolve_filename(meta)
        
        # Extract basic info
        file_size_bytes = meta.get("File Size (Bytes)", 0)
        sha256_val = DataCleaner.clean_hash(str(meta.get("SHA256", "N/A")))
        
        verdict = "CLEAN"
        score = 0.0
        
        # Pull verdict and score from scoring results if available
        scoring_results_dict = data.get("Scoring_Results", {})
        if scoring_results_dict:
            primary_target = list(scoring_results_dict.keys())[0]
            sr = scoring_results_dict[primary_target]
            verdict = sr.get("verdict", "CLEAN")
            score = sr.get("total_score", 0.0)
        # Extract dynamic telemetry early for Executive Summary highlights
        dyn_results = data.get("Dynamic_Analysis_Results", {})
        telemetry = {}
        if dyn_results:
            target_name = list(dyn_results.keys())[0]
            telemetry = dyn_results.get(target_name, {})

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
            [Paragraph("<b>File Size</b>", self.normal_bold), Paragraph(DataCleaner.format_size(file_size_bytes), self.normal)],
            [Paragraph("<b>SHA256</b>", self.normal_bold), Paragraph(sha256_val, self.code_style)],
            [Paragraph("<b>Final Verdict</b>", self.normal_bold), Paragraph(f"<font color='{verdict_color}'><b>{verdict}</b></font>", self.normal_bold)],
            [Paragraph("<b>Risk Score</b>", self.normal_bold), Paragraph(f"<b>{score * 10.0:.0f}/100</b>", self.normal_bold)]
        ]

        cover_table = TableFormatter.build_table(
            data=cover_data,
            col_widths=[130, 374],
            bg_color=self.bg_light,
            border_color=self.border_color,
            is_long=False,
            repeat_rows=0,
            valign='MIDDLE',
            padding=8
        )
        story.append(cover_table)
        story.append(PageBreak())

        # ==================================================
        # 1.5 TABLE OF CONTENTS
        # ==================================================
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

        toc_table = TableFormatter.build_table(
            data=toc_table_data,
            col_widths=[200, 260, 44],
            bg_color=None,
            border_color=None,
            is_long=False,
            repeat_rows=0,
            valign='BOTTOM',
            padding=4
        )
        story.append(toc_table)
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

        # Dynamic helper functions for contextual explanations
        def get_yara_desc(rule):
            rl = rule.lower()
            if "process_injection" in rl: return "Process memory injection vector detected"
            if "anti_analysis" in rl or "debugging" in rl: return "Anti-analysis/debugging check matched"
            if "credential_dumping" in rl or "mimikatz" in rl: return "Credential stealing/memory dumping signature"
            if "keylogging" in rl: return "Keypress logging/spyware signature"
            if "evasion" in rl or "hash" in rl: return "API hashing or defense evasion signature"
            if "obfuscation" in rl or "crypto" in rl: return "Obfuscation or crypto constants matched"
            if "dropper" in rl or "embedded" in rl: return "Installer or embedded executable payload signature"
            if "rmm" in rl or "abuse" in rl: return "Potential remote monitoring/administration tool abuse"
            return "Suspicious heuristic matches security rule"

        api_explanations = {
            "VirtualAllocEx": "Remote memory allocation (process injection)",
            "WriteProcessMemory": "Memory write capability (process injection)",
            "CreateRemoteThread": "Thread execution in remote process (code execution)",
            "IsDebuggerPresent": "Local debugger detection check (anti-analysis)",
            "CheckRemoteDebuggerPresent": "Remote debugger detection check (anti-analysis)",
            "CreateProcessW": "Process spawning control (child process creation)",
            "CreateProcessA": "Process spawning control (child process creation)",
            "ShellExecuteW": "Command shell execution",
            "ShellExecuteA": "Command shell execution",
            "WinExec": "Command execution",
            "GetProcAddress": "Dynamic API loading behavior",
            "LoadLibraryA": "Dynamic module loading behavior",
            "LoadLibraryW": "Dynamic module loading behavior",
        }

        # Extract and compile all unusual static & dynamic indicators
        yara_rules = []
        for t, res in static_results.items():
            yara_analysis = res.get("YARA Signatures", {})
            if yara_analysis:
                rules_val = yara_analysis.get("Matched Rules") or yara_analysis.get("Rules")
                if isinstance(rules_val, list):
                    yara_rules.extend(rules_val)
                elif isinstance(rules_val, str) and rules_val != "N/A":
                    yara_rules.extend([x.strip() for x in rules_val.split(",") if x.strip()])

        suspicious_imps = []
        for t, res in static_results.items():
            imp_data = res.get("Suspicious Imports", {})
            if imp_data:
                apis = imp_data.get("APIs")
                if isinstance(apis, list):
                    suspicious_imps.extend(apis)
                elif isinstance(apis, str) and apis != "N/A":
                    suspicious_imps.extend([x.strip() for x in apis.split(",") if x.strip()])

        unusual_sects = []
        for t, res in static_results.items():
            sections_data = res.get("Sections", {})
            for sect_name, info in sections_data.items():
                perms = ""
                entropy = ""
                info_str = str(info)
                p_match = re.search(r"Perms:\s*([^\s|]+)", info_str)
                if p_match:
                    perms = p_match.group(1)
                e_match = re.search(r"Entropy:\s*([^\s|]+)", info_str)
                if e_match:
                    entropy = e_match.group(1)
                
                is_unusual_perms = 'W' in perms.upper() and 'E' in perms.upper()
                is_unusual_entropy = False
                try:
                    is_unusual_entropy = float(entropy) > 7.0
                except ValueError:
                    pass
                if is_unusual_perms or is_unusual_entropy:
                    clean_name = sect_name.replace("Section:", "").strip()
                    reason = []
                    if is_unusual_perms: reason.append("Writable + Executable perms (RWE)")
                    if is_unusual_entropy: reason.append("High entropy (potential obfuscation/packing)")
                    unusual_sects.append(f"• <b>{clean_name}</b> &mdash; Entropy: {entropy}, Permissions: {perms} ({', and '.join(reason)})")

        # Check overall file entropy
        overall_entropy_val = "N/A"
        for t, res in static_results.items():
            pe_headers = res.get("PE Headers", {})
            if "Overall File Entropy" in pe_headers:
                overall_entropy_val = pe_headers["Overall File Entropy"]

        is_entropy_really_high = False
        try:
            is_entropy_really_high = float(overall_entropy_val) >= 7.0
        except ValueError:
            pass

        dll_info = telemetry.get("dll_signature_monitoring", {})
        unsigned_dlls = [d.get("dll_name") for d in dll_info.get("details", []) if d.get("signature_status") == "UNSIGNED"]

        pers_data = telemetry.get("persistence_analysis", {})
        high_conf = pers_data.get("high_confidence_persistence", [])

        net_info = telemetry.get("network_communication_analysis", {})
        net_details = net_info.get("details", [])
        active_domains = []
        if net_details:
            active_domains = list(set([conn.get("scapy_action") or conn.get("domain") for conn in net_details if conn.get("scapy_action") or conn.get("domain")]))

        # Format and append findings with beautiful headers and line splits
        has_findings = bool(yara_rules or suspicious_imps or unusual_sects or unsigned_dlls or high_conf or active_domains or is_entropy_really_high)
        if has_findings:
            overall_assessment += "<br/><br/><font size='10'><b>[!] UNUSUAL FINDINGS SUMMARY (VERIFY RECOMMENDED)</b></font>"
            overall_assessment += "<br/><font color='#cbd5e1'>--------------------------------------------------------------------------------</font>"

            if is_entropy_really_high:
                overall_assessment += "<br/><br/><b>High File Entropy:</b>"
                overall_assessment += f"<br/>• <font color='#dc2626'><b>Overall Entropy: {overall_entropy_val}</b></font> &mdash; Indicates potential obfuscation, packing, or encryption"

            if yara_rules:
                overall_assessment += "<br/><br/><b>YARA Signatures Triggered:</b>"
                for r in yara_rules:
                    desc = get_yara_desc(r)
                    overall_assessment += f"<br/>• <font color='#dc2626'><b>{r}</b></font> &mdash; {desc}"

            if suspicious_imps:
                overall_assessment += "<br/><br/><b>Suspicious API Imports:</b>"
                for api in suspicious_imps:
                    desc = api_explanations.get(api, "Suspicious Win32 API import capability")
                    overall_assessment += f"<br/>• <font color='#dc2626'><b>{api}</b></font> &mdash; {desc}"

            if unusual_sects:
                overall_assessment += "<br/><br/><b>Suspicious PE Sections:</b>"
                for sect_str in unusual_sects:
                    overall_assessment += f"<br/><font color='#dc2626'>{sect_str}</font>"

            if unsigned_dlls:
                overall_assessment += "<br/><br/><b>Unsigned DLLs Loaded during Sandbox Execution:</b>"
                for dll in unsigned_dlls:
                    overall_assessment += f"<br/>• <font color='#dc2626'><b>{dll}</b></font> &mdash; Missing valid code signature"

            if high_conf:
                overall_assessment += "<br/><br/><b>Persistence Established:</b>"
                for item in high_conf:
                    mech = item.get('mechanism', 'N/A')
                    cat = item.get('category', 'N/A')
                    overall_assessment += f"<br/>• <font color='#dc2626'><b>{mech}</b></font> &mdash; Category: {cat}"

            if active_domains:
                overall_assessment += "<br/><br/><b>Outbound Network Connections:</b>"
                for dom in active_domains[:10]:
                    overall_assessment += f"<br/>• <font color='#dc2626'><b>{dom}</b></font> &mdash; Connection request logged"

        summary_table_data = [
            [Paragraph("<b>Sample Analyzed</b>", self.normal_bold), Paragraph(filename, self.normal)],
            [Paragraph("<b>Risk Score</b>", self.normal_bold), Paragraph(f"<b>{score * 10.0:.0f}/100</b>", self.normal_bold)],
            [Paragraph("<b>Verdict</b>", self.normal_bold), Paragraph(f"<font color='{verdict_color}'><b>{verdict}</b></font>", self.normal_bold)],
            [Paragraph("<b>Total YARA Matches</b>", self.normal_bold), Paragraph(str(yara_matches), self.normal)]
        ]

        summary_table = TableFormatter.build_table(
            data=summary_table_data,
            col_widths=[150, 354],
            bg_color=self.bg_light,
            border_color=self.border_color,
            is_long=False,
            repeat_rows=0,
            valign='MIDDLE',
            padding=6
        )
        story.append(summary_table)
        story.append(Spacer(1, 15))
        story.append(Paragraph("<b>Overall Assessment:</b>", self.h2_style))
        story.append(Paragraph(overall_assessment, self.normal))
        
        story.append(PageBreak())

        # ==================================================
        # 3. STATIC ANALYSIS
        # ==================================================
        story.append(HeadingTracker("STATIC_ANALYSIS", page_map))
        story.append(Paragraph("2. Static Analysis", self.h1_style))
        story.append(Spacer(1, 5))

        package_ext = data.get("Package_Extraction", [])

        # 1. Package Hashes
        story.append(Paragraph("Package Hashes", self.h2_style))
        hashes_tbl_data = [
            [Paragraph("<b>MD5</b>", self.normal_bold), Paragraph(DataCleaner.clean_hash(str(meta.get("MD5", "N/A"))), self.code_style)],
            [Paragraph("<b>SHA-1</b>", self.normal_bold), Paragraph(DataCleaner.clean_hash(str(meta.get("SHA1", "N/A"))), self.code_style)],
            [Paragraph("<b>SHA-256</b>", self.normal_bold), Paragraph(DataCleaner.clean_hash(str(meta.get("SHA256", "N/A"))), self.code_style)],
            [Paragraph("<b>SHA-512</b>", self.normal_bold), Paragraph(DataCleaner.clean_hash(str(meta.get("SHA512", "N/A"))), self.code_style)]
        ]
        t_hashes = TableFormatter.build_table(
            data=hashes_tbl_data,
            col_widths=[120, 384],
            bg_color=self.bg_light,
            border_color=self.border_color,
            is_long=False,
            repeat_rows=0,
            valign='TOP',
            padding=6
        )
        story.append(t_hashes)
        story.append(Spacer(1, 10))

        # 2. Hash of Unzipped Package
        story.append(Paragraph("Hash of Unzipped Package", self.h2_style))
        if package_ext:
            unzip_rows = []
            for item in package_ext:
                rel_path = item.get("Relative_Path", "Unknown")
                sha256 = item.get("SHA256", "N/A")
                unzip_rows.append([Paragraph(rel_path, self.normal), Paragraph(DataCleaner.clean_hash(sha256), self.code_style)])
            t_unzip = TableFormatter.build_table(
                data=unzip_rows,
                col_widths=[150, 354],
                bg_color=self.bg_light,
                border_color=self.border_color,
                is_long=True,
                repeat_rows=0,
                valign='TOP',
                padding=6
            )
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
            fname = DataCleaner.resolve_filename(meta)
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
            
            sect_rows = [[
                Paragraph("<b>Section Name</b>", self.normal_bold),
                Paragraph("<b>Permissions</b>", self.normal_bold),
                Paragraph("<b>Entropy</b>", self.normal_bold),
            ]]
            
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
                
                is_unusual_perms = 'W' in perms.upper() and 'E' in perms.upper()
                is_unusual_entropy = False
                try:
                    is_unusual_entropy = float(entropy) > 7.0
                except ValueError:
                    pass
                
                perms_styled = perms
                entropy_styled = entropy
                sect_name_styled = sect_name.replace("Section:", "").strip()
                
                if is_unusual_perms:
                    perms_styled = f"<font color='#dc2626'><b>[!] {perms}</b></font>"
                    sect_name_styled = f"<font color='#dc2626'><b>{sect_name_styled}</b></font>"
                if is_unusual_entropy:
                    entropy_styled = f"<font color='#dc2626'><b>[!] {entropy}</b></font>"
                    sect_name_styled = f"<font color='#dc2626'><b>{sect_name_styled}</b></font>"

                sect_rows.append([
                    Paragraph(sect_name_styled, self.normal),
                    Paragraph(perms_styled, self.code_style),
                    Paragraph(entropy_styled, self.code_style)
                ])
            if len(sect_rows) > 1:
                t_sect = TableFormatter.build_table(
                    data=sect_rows,
                    col_widths=[150, 150, 204],
                    bg_color=self.bg_light,
                    border_color=self.border_color,
                    is_long=True,
                    repeat_rows=1,
                    valign='TOP',
                    padding=6
                )
                story.append(t_sect)
            else:
                story.append(Paragraph("N/A - Section analysis not performed", self.normal))
            story.append(Spacer(1, 8))
            
            # Overall File Entropy (printed below Section Analysis)
            file_entropy_val = file_data.get("PE Headers", {}).get("Overall File Entropy", "N/A")
            story.append(Paragraph(f"<b>Overall File Entropy:</b> {file_entropy_val}", self.normal))
            story.append(Spacer(1, 10))

            # PE Headers
            story.append(Paragraph("PE Headers", self.h2_style))
            pe_headers_data = file_data.get("PE Headers", {})
            if pe_headers_data:
                pe_rows = []
                for k, v in pe_headers_data.items():
                    if k == "Overall File Entropy":
                        continue
                    pe_rows.append([Paragraph(f"<b>{k}</b>", self.normal_bold), Paragraph(str(v), self.normal)])
                t_pe = TableFormatter.build_table(
                    data=pe_rows,
                    col_widths=[200, 304],
                    bg_color=self.bg_light,
                    border_color=self.border_color,
                    is_long=True,
                    repeat_rows=0,
                    valign='TOP',
                    padding=6
                )
                story.append(t_pe)
            else:
                story.append(Paragraph("N/A", self.normal))
            story.append(Spacer(1, 10))

            # Mitigations
            story.append(Paragraph("Security Mitigations", self.h2_style))
            mit_data = file_data.get("Mitigations", {})
            if mit_data:
                mit_rows = [[Paragraph(f"<b>{k}</b>", self.normal_bold), Paragraph(str(v), self.normal)] for k, v in mit_data.items()]
                t_mit = TableFormatter.build_table(
                    data=mit_rows,
                    col_widths=[200, 304],
                    bg_color=self.bg_light,
                    border_color=self.border_color,
                    is_long=True,
                    repeat_rows=0,
                    valign='TOP',
                    padding=6
                )
                story.append(t_mit)
            else:
                story.append(Paragraph("N/A", self.normal))
            story.append(Spacer(1, 10))

            # Suspicious Imports
            story.append(Paragraph("Suspicious Imports", self.h2_style))
            imp_data = file_data.get("Suspicious Imports", {})
            if imp_data:
                imp_rows = []
                for k, v in imp_data.items():
                    imp_rows.append([
                        Paragraph(f"<font color='#dc2626'><b>{k}</b></font>", self.normal_bold),
                        Paragraph(str(v), self.normal)
                    ])
                t_imp = TableFormatter.build_table(
                    data=imp_rows,
                    col_widths=[150, 354],
                    bg_color=self.bg_light,
                    border_color=self.border_color,
                    is_long=True,
                    repeat_rows=0,
                    valign='TOP',
                    padding=6
                )
                story.append(t_imp)
            else:
                story.append(Paragraph("N/A", self.normal))
            story.append(Spacer(1, 10))

            # Extracted Artifacts
            story.append(Paragraph("Extracted Artifacts", self.h2_style))
            art_data = file_data.get("Extracted Artifacts", {})
            if art_data:
                art_rows = []
                for k in ["IPv4", "IPv6", "URL", "Registry", "Password-Like"]:
                    v = art_data.get(k, [])
                    v_str = ", ".join(str(x) for x in v) if isinstance(v, list) else str(v)
                    art_rows.append([Paragraph(f"<b>{k}</b>", self.normal_bold), Paragraph(v_str, self.code_style)])
                t_art = TableFormatter.build_table(
                    data=art_rows,
                    col_widths=[150, 354],
                    bg_color=self.bg_light,
                    border_color=self.border_color,
                    is_long=True,
                    repeat_rows=0,
                    valign='TOP',
                    padding=6
                )
                story.append(t_art)
            else:
                story.append(Paragraph("N/A", self.normal))
            story.append(Spacer(1, 10))

            # YARA Signatures
            story.append(Paragraph("YARA Signatures", self.h2_style))
            yara_data = file_data.get("YARA Signatures", {})
            if yara_data:
                yara_rows = []
                for k, v in yara_data.items():
                    val_str = str(v)
                    if k.lower() in ("rules", "hits") and val_str != "0" and val_str != "N/A":
                        val_str = f"<font color='#dc2626'><b>{val_str}</b></font>"
                    yara_rows.append([
                        Paragraph(f"<b>{k}</b>", self.normal_bold),
                        Paragraph(val_str, self.normal)
                    ])
                t_yara = TableFormatter.build_table(
                    data=yara_rows,
                    col_widths=[150, 354],
                    bg_color=self.bg_light,
                    border_color=self.border_color,
                    is_long=True,
                    repeat_rows=0,
                    valign='TOP',
                    padding=6
                )
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
                t_man = TableFormatter.build_table(
                    data=man_rows,
                    col_widths=[180, 324],
                    bg_color=self.bg_light,
                    border_color=self.border_color,
                    is_long=False,
                    repeat_rows=0,
                    valign='TOP',
                    padding=6
                )
                story.append(t_man)
                break
        if not has_manifest:
            story.append(Paragraph("N/A - Manifest analysis not performed", self.normal))

        story.append(PageBreak())

        # ==================================================
        # 5. DYNAMIC ANALYSIS
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

        analysis_type = meta.get("Analysis Type", "full_detonation")

        # Compute Registry Counts
        reg_added_cnt = 0
        reg_deleted_cnt = 0
        reg_modified_cnt = 0

        p1_reg = []
        p2_reg = []

        if analysis_type == "bifurcated":
            for ev in telemetry.get("Registry", []):
                ev_str = str(ev)
                ev_upper = ev_str.upper()
                if "DELETE" in ev_upper:
                    reg_deleted_cnt += 1
                elif "WRITE" in ev_upper or "ADD" in ev_upper or "CREATE" in ev_upper:
                    reg_added_cnt += 1
                else:
                    reg_modified_cnt += 1
                
                # Segregate by Phase
                if "PHASE: MAIN_PAYLOAD" in ev_upper:
                    clean_ev = ev_str.replace(" [Phase: MAIN_PAYLOAD]", "").replace(" [Phase: INSTALLER_WRAPPER]", "")
                    p2_reg.append(clean_ev)
                else:
                    clean_ev = ev_str.replace(" [Phase: MAIN_PAYLOAD]", "").replace(" [Phase: INSTALLER_WRAPPER]", "")
                    p1_reg.append(clean_ev)
        else:
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
        if analysis_type == "bifurcated":
            story.append(Paragraph("Registry Entries Made by the Application", self.h2_style))
            story.append(Paragraph(
                f"Summary of registry activity: <b>{reg_added_cnt}</b> created/added, <b>{reg_modified_cnt}</b> modified, and <b>{reg_deleted_cnt}</b> deleted.",
                self.normal
            ))
            story.append(Spacer(1, 5))
            
            # Phase 1
            story.append(Paragraph(f"<b>Phase 1: Installation (Installer Wrapper) Registry Changes</b> &mdash; <b>{len(p1_reg)}</b> changes recorded.", self.normal))
            story.append(Spacer(1, 8))

            # Phase 2
            story.append(Paragraph(f"<b>Phase 2: Payload Testing (Main Payload) Registry Changes</b> &mdash; <b>{len(p2_reg)}</b> changes recorded.", self.normal))
            story.append(Spacer(1, 10))
        else:
            story.append(Paragraph("Registry Entry Made by the Application", self.h2_style))
            story.append(Paragraph(
                f"Summary of registry activity: <b>{reg_added_cnt}</b> created/added, <b>{reg_modified_cnt}</b> modified, and <b>{reg_deleted_cnt}</b> deleted.",
                self.normal
            ))
            story.append(Spacer(1, 5))

            reg_header = [
                Paragraph("<b>Registry Key / Value Path</b>", self.normal_bold),
                Paragraph("<b>Operation Type</b>", self.normal_bold)
            ]
            reg_rows = [reg_header]
            if "process_tree_generation" in telemetry:
                reg_data = telemetry.get("registry_monitoring", {})
                for k in reg_data.get("keys_deleted", []):
                    reg_rows.append([Paragraph(f"<font color='#dc2626'>{k}</font>", self.code_style), Paragraph("<font color='#dc2626'><b>[!] KEY DELETED</b></font>", self.normal)])
                for v in reg_data.get("values_deleted", []):
                    reg_rows.append([Paragraph(f"<font color='#dc2626'>{v}</font>", self.code_style), Paragraph("<font color='#dc2626'><b>[!] VALUE DELETED</b></font>", self.normal)])
                for val in reg_data.get("values_added", []):
                    path = val.get("path", "")
                    is_sus = any(x in path.lower() for x in ["run", "runonce", "startup", "services", "winlogon"])
                    p_style = f"<font color='#dc2626'><b>[!] {path}</b></font>" if is_sus else path
                    op_style = f"<font color='#dc2626'><b>VALUE ADDED ({val.get('type')})</b></font>" if is_sus else f"VALUE ADDED ({val.get('type')})"
                    reg_rows.append([Paragraph(p_style, self.code_style), Paragraph(op_style, self.normal)])
                for val in reg_data.get("values_modified", []):
                    path = val.get("path", "")
                    is_sus = any(x in path.lower() for x in ["run", "runonce", "startup", "services", "winlogon"])
                    p_style = f"<font color='#dc2626'><b>[!] {path}</b></font>" if is_sus else path
                    op_style = f"<font color='#dc2626'><b>VALUE MODIFIED ({val.get('type')})</b></font>" if is_sus else f"VALUE MODIFIED ({val.get('type')})"
                    reg_rows.append([Paragraph(p_style, self.code_style), Paragraph(op_style, self.normal)])
            else:
                for ev in telemetry.get("Registry", []):
                    reg_rows.append([Paragraph(str(ev), self.code_style), Paragraph("MUTATED", self.normal)])

            if len(reg_rows) > 1:
                t_reg = TableFormatter.build_table(
                    data=reg_rows,
                    col_widths=[384, 120],
                    bg_color=self.bg_light,
                    border_color=self.border_color,
                    is_long=True,
                    repeat_rows=1,
                    valign='TOP',
                    header_bg=self.primary_color,
                    padding=6
                )
                story.append(t_reg)
            else:
                story.append(Paragraph("N/A - No registry mutations captured", self.normal))
            story.append(Spacer(1, 10))

        # Compute File System Counts
        fs_created_cnt = 0
        fs_deleted_cnt = 0
        fs_modified_cnt = 0
        folder_created_cnt = 0
        folder_modified_cnt = 0
        folder_deleted_cnt = 0

        p1_fs = []
        p2_fs = []

        if analysis_type == "bifurcated":
            for ev in telemetry.get("Filesystem", []):
                ev_str = str(ev)
                ev_upper = ev_str.upper()
                if "DELETE" in ev_upper:
                    fs_deleted_cnt += 1
                elif "CREATE" in ev_upper or "DROP" in ev_upper:
                    fs_created_cnt += 1
                else:
                    fs_modified_cnt += 1
                
                # Segregate by Phase
                if "PHASE: MAIN_PAYLOAD" in ev_upper:
                    clean_ev = ev_str.replace(" [Phase: MAIN_PAYLOAD]", "").replace(" [Phase: INSTALLER_WRAPPER]", "")
                    p2_fs.append(clean_ev)
                else:
                    clean_ev = ev_str.replace(" [Phase: MAIN_PAYLOAD]", "").replace(" [Phase: INSTALLER_WRAPPER]", "")
                    p1_fs.append(clean_ev)
        else:
            if "process_tree_generation" in telemetry:
                fs_data = telemetry.get("file_system_monitoring", {})
                fs_created_cnt = len(fs_data.get("files_created", []))
                fs_deleted_cnt = len(fs_data.get("files_deleted", []))
                fs_modified_cnt = len(fs_data.get("files_modified", [])) + len(fs_data.get("files_renamed", []))
                folder_created_cnt = len(fs_data.get("folders_created", []))
                folder_modified_cnt = len(fs_data.get("folders_modified", []))
                folder_deleted_cnt = len(fs_data.get("folders_deleted", []))
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

        story.append(Spacer(1, 15))
        story.append(get_divider())
        story.append(Spacer(1, 15))

        # 2. File and Folder Changes Made During Installation
        if analysis_type == "bifurcated":
            story.append(Paragraph("File and Folder Changes Made by the Application", self.h2_style))
            story.append(Paragraph(
                f"Summary of file changes: <b>{fs_created_cnt}</b> created, <b>{fs_modified_cnt}</b> modified, and <b>{fs_deleted_cnt}</b> deleted.",
                self.normal
            ))
            story.append(Spacer(1, 5))
            
            # Phase 1
            story.append(Paragraph(f"<b>Phase 1: Installation (Installer Wrapper) File Changes</b> &mdash; <b>{len(p1_fs)}</b> changes recorded.", self.normal))
            story.append(Spacer(1, 8))

            # Phase 2
            story.append(Paragraph(f"<b>Phase 2: Payload Testing (Main Payload) File Changes</b> &mdash; <b>{len(p2_fs)}</b> changes recorded.", self.normal))
            story.append(Spacer(1, 10))
        else:
            story.append(Paragraph("File and Folder Changes Made During Installation", self.h2_style))
            story.append(Paragraph(
                f"Summary of file changes: <b>{fs_created_cnt}</b> created, <b>{fs_modified_cnt}</b> modified, and <b>{fs_deleted_cnt}</b> deleted.",
                self.normal
            ))
            story.append(Paragraph(
                f"Summary of folder changes: <b>{folder_created_cnt}</b> created, <b>{folder_modified_cnt}</b> modified, and <b>{folder_deleted_cnt}</b> deleted.",
                self.normal
            ))
            story.append(Spacer(1, 10))

            fs_header = [
                Paragraph("<b>File / Folder Path</b>", self.normal_bold),
                Paragraph("<b>Operation Type</b>", self.normal_bold)
            ]
            fs_rows = [fs_header]
            if "process_tree_generation" in telemetry:
                fs_data = telemetry.get("file_system_monitoring", {})
                sus_fs_keywords = ["temp", "appdata", "roaming", "\\tmp\\", "programdata", "startup", "system32", "syswow64"]
                sus_ext = [".exe", ".dll", ".bat", ".ps1", ".vbs", ".cmd", ".scr", ".pif"]
                def _is_sus_path(p):
                    pl = p.lower()
                    return any(k in pl for k in sus_fs_keywords) or any(pl.endswith(e) for e in sus_ext)
                # File changes
                for f in fs_data.get("files_created", []):
                    if _is_sus_path(f):
                        fs_rows.append([Paragraph(f"<font color='#dc2626'><b>[!] {f}</b></font>", self.code_style), Paragraph("<font color='#dc2626'><b>FILE CREATED</b></font>", self.normal)])
                    else:
                        fs_rows.append([Paragraph(f, self.code_style), Paragraph("FILE CREATED", self.normal)])
                for f in fs_data.get("files_modified", []):
                    if _is_sus_path(f):
                        fs_rows.append([Paragraph(f"<font color='#dc2626'><b>[!] {f}</b></font>", self.code_style), Paragraph("<font color='#dc2626'><b>FILE MODIFIED</b></font>", self.normal)])
                    else:
                        fs_rows.append([Paragraph(f, self.code_style), Paragraph("FILE MODIFIED", self.normal)])
                for f in fs_data.get("files_deleted", []):
                    fs_rows.append([Paragraph(f"<font color='#dc2626'>{f}</font>", self.code_style), Paragraph("<font color='#dc2626'><b>FILE DELETED</b></font>", self.normal)])
                for f in fs_data.get("files_renamed", []):
                    fs_rows.append([Paragraph(f, self.code_style), Paragraph("FILE RENAMED", self.normal)])
                # Folder changes
                for f in fs_data.get("folders_created", []):
                    if _is_sus_path(f):
                        fs_rows.append([Paragraph(f"<font color='#dc2626'><b>[!] {f}</b></font>", self.code_style), Paragraph("<font color='#dc2626'><b>FOLDER CREATED</b></font>", self.normal)])
                    else:
                        fs_rows.append([Paragraph(f, self.code_style), Paragraph("FOLDER CREATED", self.normal)])
                for f in fs_data.get("folders_modified", []):
                    if _is_sus_path(f):
                        fs_rows.append([Paragraph(f"<font color='#dc2626'><b>[!] {f}</b></font>", self.code_style), Paragraph("<font color='#dc2626'><b>FOLDER MODIFIED</b></font>", self.normal)])
                    else:
                        fs_rows.append([Paragraph(f, self.code_style), Paragraph("FOLDER MODIFIED", self.normal)])
                for f in fs_data.get("folders_deleted", []):
                    fs_rows.append([Paragraph(f"<font color='#dc2626'>{f}</font>", self.code_style), Paragraph("<font color='#dc2626'><b>FOLDER DELETED</b></font>", self.normal)])
            else:
                for ev in telemetry.get("Filesystem", []):
                    fs_rows.append([Paragraph(str(ev), self.code_style), Paragraph("MUTATED", self.normal)])

            if len(fs_rows) > 1:
                t_fs = TableFormatter.build_table(
                    data=fs_rows,
                    col_widths=[384, 120],
                    bg_color=self.bg_light,
                    border_color=self.border_color,
                    is_long=True,
                    repeat_rows=1,
                    valign='TOP',
                    header_bg=self.primary_color,
                    padding=6
                )
                story.append(t_fs)
            else:
                story.append(Paragraph("N/A - No file or folder changes captured", self.normal))
            story.append(Spacer(1, 10))

        story.append(Spacer(1, 15))
        story.append(get_divider())
        story.append(Spacer(1, 15))
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
                t_high = TableFormatter.build_table(
                    data=high_rows,
                    col_widths=[110, 140, 254],
                    bg_color=self.bg_light,
                    border_color=self.border_color,
                    is_long=True,
                    repeat_rows=1,
                    valign='TOP',
                    header_bg=self.primary_color,
                    padding=6
                )
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
            
            display_low_conf = low_conf[:15]
            for item in display_low_conf:
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
                
            if len(low_conf) > 15:
                remaining = len(low_conf) - 15
                low_rows.append([
                    Paragraph("<b>...</b>", self.normal_bold),
                    Paragraph("<b>...</b>", self.normal_bold),
                    Paragraph(f"<i>[!] {remaining} other low-confidence system noise/lingering entries omitted for report readability.</i>", self.normal_bold)
                ])
                
            if len(low_rows) > 1:
                t_low = TableFormatter.build_table(
                    data=low_rows,
                    col_widths=[110, 140, 254],
                    bg_color=self.bg_light,
                    border_color=self.border_color,
                    is_long=True,
                    repeat_rows=1,
                    valign='TOP',
                    header_bg=self.primary_color,
                    padding=6
                )
                story.append(t_low)
            else:
                story.append(Paragraph("No low-confidence system noise/lingering modifications detected.", self.normal))
                
            story.append(Spacer(1, 8))
            
        else:
            # Fallback legacy layout
            pers_rows = [[
                Paragraph("<b>Category / Mechanism</b>", self.normal_bold),
                Paragraph("<b>Details / Target</b>", self.normal_bold),
                Paragraph("<b>Command / Associated Path</b>", self.normal_bold)
            ]]
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
            
            if len(pers_rows) > 1:
                t_pers = TableFormatter.build_table(
                    data=pers_rows,
                    col_widths=[120, 150, 234],
                    bg_color=self.bg_light,
                    border_color=self.border_color,
                    is_long=True,
                    repeat_rows=1,
                    valign='TOP',
                    header_bg=self.primary_color,
                    padding=6
                )
                story.append(t_pers)
            else:
                story.append(Paragraph("N/A - No persistence mechanisms established", self.normal))
            story.append(Spacer(1, 10))

        story.append(Spacer(1, 15))
        story.append(get_divider())
        story.append(Spacer(1, 15))
        # 4. Process Initialization
        proc_flowables = [
            Paragraph("Process Initialization", self.h2_style)
        ]
        
        # Embed WMI Process Tree Visual Graph
        img_path = telemetry.get("analysis_metadata", {}).get("process_tree_image_path", "")
        if img_path and os.path.exists(img_path):
            proc_flowables.append(Image(img_path, width=460, height=276))
            proc_flowables.append(Spacer(1, 10))
            
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
                proc_flowables.append(Paragraph(tree_str, self.code_style))
        else:
            proc_events = telemetry.get("Processes", [])
            if proc_events:
                has_proc = True
                for ev in proc_events:
                    proc_flowables.append(Paragraph(f"• {ev}", self.normal))

        if not has_proc:
            proc_flowables.append(Paragraph("N/A - No process initialization recorded", self.normal))
        proc_flowables.append(Spacer(1, 10))

        story.append(KeepTogether(proc_flowables))

        story.append(Spacer(1, 15))
        story.append(get_divider())
        story.append(Spacer(1, 15))
        # 7. Resource Utility
        res_flowables = [
            Paragraph("Resource Utility", self.h2_style)
        ]
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
                t_res = TableFormatter.build_table(
                    data=peak_rows,
                    col_widths=[180, 324],
                    bg_color=self.bg_light,
                    border_color=self.border_color,
                    is_long=False,
                    repeat_rows=0,
                    valign='TOP',
                    padding=6
                )
                res_flowables.append(t_res)
                
                # Render CPU utilization profile graph if present
                cpu_img = peak.get("cpu_graph_image_path", "")
                if cpu_img and os.path.exists(cpu_img):
                    res_flowables.append(Spacer(1, 10))
                    res_flowables.append(Image(cpu_img, width=460, height=184))
                    res_flowables.append(Spacer(1, 5))
        
        if not has_res:
            res_flowables.append(Paragraph("N/A - Resource utility monitoring not performed", self.normal))
        res_flowables.append(Spacer(1, 10))

        story.append(KeepTogether(res_flowables))

        story.append(Spacer(1, 15))
        story.append(get_divider())
        story.append(Spacer(1, 15))
        # 8. Dropped / Loaded DLLs
        story.append(Paragraph("Dropped / Loaded DLLs", self.h2_style))
        dll_info = telemetry.get("dll_signature_monitoring", {})
        dll_details = dll_info.get("details", [])
        unsigned_count = dll_info.get("unsigned_dlls_count", 0)

        if analysis_type == "bifurcated" and dll_details:
            p1_dlls = [d for d in dll_details if d.get("analysis_phase") != "MAIN_PAYLOAD"]
            p2_dlls = [d for d in dll_details if d.get("analysis_phase") == "MAIN_PAYLOAD"]
            
            p1_unsigned = len([d for d in p1_dlls if d.get("signature_status") == "UNSIGNED"])
            p2_unsigned = len([d for d in p2_dlls if d.get("signature_status") == "UNSIGNED"])
            
            def draw_dll_table(dlls):
                dll_table_data = [[
                    Paragraph("<b>DLL Name</b>", self.normal_bold),
                    Paragraph("<b>Path</b>", self.normal_bold),
                    Paragraph("<b>Signature</b>", self.normal_bold),
                    Paragraph("<b>Risk Indicators</b>", self.normal_bold),
                ]]
                for dll in dlls:
                    sig_status = dll.get("signature_status", "UNKNOWN")
                    sig_color = "#dc2626" if sig_status == "UNSIGNED" else "#16a34a"
                    risk_indicators = dll.get("risk_indicators", [])
                    risk_text = ", ".join(risk_indicators) if risk_indicators else "None"
                    risk_styled = f"<font color='#dc2626'><b>{risk_text}</b></font>" if risk_indicators else "None"
                    dll_name = dll.get("dll_name", "Unknown")
                    dll_path = dll.get("dll_path", "N/A")
                    if sig_status == "UNSIGNED":
                        name_p = Paragraph(f"<font color='#dc2626'><b>[!] {dll_name}</b></font>", self.normal_bold)
                        path_p = Paragraph(f"<font color='#dc2626'>{dll_path}</font>", self.code_style)
                    else:
                        name_p = Paragraph(dll_name, self.normal)
                        path_p = Paragraph(dll_path, self.code_style)
                    dll_table_data.append([
                        name_p,
                        path_p,
                        Paragraph(f"<font color='{sig_color}'><b>{sig_status}</b></font>", self.normal),
                        Paragraph(risk_styled, self.normal),
                    ])
                return TableFormatter.build_table(
                    data=dll_table_data,
                    col_widths=[90, 190, 74, 150],
                    bg_color=self.bg_light,
                    border_color=self.border_color,
                    is_long=True,
                    repeat_rows=1,
                    valign='TOP',
                    header_bg=self.primary_color,
                    padding=6
                )
                
            story.append(Paragraph("<b>Phase 1: Installation (Installer Wrapper) Loaded/Dropped DLLs</b>", self.normal_bold))
            if p1_unsigned:
                story.append(Paragraph(f"<font color='#dc2626'><b>{p1_unsigned} unsigned DLL(s)</b></font> detected in Phase 1.", self.normal))
                story.append(Spacer(1, 4))
            if p1_dlls:
                story.append(draw_dll_table(p1_dlls))
            else:
                story.append(Paragraph("No DLLs loaded or dropped in Phase 1.", self.normal))
            story.append(Spacer(1, 8))
            
            story.append(Paragraph("<b>Phase 2: Payload Testing (Main Payload) Loaded/Dropped DLLs</b>", self.normal_bold))
            if p2_unsigned:
                story.append(Paragraph(f"<font color='#dc2626'><b>{p2_unsigned} unsigned DLL(s)</b></font> detected in Phase 2.", self.normal))
                story.append(Spacer(1, 4))
            if p2_dlls:
                story.append(draw_dll_table(p2_dlls))
            else:
                story.append(Paragraph("No DLLs loaded or dropped in Phase 2.", self.normal))
            story.append(Spacer(1, 10))

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
            hash_table = TableFormatter.build_table(
                data=hash_data,
                col_widths=[120, 384],
                bg_color=self.bg_light,
                border_color=self.border_color,
                is_long=True,
                repeat_rows=1,
                valign='TOP',
                header_bg=self.primary_color,
                padding=6
            )
            story.append(hash_table)
            
        elif dll_details:
            dll_table_data = [[
                Paragraph("<b>DLL Name</b>", self.normal_bold),
                Paragraph("<b>Path</b>", self.normal_bold),
                Paragraph("<b>Signature</b>", self.normal_bold),
                Paragraph("<b>Risk Indicators</b>", self.normal_bold),
            ]]
            for dll in dll_details:
                sig_status = dll.get("signature_status", "UNKNOWN")
                sig_color = "#dc2626" if sig_status == "UNSIGNED" else "#16a34a"
                risk_indicators = dll.get("risk_indicators", [])
                risk_text = ", ".join(risk_indicators) if risk_indicators else "None"
                risk_styled = f"<font color='#dc2626'><b>{risk_text}</b></font>" if risk_indicators else "None"

                dll_name = dll.get("dll_name", "Unknown")
                dll_path = dll.get("dll_path", "N/A")
                if sig_status == "UNSIGNED":
                    name_p = Paragraph(f"<font color='#dc2626'><b>[!] {dll_name}</b></font>", self.normal_bold)
                    path_p = Paragraph(f"<font color='#dc2626'>{dll_path}</font>", self.code_style)
                else:
                    name_p = Paragraph(dll_name, self.normal)
                    path_p = Paragraph(dll_path, self.code_style)

                dll_table_data.append([
                    name_p,
                    path_p,
                    Paragraph(f"<font color='{sig_color}'><b>{sig_status}</b></font>", self.normal),
                    Paragraph(risk_styled, self.normal),
                ])

            dll_table = TableFormatter.build_table(
                data=dll_table_data,
                col_widths=[90, 190, 74, 150],
                bg_color=self.bg_light,
                border_color=self.border_color,
                is_long=True,
                repeat_rows=1,
                valign='TOP',
                header_bg=self.primary_color,
                padding=6
            )
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
            hash_table = TableFormatter.build_table(
                data=hash_data,
                col_widths=[120, 384],
                bg_color=self.bg_light,
                border_color=self.border_color,
                is_long=True,
                repeat_rows=1,
                valign='TOP',
                header_bg=self.primary_color,
                padding=6
            )
            story.append(hash_table)
        else:
            story.append(Paragraph("No DLLs were dropped or loaded during execution.", self.normal))

        # 9. Network Communication Analysis
        story.append(Spacer(1, 15))
        story.append(get_divider())
        story.append(Spacer(1, 15))
        story.append(Paragraph("Network Communication Analysis", self.h2_style))
        net_info = telemetry.get("network_communication_analysis", {})
        net_details = net_info.get("details", [])
        total_connections = net_info.get("summary", {}).get("total_connections", 0)

        if analysis_type == "bifurcated" and net_details:
            p1_net = [n for n in net_details if n.get("analysis_phase") != "MAIN_PAYLOAD"]
            p2_net = [n for n in net_details if n.get("analysis_phase") == "MAIN_PAYLOAD"]

            story.append(Paragraph(
                f"Total connections/requests captured: <b>{total_connections}</b>",
                self.normal
            ))
            story.append(Spacer(1, 8))

            def draw_net_table(conns):
                net_table_data = [[
                    Paragraph("<b>Protocol</b>", self.normal_bold),
                    Paragraph("<b>Port</b>", self.normal_bold),
                    Paragraph("<b>Direction</b>", self.normal_bold),
                    Paragraph("<b>Activity / Domain / Command</b>", self.normal_bold),
                ]]
                sus_ports = {80, 443, 8080, 8443, 53, 21, 22, 23, 25, 110, 143, 3389, 445}
                for conn in conns:
                    proto = conn.get("protocol", "N/A")
                    port = str(conn.get("dst_port", "N/A"))
                    direct = conn.get("direction", "OUTBOUND")
                    action = conn.get("scapy_action", "") or conn.get("domain", "") or "N/A"

                    is_outbound = direct.upper() == "OUTBOUND"
                    is_suspicious_net = is_outbound

                    if is_suspicious_net:
                        net_table_data.append([
                            Paragraph(f"<font color='#dc2626'><b>{proto}</b></font>", self.normal),
                            Paragraph(f"<font color='#dc2626'><b>{port}</b></font>", self.normal),
                            Paragraph(f"<font color='#dc2626'><b>{direct}</b></font>", self.normal),
                            Paragraph(f"<font color='#dc2626'><b>[!] {action}</b></font>", self.code_style),
                        ])
                    else:
                        net_table_data.append([
                            Paragraph(proto, self.normal),
                            Paragraph(port, self.normal),
                            Paragraph(direct, self.normal),
                            Paragraph(action, self.code_style),
                        ])
                return TableFormatter.build_table(
                    data=net_table_data,
                    col_widths=[64, 54, 74, 312],
                    bg_color=self.bg_light,
                    border_color=self.border_color,
                    is_long=True,
                    repeat_rows=1,
                    valign='TOP',
                    header_bg=self.primary_color,
                    padding=6
                )

            story.append(Paragraph("<b>Phase 1: Installation (Installer Wrapper) Network Traffic</b>", self.normal_bold))
            story.append(Spacer(1, 4))
            if p1_net:
                story.append(draw_net_table(p1_net))
            else:
                story.append(Paragraph("No network activity captured in Phase 1.", self.normal))
            story.append(Spacer(1, 8))

            story.append(Paragraph("<b>Phase 2: Payload Testing (Main Payload) Network Traffic</b>", self.normal_bold))
            story.append(Spacer(1, 4))
            if p2_net:
                story.append(draw_net_table(p2_net))
            else:
                story.append(Paragraph("No network activity captured in Phase 2.", self.normal))
            story.append(Spacer(1, 10))

        elif net_details:
            story.append(Paragraph(
                f"Total connections/requests captured: <b>{total_connections}</b>",
                self.normal
            ))
            story.append(Spacer(1, 8))
            net_table_data = [[
                Paragraph("<b>Protocol</b>", self.normal_bold),
                Paragraph("<b>Port</b>", self.normal_bold),
                Paragraph("<b>Direction</b>", self.normal_bold),
                Paragraph("<b>Activity / Domain / Command</b>", self.normal_bold),
            ]]
            
            sus_ports = {80, 443, 8080, 8443, 53, 21, 22, 23, 25, 110, 143, 3389, 445}
            for conn in net_details:
                proto = conn.get("protocol", "N/A")
                port = str(conn.get("dst_port", "N/A"))
                direct = conn.get("direction", "OUTBOUND")
                action = conn.get("scapy_action", "") or conn.get("domain", "") or "N/A"
                
                is_outbound = direct.upper() == "OUTBOUND"
                is_suspicious_net = is_outbound

                if is_suspicious_net:
                    net_table_data.append([
                        Paragraph(f"<font color='#dc2626'><b>{proto}</b></font>", self.normal),
                        Paragraph(f"<font color='#dc2626'><b>{port}</b></font>", self.normal),
                        Paragraph(f"<font color='#dc2626'><b>{direct}</b></font>", self.normal),
                        Paragraph(f"<font color='#dc2626'><b>[!] {action}</b></font>", self.code_style),
                    ])
                else:
                    net_table_data.append([
                        Paragraph(proto, self.normal),
                        Paragraph(port, self.normal),
                        Paragraph(direct, self.normal),
                        Paragraph(action, self.code_style),
                    ])
                
            net_table = TableFormatter.build_table(
                data=net_table_data,
                col_widths=[64, 54, 74, 312],
                bg_color=self.bg_light,
                border_color=self.border_color,
                is_long=True,
                repeat_rows=1,
                valign='TOP',
                header_bg=self.primary_color,
                padding=6
            )
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
                net_table = TableFormatter.build_table(
                    data=net_table_data,
                    col_widths=[504],
                    bg_color=self.bg_light,
                    border_color=self.border_color,
                    is_long=True,
                    repeat_rows=1,
                    valign='TOP',
                    header_bg=self.primary_color,
                    padding=6
                )
                story.append(net_table)
            else:
                story.append(Paragraph("No network activity captured during execution.", self.normal))

        return story

    def _extract_iocs_data(self, data: dict) -> dict:
        """Extracts indicators of compromise (IOCs) from generated report data structure."""
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
                v = DataCleaner.clean_hash(v)
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


# ═══════════════════════════════════════════════════════════════════════════
# COMPATIBILITY WRAPPER CLASS
# ═══════════════════════════════════════════════════════════════════════════
class ReportGenerator:
    """
    Backward-compatible wrapper for PDFReportBuilder.
    Allows existing client calls to remain unchanged.
    """
    def __init__(self, config: dict) -> None:
        self.config = config
        self.builder = PDFReportBuilder(config)

    def generate_reports(
        self,
        metadata:        dict,
        package_data:    list,
        static_data:     dict,
        dynamic_data:    dict | None = None,
        dynamic_summary: dict | None = None,
        scoring_results: dict | None = None,
    ) -> None:
        """Invokes the modern report generation builder."""
        self.builder.generate_reports(
            metadata=metadata,
            package_data=package_data,
            static_data=static_data,
            dynamic_data=dynamic_data,
            dynamic_summary=dynamic_summary,
            scoring_results=scoring_results
        )

    def _build_pdf(self, data: dict, path: str, *, scoring_results: dict | None = None) -> None:
        """Invokes the modern PDF compiler."""
        self.builder._build_pdf(data, path, scoring_results=scoring_results)
