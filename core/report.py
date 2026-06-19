"""
MARS — Report Generator (ReportLab)
=====================================
Produces a structured PDF with:
  * Title page
  * Auto-generated Table of Contents (two-pass build for correct page numbers)
  * Section 1 — File Intake Summary
  * Section 2 — Package & Archive Unpacking
  * Section 3 — Deep Static Analysis
  * Section 4 — Dynamic Sandbox Analysis

PARAMETER DESCRIPTIONS
------------------------
Each analysed field can carry a human-readable description that appears as
italic helper text directly beneath the value in the report.  Fill in the
TODO strings in PARAM_DESCRIPTIONS below; any entry that still starts with
"TODO" is silently omitted from the rendered PDF so the layout stays clean
until descriptions are written.
"""

import os
import json
import datetime
from pubsub import pub

# ---------------------------------------------------------------------------
# ReportLab
# ---------------------------------------------------------------------------
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame,
    Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether, NextPageTemplate,
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.pdfbase import pdfmetrics

from core.dynamic import TELEMETRY_KEYS

# ===========================================================================
# PARAMETER DESCRIPTIONS
# ===========================================================================
# Replace "TODO: …" strings with a plain-English sentence explaining what
# the field means.  Entries that still begin with "TODO" are not shown in
# the PDF, so partial completion is fine.
# ---------------------------------------------------------------------------

PARAM_DESCRIPTIONS: dict[str, str] = {

    # ------------------------------------------------------------------
    # Section 1 — File Intake Summary
    # ------------------------------------------------------------------
    "Analysis ID":
        "TODO: Unique identifier auto-generated for this analysis session.",
    "Filename":
        "TODO: Original filename of the submitted sample as read from disk.",
    "File Path":
        "TODO: Absolute filesystem path from which the sample was ingested.",
    "Extension":
        "TODO: File extension used to determine the analysis pipeline branch.",
    "File Size":
        "TODO: Total size of the submitted file in bytes.",
    "MD5":
        "TODO: MD5 digest of the file — used for fast de-duplication checks.",
    "SHA1":
        "TODO: SHA-1 digest of the file.",
    "SHA256":
        "TODO: SHA-256 cryptographic hash — primary unique identifier for the sample.",
    "Magic Bytes":
        "TODO: First four bytes of the file used to verify the true file type.",
    "Submission Timestamp":
        "TODO: UTC date and time at which the file was submitted to the pipeline.",

    # ------------------------------------------------------------------
    # Section 3 — PE Headers
    # ------------------------------------------------------------------
    "Machine Architecture":
        "TODO: Target CPU architecture encoded in the PE COFF File Header (e.g. 0x14c = x86).",
    "Compile Timestamp":
        "TODO: Date and time the binary was linked, taken from the PE File Header. Can be forged.",
    "DOS Header Offset (e_lfanew)":
        "TODO: Byte offset of the PE signature from the start of the file (DOS stub field e_lfanew).",
    "Address of Entry Point":
        "TODO: RVA of the first instruction executed; unusual values may indicate packing.",
    "Image Base":
        "TODO: Preferred virtual address at which the image is loaded into memory.",
    "Number of Sections":
        "TODO: Count of PE sections; unusually high or low values can indicate packing.",

    # ------------------------------------------------------------------
    # Section 3 — Mitigations
    # ------------------------------------------------------------------
    "DEP / NX Bit":
        "TODO: Data Execution Prevention — prevents shellcode in data pages from executing.",
    "ASLR":
        "TODO: Address Space Layout Randomisation — randomises base addresses to hinder ROP chains.",
    "CFG (Control Flow Guard)":
        "TODO: Microsoft's control-flow integrity mechanism that validates indirect call targets.",
    "RFG (Return Flow Guard)":
        "TODO: Return-oriented-programming mitigation that validates return addresses.",
    "SafeSEH":
        "TODO: Structured Exception Handler protection — validates handlers against a compile-time table.",
    "Stack Canaries (/GS)":
        "TODO: Compiler-inserted stack cookie that detects stack-smashing overflows at runtime.",
    "Hardware Protection (CET/Shadow Stack)":
        "TODO: Intel CET Shadow Stack — hardware-enforced return-address integrity.",
    "Force Integrity":
        "TODO: Requires the binary to carry a valid Authenticode signature before loading.",
    "Isolation / AppContainer":
        "TODO: Binary runs inside an AppContainer sandbox with restricted privilege.",

    # ------------------------------------------------------------------
    # Section 3 — Sections
    # ------------------------------------------------------------------
    "Section Permissions":
        "TODO: R/W/E permission bits for each PE section; RWE is highly suspicious.",
    "Section Entropy":
        "TODO: Shannon entropy score (0–8); values >= 7.0 suggest packing or encryption.",

    # ------------------------------------------------------------------
    # Section 3 — Imports
    # ------------------------------------------------------------------
    "Tracked APIs Found":
        "TODO: Number of monitored Win32 API imports identified in the Import Address Table.",
    "APIs":
        "TODO: Comma-separated list of suspicious API names found; cross-reference with ATT&CK.",

    # ------------------------------------------------------------------
    # Section 3 — Manifest Data
    # ------------------------------------------------------------------
    "Manifest Status":
        "TODO: Whether a valid XML application manifest was found and parsed inside the PE resources.",
    "Requested Execution Level":
        "TODO: Privilege level declared by the manifest (asInvoker / highestAvailable / requireAdministrator).",

    # ------------------------------------------------------------------
    # Section 3 — Strings Analytics
    # ------------------------------------------------------------------
    "IPv4":
        "TODO: Count of IPv4 addresses extracted via regex; may indicate C2 infrastructure.",
    "IPv6":
        "TODO: Count of IPv6 addresses found in the binary.",
    "URL":
        "TODO: Count of HTTP/HTTPS URLs embedded in the binary.",
    "Registry":
        "TODO: Count of registry key paths extracted; persistence and configuration artefacts.",
    "Email":
        "TODO: Count of email addresses found; can indicate author attribution or phishing targets.",
    "Password-Like":
        "TODO: Count of strings matching a high-complexity password pattern.",

    # ------------------------------------------------------------------
    # Section 3 — YARA
    # ------------------------------------------------------------------
    "Hits":
        "TODO: Total number of YARA rule signatures that matched against the sample.",
    "Matched Rules":
        "TODO: Comma-separated list of YARA rule names that fired; each rule name encodes a threat family.",

    # ------------------------------------------------------------------
    # Section 2 — Package Extraction
    # ------------------------------------------------------------------
    "Total Extracted Files":
        "TODO: Number of files unpacked from the archive or MSI payload.",
    "Flagged Payloads":
        "TODO: Count of extracted files whose extension matches a high-risk executable type.",
    "Relative_Path":
        "TODO: Path of the file relative to the archive root.",
    "Extension":
        "TODO: File extension of the extracted artefact.",
    "Size_Bytes":
        "TODO: Size of the extracted file in bytes.",
    "SHA256":
        "TODO: SHA-256 hash of the extracted file.",

    # ------------------------------------------------------------------
    # Section 4 — Dynamic Telemetry categories
    # ------------------------------------------------------------------
    "Filesystem":
        "TODO: File creation, deletion, and modification events observed during sandbox detonation.",
    "Registry":
        "TODO: Windows Registry key reads, writes, and deletions captured during execution.",
    "Persistence":
        "TODO: Mechanisms used by the sample to survive reboots (Run keys, scheduled tasks, services).",
    "Processes":
        "TODO: Child processes spawned and process-injection events observed by the agent.",
    "Memory":
        "TODO: Memory forensics results — injected regions, hollowed processes, and anomalous mappings.",
    "Network":
        "TODO: DNS queries, HTTP/S requests, and raw TCP/UDP connections intercepted by the sandbox.",
    "Hardware":
        "TODO: CPU, disk, and peripheral stress events that may indicate crypto-mining or wipers.",
    "System":
        "TODO: Operating-system level events including privilege escalation and UAC bypass attempts.",
}

# ===========================================================================
# Telemetry category labels (kept in sync with dynamic.py)
# ===========================================================================
CATEGORY_LABELS: dict[str, str] = {
    "Filesystem":   "Filesystem Activity (FR-DYN-01)",
    "Registry":     "Registry Mutations (FR-DYN-02)",
    "Persistence":  "Persistence Mechanisms (FR-DYN-03)",
    "Processes":    "Process Activity (FR-DYN-04)",
    "Memory":       "Memory Forensics (FR-DYN-05)",
    "Network":      "Network Telemetry (FR-DYN-06)",
    "Hardware":     "Hardware / System Stress (FR-DYN-07)",
    "System":       "System & Agent Events",
}

# ===========================================================================
# Colour palette
# ===========================================================================
C_NAVY        = colors.HexColor("#1e2846")   # section header background
C_MIDBLUE     = colors.HexColor("#2c3e6b")   # subsection header background
C_LIGHTBLUE   = colors.HexColor("#dce7ff")   # table header fill
C_ROW_ALT     = colors.HexColor("#f0f4ff")   # alternating table row
C_ACCENT      = colors.HexColor("#e8edf8")   # parameter description background
C_WHITE       = colors.white
C_RED         = colors.HexColor("#c80000")
C_ORANGE      = colors.HexColor("#e06000")
C_DARKTEXT    = colors.HexColor("#1a1a2e")
C_MUTED       = colors.HexColor("#555577")
C_HEADER_TEXT = colors.HexColor("#dce7ff")

PAGE_W, PAGE_H = A4
MARGIN        = 2 * cm
CONTENT_W     = PAGE_W - 2 * MARGIN


# ===========================================================================
# Style sheet
# ===========================================================================
def _build_styles() -> dict:
    base = getSampleStyleSheet()

    def ps(name, **kw) -> ParagraphStyle:
        return ParagraphStyle(name, **kw)

    return {
        # ---- headings (registered with TOC) ----
        "H1": ps("H1",
                 fontName="Helvetica-Bold", fontSize=13,
                 textColor=C_HEADER_TEXT, backColor=C_NAVY,
                 spaceAfter=6, spaceBefore=14,
                 leftIndent=6, rightIndent=6,
                 borderPad=(4, 4, 4, 4)),
        "H2": ps("H2",
                 fontName="Helvetica-Bold", fontSize=11,
                 textColor=C_HEADER_TEXT, backColor=C_MIDBLUE,
                 spaceAfter=4, spaceBefore=10,
                 leftIndent=4, borderPad=(3, 3, 3, 3)),
        "H3": ps("H3",
                 fontName="Helvetica-Bold", fontSize=10,
                 textColor=C_MIDBLUE,
                 spaceAfter=3, spaceBefore=8),

        # ---- body ----
        "Body": ps("Body",
                   fontName="Helvetica", fontSize=9,
                   textColor=C_DARKTEXT,
                   spaceAfter=2, leading=13),
        "BodyBold": ps("BodyBold",
                       fontName="Helvetica-Bold", fontSize=9,
                       textColor=C_DARKTEXT, spaceAfter=2),
        "BodySmall": ps("BodySmall",
                        fontName="Helvetica", fontSize=8,
                        textColor=C_DARKTEXT, leading=11),
        "BodyMono": ps("BodyMono",
                       fontName="Courier", fontSize=8,
                       textColor=C_DARKTEXT, leading=11),

        # ---- description placeholder ----
        "Desc": ps("Desc",
                   fontName="Helvetica-Oblique", fontSize=8,
                   textColor=C_MUTED, spaceAfter=4,
                   leftIndent=4),

        # ---- misc ----
        "Title": ps("Title",
                    fontName="Helvetica-Bold", fontSize=26,
                    textColor=C_WHITE, alignment=TA_CENTER,
                    spaceAfter=8),
        "Subtitle": ps("Subtitle",
                       fontName="Helvetica", fontSize=13,
                       textColor=colors.HexColor("#b0c4f0"),
                       alignment=TA_CENTER, spaceAfter=6),
        "TitleMeta": ps("TitleMeta",
                        fontName="Helvetica", fontSize=10,
                        textColor=colors.HexColor("#90a8d0"),
                        alignment=TA_CENTER, spaceAfter=4),
        "TocEntry": ps("TocEntry",
                       fontName="Helvetica", fontSize=10,
                       textColor=C_DARKTEXT, spaceAfter=3,
                       leftIndent=0),
        "TocEntry2": ps("TocEntry2",
                        fontName="Helvetica", fontSize=9,
                        textColor=C_MUTED, spaceAfter=2,
                        leftIndent=16),
        "Alert": ps("Alert",
                    fontName="Helvetica-Bold", fontSize=9,
                    textColor=C_RED, spaceAfter=2),
        "Warning": ps("Warning",
                      fontName="Helvetica-Bold", fontSize=9,
                      textColor=C_ORANGE, spaceAfter=2),
        "Center": ps("Center",
                     fontName="Helvetica", fontSize=9,
                     alignment=TA_CENTER, textColor=C_DARKTEXT),
        "FooterStyle": ps("FooterStyle",
                          fontName="Helvetica", fontSize=8,
                          textColor=C_MUTED, alignment=TA_CENTER),
    }


# ===========================================================================
# Custom DocTemplate — registers TOC entries in afterFlowable
# ===========================================================================
class _MARSDoc(BaseDocTemplate):
    def __init__(self, path: str, **kw):
        super().__init__(path, **kw)
        self._toc: TableOfContents | None = None

    def attach_toc(self, toc: TableOfContents):
        self._toc = toc

    def afterFlowable(self, flowable):
        """Fires after each flowable is rendered — used to notify the TOC."""
        if not isinstance(flowable, Paragraph):
            return
        style_name = flowable.style.name
        if style_name == "H1":
            self.notify("TOCEntry", (0, flowable.getPlainText(), self.page))
        elif style_name == "H2":
            self.notify("TOCEntry", (1, flowable.getPlainText(), self.page))


# ===========================================================================
# Page-drawing callbacks (header / footer painted on canvas)
# ===========================================================================
def _draw_content_page(canvas, doc):
    """Header + footer for content pages (all pages after the title page)."""
    canvas.saveState()

    # Header bar
    canvas.setFillColor(C_NAVY)
    canvas.rect(0, PAGE_H - 1.1 * cm, PAGE_W, 1.1 * cm, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.setFillColor(C_HEADER_TEXT)
    canvas.drawString(MARGIN, PAGE_H - 0.75 * cm,
                      "MARS \u2014 Malware Analysis & Reverse-engineering System")
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#8090c0"))
    canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 0.75 * cm,
                           datetime.datetime.now().strftime("%Y-%m-%d"))

    # Footer bar
    canvas.setFillColor(C_NAVY)
    canvas.rect(0, 0, PAGE_W, 0.9 * cm, fill=1, stroke=0)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(C_HEADER_TEXT)
    canvas.drawCentredString(PAGE_W / 2, 0.3 * cm,
                             f"Page {doc.page}  |  CONFIDENTIAL — Internal Use Only")

    canvas.restoreState()


def _draw_title_page(canvas, doc):
    """Full-bleed background for the title page — no header/footer text."""
    canvas.saveState()
    canvas.setFillColor(C_NAVY)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    # Decorative accent strip
    canvas.setFillColor(C_MIDBLUE)
    canvas.rect(0, PAGE_H * 0.38, PAGE_W, PAGE_H * 0.28, fill=1, stroke=0)
    canvas.restoreState()


# ===========================================================================
# Helper — safe text (strips non-latin-1 chars for Helvetica)
# ===========================================================================
def _safe(text: str) -> str:
    return str(text).encode("latin-1", "replace").decode("latin-1")


# ===========================================================================
# Helper — description lookup
# ===========================================================================
def _desc(key: str) -> str | None:
    """Return the description string if it is filled in, else None."""
    raw = PARAM_DESCRIPTIONS.get(key, "")
    if not raw or raw.startswith("TODO"):
        return None
    return raw


# ===========================================================================
# Helper — build a two-column parameter table
# ===========================================================================
def _param_table(rows: list[tuple], styles: dict) -> Table:
    """
    rows: list of (key, value) pairs.
    Returns a styled ReportLab Table.
    """
    table_data = []
    for i, (k, v) in enumerate(rows):
        key_para   = Paragraph(_safe(str(k)), styles["BodyBold"])
        val_text   = _safe(str(v))
        val_style  = styles["Alert"] if ("[CRITICAL]" in val_text or "[PACKED" in val_text or "[SUSPICIOUS" in val_text) \
                     else styles["Warning"] if "[WARNING]" in val_text \
                     else styles["BodyMono"]
        val_para   = Paragraph(val_text, val_style)
        desc       = _desc(str(k))
        if desc:
            val_cell = [val_para, Paragraph(desc, styles["Desc"])]
        else:
            val_cell = [val_para]
        table_data.append([key_para, val_cell])

    col_w = [CONTENT_W * 0.32, CONTENT_W * 0.68]
    tbl = Table(table_data, colWidths=col_w, repeatRows=0)

    style_cmds = [
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",(0, 0), (-1, -1), 6),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0,0), (-1, -1), 4),
        ("LINEBELOW",   (0, 0), (-1, -2), 0.25, colors.HexColor("#d0d8f0")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_WHITE, C_ROW_ALT]),
        ("BOX",         (0, 0), (-1, -1), 0.5, colors.HexColor("#c0ccee")),
    ]
    tbl.setStyle(TableStyle(style_cmds))
    return tbl


# ===========================================================================
# Helper — build a package extraction table
# ===========================================================================
def _package_table(items: list[dict], styles: dict) -> Table:
    header = ["Path", "Ext", "Size (B)", "SHA-256 (abbrev.)", "Flag"]
    header_paras = [Paragraph(h, styles["BodyBold"]) for h in header]
    rows = [header_paras]

    for item in items:
        flagged = item.get("Is_Flagged", False)
        row_style = styles["Alert"] if flagged else styles["BodySmall"]
        sha = _safe(str(item.get("SHA256", "N/A")))
        rows.append([
            Paragraph(_safe(item.get("Relative_Path", "?")), row_style),
            Paragraph(_safe(item.get("Extension", "")),      row_style),
            Paragraph(str(item.get("Size_Bytes", 0)),        row_style),
            Paragraph(sha[:20] + "…" if len(sha) > 20 else sha, row_style),
            Paragraph("FLAGGED" if flagged else "—",         row_style),
        ])

    col_w = [
        CONTENT_W * 0.35,
        CONTENT_W * 0.07,
        CONTENT_W * 0.10,
        CONTENT_W * 0.33,
        CONTENT_W * 0.15,
    ]
    tbl = Table(rows, colWidths=col_w, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), C_LIGHTBLUE),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
        ("GRID",        (0, 0), (-1, -1), 0.25, colors.HexColor("#c0ccee")),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",(0, 0), (-1, -1), 5),
        ("TOPPADDING",  (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0,0), (-1, -1), 3),
    ]))
    return tbl


# ===========================================================================
# Helper — dynamic telemetry summary table
# ===========================================================================
def _telemetry_summary_table(telemetry: dict, summary: dict, styles: dict) -> Table:
    header = ["Category", "Events", "Notable / High-Risk"]
    rows   = [[Paragraph(h, styles["BodyBold"]) for h in header]]

    for cat in TELEMETRY_KEYS:
        label    = CATEGORY_LABELS.get(cat, cat)
        cat_sum  = summary.get(cat, {})
        count    = cat_sum.get("count", len(telemetry.get(cat, [])))
        notable  = cat_sum.get("notable", [])
        notable_str = f"{len(notable)} flagged" if notable else "\u2014"

        count_style = styles["Alert"] if count > 0 else styles["Body"]
        rows.append([
            Paragraph(label,       styles["Body"]),
            Paragraph(str(count),  count_style),
            Paragraph(notable_str, styles["Warning"] if notable else styles["Body"]),
        ])

    col_w = [CONTENT_W * 0.60, CONTENT_W * 0.15, CONTENT_W * 0.25]
    tbl   = Table(rows, colWidths=col_w, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), C_LIGHTBLUE),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
        ("GRID",           (0, 0), (-1, -1), 0.25, colors.HexColor("#c0ccee")),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("LEFTPADDING",    (0, 0), (-1, -1), 6),
        ("TOPPADDING",     (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
    ]))
    return tbl


# ===========================================================================
# Main report generator class
# ===========================================================================
class ReportGenerator:
    def __init__(self, config: dict):
        self.reports_dir = config.get("system", {}).get("reports_dir", "./workspace/reports")
        os.makedirs(self.reports_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Public entry-point
    # ------------------------------------------------------------------
    def generate_reports(
        self,
        metadata:        dict,
        package_data:    list,
        static_data:     dict,
        dynamic_data:    dict | None = None,
        dynamic_summary: dict | None = None,
    ):
        pub.sendMessage("gui.log", msg="\n[*] --- Starting Reporting Module ---")

        analysis_id = metadata.get(
            "Analysis ID",
            f"MARS_UNKNOWN_{datetime.datetime.now().strftime('%H%M%S')}",
        )
        base_filename = os.path.join(self.reports_dir, f"{analysis_id}_Report")

        compiled = {
            "Analysis_Summary":         metadata,
            "Package_Extraction":       package_data,
            "Static_Analysis_Results":  static_data,
            "Dynamic_Analysis_Results": dynamic_data  or {},
            "Dynamic_Summary":          dynamic_summary or {},
        }

        # JSON (always saved first as a raw artefact)
        json_path = f"{base_filename}.json"
        with open(json_path, "w") as fh:
            json.dump(compiled, fh, indent=4)
        pub.sendMessage("gui.log", msg=f"  [+] JSON Report Saved: {json_path}")

        # PDF
        pdf_path = f"{base_filename}.pdf"
        try:
            self._build_pdf(compiled, pdf_path)
            pub.sendMessage("gui.log", msg=f"  [+] PDF Report Saved: {pdf_path}")
        except Exception as exc:
            pub.sendMessage("gui.log", msg=f"  [!] PDF generation failed: {exc}")
            raise

    # ------------------------------------------------------------------
    # PDF builder — orchestrates story construction and two-pass build
    # ------------------------------------------------------------------
    def _build_pdf(self, data: dict, output_path: str):
        styles = _build_styles()

        # ---- document template ----------------------------------------
        doc = _MARSDoc(
            output_path,
            pagesize=A4,
            leftMargin=MARGIN,  rightMargin=MARGIN,
            topMargin=1.5 * cm, bottomMargin=1.3 * cm,
        )

        title_frame   = Frame(0, 0, PAGE_W, PAGE_H, id="title_frame")
        content_frame = Frame(
            MARGIN, 1.1 * cm,
            CONTENT_W, PAGE_H - 2.6 * cm,
            id="content_frame",
        )

        doc.addPageTemplates([
            PageTemplate(id="Title",   frames=[title_frame],
                         onPage=_draw_title_page),
            PageTemplate(id="Content", frames=[content_frame],
                         onPage=_draw_content_page),
        ])

        # ---- table of contents ----------------------------------------
        toc = TableOfContents()
        toc.levelStyles = [styles["TocEntry"], styles["TocEntry2"]]
        doc.attach_toc(toc)

        # ---- assemble story -------------------------------------------
        story: list = []
        story += self._title_page(data, styles)
        story += self._toc_page(toc, styles)
        story += self._section_intake(data.get("Analysis_Summary", {}), styles)
        story += self._section_packages(data.get("Package_Extraction") or [], styles)
        story += self._section_static(data.get("Static_Analysis_Results", {}), styles)
        story += self._section_dynamic(
            data.get("Dynamic_Analysis_Results", {}),
            data.get("Dynamic_Summary",          {}),
            styles,
        )

        # ---- two-pass build (required for accurate TOC page numbers) ---
        doc.multiBuild(story)

    # ==================================================================
    # Title page
    # ==================================================================
    def _title_page(self, data: dict, styles: dict) -> list:
        meta       = data.get("Analysis_Summary", {})
        analysis_id = meta.get("Analysis ID", "N/A")
        filename    = meta.get("Filename",    "N/A")
        ts          = meta.get("Submission Timestamp",
                               datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        elems: list = [NextPageTemplate("Title")]

        # vertical spacer to push content into the middle blue band
        elems.append(Spacer(1, PAGE_H * 0.42))

        elems.append(Paragraph("MARS", styles["Title"]))
        elems.append(Paragraph(
            "Malware Analysis &amp; Reverse-engineering System",
            styles["Subtitle"],
        ))
        elems.append(Spacer(1, 0.4 * cm))
        elems.append(HRFlowable(
            width="60%", thickness=1,
            color=colors.HexColor("#5070c0"),
            hAlign="CENTER",
        ))
        elems.append(Spacer(1, 0.4 * cm))
        elems.append(Paragraph(f"Analysis ID: {_safe(analysis_id)}", styles["TitleMeta"]))
        elems.append(Paragraph(f"Target: {_safe(filename)}",          styles["TitleMeta"]))
        elems.append(Paragraph(f"Generated: {_safe(str(ts))}",        styles["TitleMeta"]))

        elems.append(PageBreak())
        return elems

    # ==================================================================
    # Table of contents page
    # ==================================================================
    def _toc_page(self, toc: TableOfContents, styles: dict) -> list:
        elems: list = [NextPageTemplate("Content")]
        elems.append(Paragraph("Table of Contents", styles["H1"]))
        elems.append(Spacer(1, 0.3 * cm))
        elems.append(toc)
        elems.append(PageBreak())
        return elems

    # ==================================================================
    # Section 1 — File Intake Summary
    # ==================================================================
    def _section_intake(self, metadata: dict, styles: dict) -> list:
        elems: list = []
        elems.append(Paragraph("1. File Intake Summary", styles["H1"]))
        elems.append(Spacer(1, 0.2 * cm))
        elems.append(Paragraph(
            "Raw metadata captured by the intake module when the sample was submitted. "
            "Hash values are computed immediately on ingestion before any analysis modifies memory.",
            styles["Body"],
        ))
        elems.append(Spacer(1, 0.3 * cm))

        rows = [(k, v) for k, v in metadata.items()]
        if rows:
            elems.append(_param_table(rows, styles))
        else:
            elems.append(Paragraph("No intake metadata available.", styles["Body"]))

        elems.append(Spacer(1, 0.5 * cm))
        return elems

    # ==================================================================
    # Section 2 — Package & Archive Unpacking
    # ==================================================================
    def _section_packages(self, package_data: list, styles: dict) -> list:
        elems: list = []
        elems.append(Paragraph("2. Package &amp; Archive Unpacking", styles["H1"]))
        elems.append(Spacer(1, 0.2 * cm))

        if not package_data:
            elems.append(Paragraph(
                "Not applicable — the submitted file is not an archive or MSI package.",
                styles["Body"],
            ))
            elems.append(Spacer(1, 0.5 * cm))
            return elems

        flagged = [f for f in package_data if f.get("Is_Flagged")]
        summary_rows = [
            ("Total Extracted Files", len(package_data)),
            ("Flagged Payloads",      len(flagged)),
        ]
        elems.append(_param_table(summary_rows, styles))
        elems.append(Spacer(1, 0.3 * cm))

        elems.append(Paragraph("Extracted Artefacts", styles["H2"]))
        elems.append(Spacer(1, 0.2 * cm))
        elems.append(Paragraph(
            "Files unpacked from the archive. FLAGGED entries have extensions that match "
            "executable payload types and are forwarded to the static analysis phase.",
            styles["Body"],
        ))
        elems.append(Spacer(1, 0.2 * cm))
        elems.append(_package_table(package_data, styles))
        elems.append(Spacer(1, 0.5 * cm))
        return elems

    # ==================================================================
    # Section 3 — Deep Static Analysis
    # ==================================================================
    def _section_static(self, static_data: dict, styles: dict) -> list:
        elems: list = []
        elems.append(Paragraph("3. Deep Static Analysis", styles["H1"]))
        elems.append(Spacer(1, 0.2 * cm))
        elems.append(Paragraph(
            "PE file structure analysis performed without executing the sample. "
            "Results include header metadata, security mitigations, section entropy, "
            "IAT inspection, manifest parsing, string extraction, and YARA signature matching.",
            styles["Body"],
        ))
        elems.append(Spacer(1, 0.3 * cm))

        if not static_data:
            elems.append(Paragraph(
                "No static analysis results — target is not a recognised PE file.",
                styles["Body"],
            ))
            elems.append(Spacer(1, 0.5 * cm))
            return elems

        for target_name, results in static_data.items():
            elems.append(Paragraph(f"Target: {_safe(target_name)}", styles["H2"]))
            elems.append(Spacer(1, 0.2 * cm))

            for category, category_data in results.items():
                elems.append(Paragraph(_safe(category), styles["H3"]))

                if isinstance(category_data, dict):
                    rows = [(k, v) for k, v in category_data.items()]
                    elems.append(_param_table(rows, styles))
                elif isinstance(category_data, list):
                    for item in category_data:
                        elems.append(Paragraph(f"\u2022 {_safe(str(item))}", styles["Body"]))
                else:
                    elems.append(Paragraph(_safe(str(category_data)), styles["Body"]))

                elems.append(Spacer(1, 0.25 * cm))

            elems.append(Spacer(1, 0.3 * cm))

        return elems

    # ==================================================================
    # Section 4 — Dynamic Sandbox Analysis
    # ==================================================================
    def _section_dynamic(
        self,
        dynamic_data:    dict,
        dynamic_summary: dict,
        styles:          dict,
    ) -> list:
        elems: list = []
        elems.append(Paragraph("4. Dynamic Sandbox Analysis", styles["H1"]))
        elems.append(Spacer(1, 0.2 * cm))
        elems.append(Paragraph(
            "Behavioural telemetry captured during live detonation inside the VMware sandbox. "
            "The agent instruments filesystem, registry, network, process, memory, and hardware "
            "subsystems in real time. Events are classified and counted per category.",
            styles["Body"],
        ))
        elems.append(Spacer(1, 0.3 * cm))

        if not dynamic_data:
            elems.append(Paragraph(
                "No dynamic analysis results — either the dynamic module was skipped or "
                "the VMware sandbox is not configured.",
                styles["Body"],
            ))
            elems.append(Spacer(1, 0.5 * cm))
            return elems

        for target_name, telemetry in dynamic_data.items():
            elems.append(Paragraph(f"Target: {_safe(target_name)}", styles["H2"]))
            elems.append(Spacer(1, 0.2 * cm))

            # ---- error case -------------------------------------------
            if "Error" in telemetry:
                elems.append(Paragraph(
                    f"Detonation error: {_safe(telemetry['Error'])}",
                    styles["Alert"],
                ))
                elems.append(Spacer(1, 0.3 * cm))
                continue

            # ---- 4a. Telemetry summary table --------------------------
            elems.append(Paragraph("Telemetry Summary", styles["H3"]))
            elems.append(Spacer(1, 0.15 * cm))
            summary_for_target = dynamic_summary.get(target_name, {})
            elems.append(_telemetry_summary_table(telemetry, summary_for_target, styles))
            elems.append(Spacer(1, 0.4 * cm))

            # ---- 4b. Per-category event detail ------------------------
            elems.append(Paragraph("Event Detail", styles["H3"]))
            elems.append(Spacer(1, 0.15 * cm))

            for cat in TELEMETRY_KEYS:
                events = telemetry.get(cat, [])
                if not events:
                    continue

                label = CATEGORY_LABELS.get(cat, cat)
                desc  = _desc(cat)

                # Category sub-header + optional description
                cat_block: list = [
                    Paragraph(f"{label}  ({len(events)} events)", styles["H3"]),
                ]
                if desc:
                    cat_block.append(Paragraph(desc, styles["Desc"]))
                cat_block.append(Spacer(1, 0.1 * cm))

                for ev in events:
                    clean = _safe(str(ev))
                    upper = clean.upper()
                    if any(kw in upper for kw in (
                        "INJECT", "RANSOM", "PROCESS_SPAWN", "REG_RUN_KEY", "FILE_DROP"
                    )):
                        ev_style = styles["Alert"]
                    elif any(kw in upper for kw in ("NETWORK", "DNS", "HTTP", "TLS")):
                        ev_style = styles["Warning"]
                    else:
                        ev_style = styles["BodySmall"]
                    cat_block.append(Paragraph(f"\u2022 {clean}", ev_style))

                cat_block.append(Spacer(1, 0.25 * cm))
                elems.append(KeepTogether(cat_block))

            elems.append(Spacer(1, 0.5 * cm))

        return elems
