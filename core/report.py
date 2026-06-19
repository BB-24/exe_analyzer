"""
MARS — Report Generator  (ReportLab · redesigned layout)
=========================================================
Pages
  1   Title page  — full canvas painting, no flowables
  2   Table of Contents — auto-built via two-pass multiBuild;
                          dot leaders + right-aligned page numbers
  3+  Section 1 — File Intake Summary
      Section 2 — Package & Archive Unpacking
      Section 3 — Deep Static Analysis
      Section 4 — Dynamic Sandbox Analysis

PARAMETER DESCRIPTIONS
-----------------------
Fill in any "TODO:" string below with a plain-English sentence.
Non-TODO entries render as italic grey helper text beneath each
value in the report.  Unfilled (TODO) entries are silently skipped.
"""

import os
import json
import datetime
from pubsub import pub

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame,
    Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether, NextPageTemplate,
)
from reportlab.platypus.tableofcontents import TableOfContents

from core.dynamic import TELEMETRY_KEYS

# ═══════════════════════════════════════════════════════════════════════════
# PARAMETER DESCRIPTIONS
# ═══════════════════════════════════════════════════════════════════════════
PARAM_DESCRIPTIONS: dict[str, str] = {

    # Section 1 — File Intake
    "Analysis ID":
        "Unique identifier auto-generated for this analysis session.",
    "Filename":
        "Original filename of the submitted sample as read from disk.",
    "File Path":
        "Absolute filesystem path from which the sample was ingested.",
    "Extension":
        "File extension used to determine the analysis pipeline branch.",
    "File Size":
        "Total size of the submitted file in bytes.",
    "MD5":
        "MD5 digest of the file — used for fast de-duplication checks.",
    "SHA1":
        "SHA-1 digest of the file.",
    "SHA256":
        "SHA-256 cryptographic hash — primary unique identifier for the sample.",
    "Magic Bytes":
        "First four bytes of the file used to verify the true file type independent of extension.",
    "Submission Timestamp":
        "UTC date and time at which the file was submitted to the pipeline.",

    # Section 3 — PE Headers
    "Machine Architecture":
        "Target CPU architecture encoded in the COFF File Header (e.g. 0x14c = x86, 0x8664 = x64).",
    "Compile Timestamp":
        "Date/time the binary was linked. Stored in the PE File Header — trivially forgeable.",
    "DOS Header Offset (e_lfanew)":
        "Byte offset of the PE signature from file start. Abnormal values may indicate header manipulation.",
    "Address of Entry Point":
        "Relative virtual address (RVA) of the first instruction executed. Unusual RVAs suggest packing.",
    "Image Base":
        "Preferred virtual address where the image is loaded. 0x400000 is the traditional default.",
    "Number of Sections":
        "Count of PE sections. Values outside 3-10 are often associated with packers or malformed binaries.",

    # Section 3 — Mitigations
    "DEP / NX Bit":
        "Data Execution Prevention — marks data pages non-executable to block shellcode.",
    "ASLR":
        "Address Space Layout Randomisation — randomises load addresses to hinder ROP chains.",
    "CFG (Control Flow Guard)":
        "Microsoft's compile-time + runtime control-flow integrity check on indirect calls.",
    "RFG (Return Flow Guard)":
        "Return-flow integrity check; guards return addresses against ROP corruption.",
    "SafeSEH":
        "Structured Exception Handler protection — validates handlers against a compile-time list.",
    "Stack Canaries (/GS)":
        "Compiler-inserted stack cookie; detects stack-buffer overflows before return.",
    "Hardware Protection (CET/Shadow Stack)":
        "Intel CET Shadow Stack — hardware-enforced return-address integrity (processor support required).",
    "Force Integrity":
        "Requires a valid Authenticode code-signing signature before the loader will map the image.",
    "Isolation / AppContainer":
        "Binary is declared to run inside an AppContainer with restricted privilege and syscall surface.",

    # Section 3 — Imports
    "Tracked APIs Found":
        "Number of monitored Win32 API imports found in the Import Address Table (IAT).",
    "APIs":
        "Comma-separated list of suspicious API names. Cross-reference with MITRE ATT&CK technique IDs.",

    # Section 3 — Manifest Data
    "Manifest Status":
        "Whether a valid XML application manifest was found and parsed inside the PE resources.",
    "Requested Execution Level":
        "Privilege level declared in the manifest: asInvoker | highestAvailable | requireAdministrator.",

    # Section 3 — YARA
    "Hits":
        "Total number of YARA rule signatures that matched against the sample.",
    "Matched Rules":
        "YARA rule names that fired. Each name encodes a threat family or behavioural pattern.",

    # Section 2 — Package Extraction
    "Total Extracted Files":
        "Number of files unpacked from the archive or MSI installer payload.",
    "Flagged Payloads":
        "Count of extracted files whose extension matches a high-risk executable type (.exe, .dll, .sys).",

    # Section 4 — Dynamic Telemetry
    "Filesystem":
        "File creation, deletion, and modification events observed during live sandbox detonation.",
    "Registry":
        "Windows Registry key reads, writes, and deletions captured during execution.",
    "Persistence":
        "Mechanisms used to survive reboots: Run keys, scheduled tasks, service registration.",
    "Processes":
        "Child processes spawned and process-injection events observed by the in-guest agent.",
    "Memory":
        "Memory forensics: injected regions, hollowed processes, anomalous virtual allocations.",
    "Network":
        "DNS queries, HTTP/S requests, and raw TCP/UDP connections intercepted by the sandbox NIC.",
    "Hardware":
        "CPU, disk, and peripheral stress events — may indicate crypto-mining or wiper activity.",
    "System":
        "OS-level events including privilege escalation, UAC bypass attempts, and driver loads.",
}

# ═══════════════════════════════════════════════════════════════════════════
# Telemetry labels
# ═══════════════════════════════════════════════════════════════════════════
CATEGORY_LABELS: dict[str, str] = {
    "Filesystem":  "Filesystem Activity    (FR-DYN-01)",
    "Registry":    "Registry Mutations     (FR-DYN-02)",
    "Persistence": "Persistence Mechanisms (FR-DYN-03)",
    "Processes":   "Process Activity       (FR-DYN-04)",
    "Memory":      "Memory Forensics       (FR-DYN-05)",
    "Network":     "Network Telemetry      (FR-DYN-06)",
    "Hardware":    "Hardware / System Stress(FR-DYN-07)",
    "System":      "System & Agent Events",
}

# ═══════════════════════════════════════════════════════════════════════════
# COLOUR PALETTE  (light / high-contrast theme)
# ═══════════════════════════════════════════════════════════════════════════

# -- Structural --
C_PAGE_BG   = colors.HexColor("#F7F9FC")   # page canvas fill
C_WHITE     = colors.white

# -- Brand / Primary --
C_NAVY      = colors.HexColor("#1A2744")   # darkest brand navy
C_SLATE     = colors.HexColor("#263056")   # mid brand slate
C_BLUE      = colors.HexColor("#3B5BDB")   # electric accent blue
C_BLUE_SOFT = colors.HexColor("#4C6EF5")   # softer accent

# -- Text --
C_TEXT      = colors.HexColor("#111827")   # near-black body text
C_MUTED     = colors.HexColor("#6B7280")   # secondary / hint text
C_HINT      = colors.HexColor("#9CA3AF")   # subtle / disabled

# -- Table --
C_TH_BG     = colors.HexColor("#1A2744")   # table header background
C_TH_FG     = colors.white                 # table header foreground
C_ROW_A     = colors.white
C_ROW_B     = colors.HexColor("#F0F4FF")   # alternating row tint
C_ROW_BORDER = colors.HexColor("#DDE3F0")  # grid lines

# -- Status --
C_RED       = colors.HexColor("#BE1414")   # critical / alert
C_AMBER     = colors.HexColor("#B45309")   # warning
C_GREEN     = colors.HexColor("#047857")   # clean / ok
C_RED_BG    = colors.HexColor("#FEF2F2")   # alert row tint
C_AMBER_BG  = colors.HexColor("#FFFBEB")   # warning row tint
C_GREEN_BG  = colors.HexColor("#ECFDF5")   # clean row tint

# -- Title page --
C_TP_BG     = colors.HexColor("#111827")   # page background
C_TP_BAND   = colors.HexColor("#1A2744")   # centre band
C_TP_ACCENT = colors.HexColor("#3B5BDB")   # accent line / chip
C_TP_TITLE  = colors.white
C_TP_SUB    = colors.HexColor("#93C5FD")   # subtitle blue
C_TP_META_L = colors.HexColor("#6B7280")   # meta label
C_TP_META_V = colors.HexColor("#E5E7EB")   # meta value

PAGE_W, PAGE_H = A4
MARGIN         = 2.0 * cm
CONTENT_W      = PAGE_W - 2 * MARGIN

# ═══════════════════════════════════════════════════════════════════════════
# STYLE SHEET
# ═══════════════════════════════════════════════════════════════════════════
def _styles() -> dict:
    def ps(name: str, **kw) -> ParagraphStyle:
        return ParagraphStyle(name, **kw)

    return {
        # ── Section headings (TOC-registered) ──────────────────────────
        "H1": ps("H1",
                 fontName="Helvetica-Bold", fontSize=12,
                 textColor=C_WHITE, backColor=C_NAVY,
                 leading=20, spaceAfter=8, spaceBefore=18,
                 leftIndent=0, rightIndent=0,
                 borderPadding=(6, 8, 6, 8)),

        "H2": ps("H2",
                 fontName="Helvetica-Bold", fontSize=10,
                 textColor=C_SLATE,
                 borderWidth=0, borderColor=C_BLUE,
                 leading=16, spaceAfter=4, spaceBefore=12,
                 leftIndent=8,
                 borderPadding=(0, 0, 0, 0)),

        "H3": ps("H3",
                 fontName="Helvetica-Bold", fontSize=9,
                 textColor=C_SLATE,
                 leading=14, spaceAfter=3, spaceBefore=8,
                 leftIndent=12),

        # ── Body text ──────────────────────────────────────────────────
        "Body": ps("Body",
                   fontName="Helvetica", fontSize=9,
                   textColor=C_TEXT, leading=14, spaceAfter=2),

        "BodyBold": ps("BodyBold",
                       fontName="Helvetica-Bold", fontSize=9,
                       textColor=C_TEXT, leading=14),

        "BodySmall": ps("BodySmall",
                        fontName="Helvetica", fontSize=8,
                        textColor=C_TEXT, leading=12),

        "BodyMono": ps("BodyMono",
                       fontName="Courier", fontSize=8,
                       textColor=C_TEXT, leading=12),

        "Desc": ps("Desc",
                   fontName="Helvetica-Oblique", fontSize=7.5,
                   textColor=C_MUTED, leading=11,
                   spaceAfter=3, leftIndent=2),

        "IntroText": ps("IntroText",
                        fontName="Helvetica", fontSize=9,
                        textColor=C_MUTED, leading=14,
                        spaceAfter=8, spaceBefore=2),

        # ── Status ─────────────────────────────────────────────────────
        "Alert": ps("Alert",
                    fontName="Helvetica-Bold", fontSize=9,
                    textColor=C_RED, leading=14),

        "Warning": ps("Warning",
                      fontName="Helvetica-Bold", fontSize=9,
                      textColor=C_AMBER, leading=14),

        "Clean": ps("Clean",
                    fontName="Helvetica", fontSize=9,
                    textColor=C_GREEN, leading=14),

        # ── TOC entries ─────────────────────────────────────────────────
        "TOC1": ps("TOC1",
                   fontName="Helvetica-Bold", fontSize=11,
                   textColor=C_NAVY, leading=22,
                   leftIndent=0, rightIndent=0,
                   spaceAfter=2, spaceBefore=4),

        "TOC2": ps("TOC2",
                   fontName="Helvetica", fontSize=9.5,
                   textColor=C_MUTED, leading=18,
                   leftIndent=18, rightIndent=0,
                   spaceAfter=0),

        # ── Table header cell ───────────────────────────────────────────
        "TH": ps("TH",
                 fontName="Helvetica-Bold", fontSize=8.5,
                 textColor=C_TH_FG, leading=12),

        "THCenter": ps("THCenter",
                       fontName="Helvetica-Bold", fontSize=8.5,
                       textColor=C_TH_FG, leading=12,
                       alignment=TA_CENTER),
    }


# ═══════════════════════════════════════════════════════════════════════════
# DOC TEMPLATE  (notifies TOC via afterFlowable)
# ═══════════════════════════════════════════════════════════════════════════
class _MARSDoc(BaseDocTemplate):
    def afterFlowable(self, flowable):
        if not isinstance(flowable, Paragraph):
            return
        sn = flowable.style.name
        if sn == "H1":
            self.notify("TOCEntry", (0, flowable.getPlainText(), self.page))
        elif sn == "H2":
            self.notify("TOCEntry", (1, flowable.getPlainText(), self.page))


# ═══════════════════════════════════════════════════════════════════════════
# CANVAS CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════
def _page_title(canvas, doc):
    """
    Title page — drawn entirely with canvas primitives so every element is
    precisely positioned.  No flowables are used on this page.
    """
    c = canvas
    c.saveState()
    ts = datetime.datetime.now().strftime("%Y-%m-%d")

    # ── Background ──────────────────────────────────────────────────────
    c.setFillColor(C_TP_BG)
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

    # ── Centre panel ────────────────────────────────────────────────────
    panel_y = PAGE_H * 0.30
    panel_h = PAGE_H * 0.42
    c.setFillColor(C_TP_BAND)
    c.rect(0, panel_y, PAGE_W, panel_h, fill=1, stroke=0)

    # ── Left accent stripe ───────────────────────────────────────────────
    stripe_w = 6
    c.setFillColor(C_TP_ACCENT)
    c.rect(MARGIN, panel_y, stripe_w, panel_h, fill=1, stroke=0)

    # ── Wordmark  "MARS" ─────────────────────────────────────────────────
    c.setFont("Helvetica-Bold", 72)
    c.setFillColor(C_TP_TITLE)
    c.drawCentredString(PAGE_W / 2, panel_y + panel_h - 1.2 * cm - 72 * 0.352778 * mm, "MARS")

    # ── Full name ────────────────────────────────────────────────────────
    c.setFont("Helvetica", 15)
    c.setFillColor(C_TP_SUB)
    c.drawCentredString(
        PAGE_W / 2,
        panel_y + panel_h - 1.2 * cm - 72 * 0.352778 * mm - 1.0 * cm,
        "Malware Analysis & Reverse-engineering System",
    )

    # ── Accent rule ──────────────────────────────────────────────────────
    rule_y = panel_y + panel_h * 0.38
    c.setStrokeColor(C_TP_ACCENT)
    c.setLineWidth(1.5)
    c.line(MARGIN + stripe_w + 10, rule_y, PAGE_W - MARGIN, rule_y)

    # ── Metadata rows ────────────────────────────────────────────────────
    meta = getattr(doc, "_mars_meta", {})
    rows = [
        ("ANALYSIS ID",  meta.get("Analysis ID",  "N/A")),
        ("TARGET FILE",  meta.get("Filename",      "N/A")),
        ("GENERATED",    ts),
    ]
    label_x  = MARGIN + stripe_w + 14
    value_x  = label_x + 3.8 * cm
    row_y    = rule_y - 0.55 * cm
    row_step = 0.70 * cm

    for label, value in rows:
        c.setFont("Helvetica-Bold", 7.5)
        c.setFillColor(C_TP_META_L)
        c.drawString(label_x, row_y, label)

        c.setFont("Helvetica", 9)
        c.setFillColor(C_TP_META_V)
        # Truncate long values so they don't overflow the panel
        v = str(value)
        if len(v) > 55:
            v = v[:52] + "..."
        c.drawString(value_x, row_y, v)
        row_y -= row_step

    # ── Classification chip ──────────────────────────────────────────────
    chip_w, chip_h = 5.2 * cm, 0.55 * cm
    chip_x = (PAGE_W - chip_w) / 2
    chip_y = panel_y - 1.6 * cm
    c.setFillColor(C_TP_ACCENT)
    c.roundRect(chip_x, chip_y, chip_w, chip_h, 3, fill=1, stroke=0)
    c.setFont("Helvetica-Bold", 8)
    c.setFillColor(colors.white)
    c.drawCentredString(PAGE_W / 2, chip_y + 0.145 * cm, "CONFIDENTIAL — INTERNAL USE ONLY")

    # ── Bottom brand strip ───────────────────────────────────────────────
    c.setFillColor(C_TP_ACCENT)
    c.rect(0, 0, PAGE_W, 0.45 * cm, fill=1, stroke=0)

    c.restoreState()


def _page_content(canvas, doc):
    """
    Header + footer chrome for all content pages (TOC onward).
    White page background with a navy top bar and a slim bottom rule.
    """
    c = canvas
    c.saveState()
    ts = datetime.datetime.now().strftime("%Y-%m-%d")

    # White page background
    c.setFillColor(C_WHITE)
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

    # ── Header bar ───────────────────────────────────────────────────────
    bar_h = 1.0 * cm
    c.setFillColor(C_NAVY)
    c.rect(0, PAGE_H - bar_h, PAGE_W, bar_h, fill=1, stroke=0)

    # Blue left accent stripe in header
    c.setFillColor(C_BLUE)
    c.rect(0, PAGE_H - bar_h, 5, bar_h, fill=1, stroke=0)

    c.setFont("Helvetica-Bold", 8.5)
    c.setFillColor(colors.white)
    c.drawString(MARGIN, PAGE_H - bar_h + 0.28 * cm,
                 "MARS  \u2014  Malware Analysis & Reverse-engineering System")

    c.setFont("Helvetica", 7.5)
    c.setFillColor(C_TP_META_L)
    c.drawRightString(PAGE_W - MARGIN, PAGE_H - bar_h + 0.28 * cm, ts)

    # ── Footer rule + page number ────────────────────────────────────────
    footer_y = 0.65 * cm
    c.setStrokeColor(C_ROW_BORDER)
    c.setLineWidth(0.5)
    c.line(MARGIN, footer_y, PAGE_W - MARGIN, footer_y)

    c.setFont("Helvetica", 7.5)
    c.setFillColor(C_MUTED)
    c.drawCentredString(PAGE_W / 2, 0.25 * cm, f"Page {doc.page}")
    c.drawString(MARGIN, 0.25 * cm, "CONFIDENTIAL")
    c.drawRightString(PAGE_W - MARGIN, 0.25 * cm, "MARS Report")

    c.restoreState()


# ═══════════════════════════════════════════════════════════════════════════
# UTILITY
# ═══════════════════════════════════════════════════════════════════════════
def _safe(v) -> str:
    return str(v).encode("latin-1", "replace").decode("latin-1")


def _desc(key: str) -> str | None:
    raw = PARAM_DESCRIPTIONS.get(key, "")
    if not raw or raw.startswith("TODO"):
        return None
    return raw


def _flag_style(text: str, styles: dict) -> ParagraphStyle:
    t = text.upper()
    if any(k in t for k in ("[CRITICAL]", "[PACKED", "[SUSPICIOUS", "FLAGGED")):
        return styles["Alert"]
    if "[WARNING]" in t:
        return styles["Warning"]
    return styles["BodyMono"]


# ═══════════════════════════════════════════════════════════════════════════
# TABLE BUILDERS
# ═══════════════════════════════════════════════════════════════════════════
def _param_table(rows: list[tuple], styles: dict) -> Table:
    """Two-column key/value parameter table with optional description row."""
    data = []
    ts_cmds = [
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LINEBEFORE",   (1, 0), (1, -1), 1, C_BLUE),
        ("BOX",          (0, 0), (-1, -1), 0.5, C_ROW_BORDER),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C_ROW_A, C_ROW_B]),
    ]

    for i, (k, v) in enumerate(rows):
        val_text  = _safe(v)
        val_style = _flag_style(val_text, styles)
        val_para  = Paragraph(val_text, val_style)
        d         = _desc(str(k))
        val_cell  = [val_para, Paragraph(d, styles["Desc"])] if d else [val_para]
        data.append([
            Paragraph(_safe(k), styles["BodyBold"]),
            val_cell,
        ])
        # Tint alert rows
        if val_style is styles["Alert"]:
            ts_cmds += [("BACKGROUND", (0, i), (-1, i), C_RED_BG)]
        elif val_style is styles["Warning"]:
            ts_cmds += [("BACKGROUND", (0, i), (-1, i), C_AMBER_BG)]

    if len(data) > 1:
        ts_cmds.append(("LINEBELOW", (0, 0), (-1, -2), 0.25, C_ROW_BORDER))

    tbl = Table(data, colWidths=[CONTENT_W * 0.30, CONTENT_W * 0.70])
    tbl.setStyle(TableStyle(ts_cmds))
    return tbl


def _data_table(
    headers: list[str],
    rows: list[list],
    col_fracs: list[float],
    styles: dict,
    *,
    flag_col: int | None = None,
) -> Table:
    """
    Generic tabular data (packages, telemetry summary, etc.).
    headers      — column label strings
    rows         — list of row data (strings or Paragraphs)
    col_fracs    — fractional widths that must sum to 1.0
    flag_col     — column index checked for alert keywords (row tinting)
    """
    col_w = [CONTENT_W * f for f in col_fracs]
    th_row = [Paragraph(_safe(h), styles["TH"]) for h in headers]
    table_rows = [th_row]
    ts_cmds = [
        # Header
        ("BACKGROUND",   (0, 0), (-1, 0), C_TH_BG),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("GRID",         (0, 0), (-1, -1), 0.3, C_ROW_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_ROW_A, C_ROW_B]),
        ("FONTSIZE",     (0, 0), (-1, -1), 8.5),
    ]

    for i, row in enumerate(rows):
        built = []
        for cell in row:
            if isinstance(cell, str):
                val_text = _safe(cell)
                built.append(Paragraph(val_text, _flag_style(val_text, styles)))
            else:
                built.append(cell)
        table_rows.append(built)

        # Row-level tinting based on flag column
        if flag_col is not None:
            raw = row[flag_col] if isinstance(row[flag_col], str) else ""
            raw_up = raw.upper()
            ri = i + 1
            if any(k in raw_up for k in ("FLAGGED", "[CRITICAL]", "INJECT", "RANSOM")):
                ts_cmds.append(("BACKGROUND", (0, ri), (-1, ri), C_RED_BG))
            elif any(k in raw_up for k in ("[WARNING]", "DNS", "HTTP", "NETWORK")):
                ts_cmds.append(("BACKGROUND", (0, ri), (-1, ri), C_AMBER_BG))

    tbl = Table(table_rows, colWidths=col_w, repeatRows=1)
    tbl.setStyle(TableStyle(ts_cmds))
    return tbl


# ═══════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════
class ReportGenerator:
    def __init__(self, config: dict):
        self.reports_dir = config.get("system", {}).get("reports_dir", "./workspace/reports")
        os.makedirs(self.reports_dir, exist_ok=True)

    # ── Public entry-point ─────────────────────────────────────────────
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
        base = os.path.join(self.reports_dir, f"{analysis_id}_Report")

        compiled = {
            "Analysis_Summary":         metadata,
            "Package_Extraction":       package_data,
            "Static_Analysis_Results":  static_data,
            "Dynamic_Analysis_Results": dynamic_data  or {},
            "Dynamic_Summary":          dynamic_summary or {},
        }

        # JSON
        json_path = f"{base}.json"
        with open(json_path, "w") as fh:
            json.dump(compiled, fh, indent=4)
        pub.sendMessage("gui.log", msg=f"  [+] JSON Report Saved: {json_path}")

        # PDF
        pdf_path = f"{base}.pdf"
        try:
            self._build_pdf(compiled, pdf_path)
            pub.sendMessage("gui.log", msg=f"  [+] PDF Report Saved: {pdf_path}")
        except Exception as exc:
            pub.sendMessage("gui.log", msg=f"  [!] PDF generation failed: {exc}")
            raise

    # ── PDF orchestrator ───────────────────────────────────────────────
    def _build_pdf(self, data: dict, path: str):
        st = _styles()
        meta = data.get("Analysis_Summary", {})

        # ── Document ────────────────────────────────────────────────────
        doc = _MARSDoc(
            path,
            pagesize=A4,
            leftMargin=MARGIN, rightMargin=MARGIN,
            topMargin=1.2 * cm, bottomMargin=1.1 * cm,
        )
        doc._mars_meta = meta  # passed through to title-page canvas callback

        # ── Page templates ──────────────────────────────────────────────
        title_frame = Frame(
            0, 0, PAGE_W, PAGE_H,
            leftPadding=0, rightPadding=0,
            topPadding=0, bottomPadding=0,
            id="title",
        )
        content_frame = Frame(
            MARGIN, 0.9 * cm,
            CONTENT_W, PAGE_H - 2.1 * cm,
            id="content",
        )
        doc.addPageTemplates([
            PageTemplate(id="Title",   frames=[title_frame],   onPage=_page_title),
            PageTemplate(id="Content", frames=[content_frame], onPage=_page_content),
        ])

        # ── TOC ─────────────────────────────────────────────────────────
        toc = TableOfContents()
        toc.dotsMinLevel = 0        # dot leaders for every heading level
        toc.levelStyles  = [st["TOC1"], st["TOC2"]]

        # ── Story ───────────────────────────────────────────────────────
        story: list = []
        story += self._page_title(st)
        story += self._page_toc(toc, st)
        story += self._sec_intake(meta, st)
        story += self._sec_packages(data.get("Package_Extraction") or [], st)
        story += self._sec_static(data.get("Static_Analysis_Results", {}), st)
        story += self._sec_dynamic(
            data.get("Dynamic_Analysis_Results", {}),
            data.get("Dynamic_Summary",          {}),
            st,
        )

        # Two-pass build → accurate TOC page numbers
        doc.multiBuild(story)

    # ══════════════════════════════════════════════════════════════════
    # PAGE 1 — Title (flowables are just spacers; chrome is all canvas)
    # ══════════════════════════════════════════════════════════════════
    def _page_title(self, st: dict) -> list:
        # The canvas callback (_page_title fn) paints the entire page.
        # NextPageTemplate switches the following pages to Content.
        # PageBreak closes page 1 so page 2 opens with Content template.
        return [
            NextPageTemplate("Content"),
            PageBreak(),
        ]

    # ══════════════════════════════════════════════════════════════════
    # PAGE 2 — Table of Contents
    # ══════════════════════════════════════════════════════════════════
    def _page_toc(self, toc: TableOfContents, st: dict) -> list:
        elems: list = [NextPageTemplate("Content")]

        # "Contents" heading — not registered in TOC itself
        elems.append(Paragraph("Contents", ParagraphStyle(
            "ContentsHeading",
            fontName="Helvetica-Bold", fontSize=20,
            textColor=C_NAVY, spaceAfter=4, spaceBefore=4,
        )))
        elems.append(HRFlowable(
            width="100%", thickness=2,
            color=C_BLUE, spaceAfter=10,
        ))
        elems.append(toc)
        elems.append(PageBreak())
        return elems

    # ══════════════════════════════════════════════════════════════════
    # SECTION 1 — File Intake Summary
    # ══════════════════════════════════════════════════════════════════
    def _sec_intake(self, metadata: dict, st: dict) -> list:
        elems: list = []
        elems.append(Paragraph("1.  File Intake Summary", st["H1"]))
        elems.append(Paragraph(
            "Metadata captured at ingestion time. Hash values are computed "
            "immediately on submission before any analysis step touches the file.",
            st["IntroText"],
        ))
        if metadata:
            elems.append(_param_table(list(metadata.items()), st))
        else:
            elems.append(Paragraph("No intake metadata available.", st["Body"]))
        elems.append(Spacer(1, 0.4 * cm))
        return elems

    # ══════════════════════════════════════════════════════════════════
    # SECTION 2 — Package & Archive Unpacking
    # ══════════════════════════════════════════════════════════════════
    def _sec_packages(self, pkg: list, st: dict) -> list:
        elems: list = []
        elems.append(Paragraph("2.  Package &amp; Archive Unpacking", st["H1"]))

        if not pkg:
            elems.append(Paragraph(
                "Not applicable — the submitted file is not a ZIP archive or MSI package.",
                st["IntroText"],
            ))
            elems.append(Spacer(1, 0.3 * cm))
            return elems

        flagged = [f for f in pkg if f.get("Is_Flagged")]
        elems.append(Paragraph(
            f"Extracted <b>{len(pkg)}</b> file(s) — "
            f"<font color='#BE1414'><b>{len(flagged)} flagged</b></font>"
            f" as executable payloads.",
            st["Body"],
        ))
        elems.append(Spacer(1, 0.25 * cm))

        # Summary stats
        elems.append(_param_table([
            ("Total Extracted Files", len(pkg)),
            ("Flagged Payloads",      len(flagged)),
        ], st))
        elems.append(Spacer(1, 0.3 * cm))

        # Artefact table
        elems.append(Paragraph("Extracted Artefacts", st["H2"]))
        elems.append(Spacer(1, 0.15 * cm))
        rows = []
        for item in pkg:
            sha = _safe(item.get("SHA256", "N/A"))
            sha_abbrev = sha[:16] + "..." if len(sha) > 16 else sha
            flag_str = "FLAGGED" if item.get("Is_Flagged") else "clean"
            rows.append([
                _safe(item.get("Relative_Path", "?")),
                _safe(item.get("Extension", "")),
                str(item.get("Size_Bytes", 0)),
                sha_abbrev,
                flag_str,
            ])
        elems.append(_data_table(
            ["Path", "Ext", "Size (B)", "SHA-256 (abbrev.)", "Status"],
            rows,
            [0.36, 0.07, 0.11, 0.30, 0.16],
            st,
            flag_col=4,
        ))
        elems.append(Spacer(1, 0.4 * cm))
        return elems

    # ══════════════════════════════════════════════════════════════════
    # SECTION 3 — Deep Static Analysis
    # ══════════════════════════════════════════════════════════════════
    def _sec_static(self, static_data: dict, st: dict) -> list:
        elems: list = []
        elems.append(Paragraph("3.  Deep Static Analysis", st["H1"]))
        elems.append(Paragraph(
            "PE file inspection performed without executing the sample. Covers header metadata, "
            "security mitigations, section entropy, IAT analysis, manifest parsing, "
            "string extraction, and YARA signature matching.",
            st["IntroText"],
        ))

        if not static_data:
            elems.append(Paragraph(
                "No static analysis results — target is not a recognised PE executable.",
                st["Body"],
            ))
            elems.append(Spacer(1, 0.4 * cm))
            return elems

        for target_name, results in static_data.items():
            elems.append(Paragraph(f"Target: {_safe(target_name)}", st["H2"]))
            elems.append(Spacer(1, 0.1 * cm))

            for category, cat_data in results.items():
                elems.append(Paragraph(_safe(category), st["H3"]))

                if isinstance(cat_data, dict):
                    elems.append(_param_table(
                        [(k, v) for k, v in cat_data.items()], st
                    ))
                elif isinstance(cat_data, list):
                    for item in cat_data:
                        text = _safe(str(item))
                        sty  = _flag_style(text, st)
                        elems.append(Paragraph(f"\u2022  {text}", sty))
                else:
                    elems.append(Paragraph(_safe(str(cat_data)), st["Body"]))

                elems.append(Spacer(1, 0.2 * cm))

            elems.append(Spacer(1, 0.3 * cm))

        return elems

    # ══════════════════════════════════════════════════════════════════
    # SECTION 4 — Dynamic Sandbox Analysis
    # ══════════════════════════════════════════════════════════════════
    def _sec_dynamic(
        self,
        dyn_data: dict,
        dyn_sum:  dict,
        st:       dict,
    ) -> list:
        elems: list = []
        elems.append(Paragraph("4.  Dynamic Sandbox Analysis", st["H1"]))
        elems.append(Paragraph(
            "Behavioural telemetry captured during live detonation in the VMware sandbox. "
            "The in-guest agent instruments filesystem, registry, network, process, memory, "
            "and hardware subsystems in real time.",
            st["IntroText"],
        ))

        if not dyn_data:
            elems.append(Paragraph(
                "No dynamic analysis results — the dynamic module was either skipped "
                "or the VMware sandbox is not configured.",
                st["Body"],
            ))
            elems.append(Spacer(1, 0.4 * cm))
            return elems

        for target_name, telemetry in dyn_data.items():
            elems.append(Paragraph(f"Target: {_safe(target_name)}", st["H2"]))
            elems.append(Spacer(1, 0.1 * cm))

            # Error case
            if "Error" in telemetry:
                elems.append(Paragraph(
                    f"Detonation error: {_safe(telemetry['Error'])}",
                    st["Alert"],
                ))
                elems.append(Spacer(1, 0.25 * cm))
                continue

            # 4a — Telemetry summary table
            elems.append(Paragraph("Telemetry Summary", st["H3"]))
            elems.append(Spacer(1, 0.1 * cm))
            summary_target = dyn_sum.get(target_name, {})
            sum_rows = []
            for cat in TELEMETRY_KEYS:
                label    = CATEGORY_LABELS.get(cat, cat)
                cat_s    = summary_target.get(cat, {})
                count    = cat_s.get("count", len(telemetry.get(cat, [])))
                notable  = cat_s.get("notable", [])
                notable_str = f"{len(notable)} flagged" if notable else "\u2014"
                sum_rows.append([label, str(count), notable_str])

            elems.append(_data_table(
                ["Category", "Events", "Notable / High-Risk"],
                sum_rows,
                [0.60, 0.15, 0.25],
                st,
                flag_col=2,
            ))
            elems.append(Spacer(1, 0.35 * cm))

            # 4b — Per-category event detail
            elems.append(Paragraph("Event Detail", st["H3"]))
            elems.append(Spacer(1, 0.1 * cm))

            for cat in TELEMETRY_KEYS:
                events = telemetry.get(cat, [])
                if not events:
                    continue

                label = CATEGORY_LABELS.get(cat, cat)
                d     = _desc(cat)
                block: list = [
                    Paragraph(_safe(f"{label}  ({len(events)} event{'s' if len(events) != 1 else ''})"),
                               st["H3"]),
                ]
                if d:
                    block.append(Paragraph(d, st["Desc"]))
                block.append(Spacer(1, 0.05 * cm))

                for ev in events:
                    txt   = _safe(str(ev))
                    upper = txt.upper()
                    if any(k in upper for k in (
                        "INJECT", "RANSOM", "PROCESS_SPAWN", "REG_RUN_KEY", "FILE_DROP"
                    )):
                        sty = st["Alert"]
                    elif any(k in upper for k in ("NETWORK", "DNS", "HTTP", "TLS")):
                        sty = st["Warning"]
                    else:
                        sty = st["BodySmall"]
                    block.append(Paragraph(f"\u2022  {txt}", sty))

                block.append(Spacer(1, 0.2 * cm))
                elems.append(KeepTogether(block))

            elems.append(Spacer(1, 0.5 * cm))

        return elems
