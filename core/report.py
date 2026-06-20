"""
MARS — Report Generator  (ReportLab · redesigned layout)
=========================================================
Pages
  1   Title page  — full canvas painting, no flowables
  2   Table of Contents — auto-built via two-pass multiBuild;
                          dot leaders + right-aligned page numbers
  3   Executive Summary — Verdict, severity score, one-paragraph summary
  4   Threat Scoring    — per-target scorecard with gauge bars
  5   IoC Summary       — consolidated copy-pasteable indicators of compromise
  6+  Section 1 — File Intake Summary
      Section 2 — Package & Archive Unpacking
      Section 3 — Deep Static Analysis
      Section 4 — Dynamic Sandbox Analysis
"""

import os
import re
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
C_PAGE_BG   = colors.HexColor("#F7F9FC")
C_WHITE     = colors.white

# -- Brand / Primary --
C_NAVY      = colors.HexColor("#1A2744")
C_SLATE     = colors.HexColor("#263056")
C_BLUE      = colors.HexColor("#3B5BDB")
C_BLUE_SOFT = colors.HexColor("#4C6EF5")

# -- Text --
C_TEXT      = colors.HexColor("#111827")
C_MUTED     = colors.HexColor("#6B7280")
C_HINT      = colors.HexColor("#9CA3AF")

# -- Table --
C_TH_BG     = colors.HexColor("#1A2744")
C_TH_FG     = colors.white
C_ROW_A     = colors.white
C_ROW_B     = colors.HexColor("#F0F4FF")
C_ROW_BORDER = colors.HexColor("#DDE3F0")

# -- Status --
C_RED       = colors.HexColor("#BE1414")
C_AMBER     = colors.HexColor("#B45309")
C_GREEN     = colors.HexColor("#047857")
C_RED_BG    = colors.HexColor("#FEF2F2")
C_AMBER_BG  = colors.HexColor("#FFFBEB")
C_GREEN_BG  = colors.HexColor("#ECFDF5")

# -- Verdict chips --
C_VERDICT_MAL  = colors.HexColor("#BE1414")
C_VERDICT_SUS  = colors.HexColor("#B45309")
C_VERDICT_CLN  = colors.HexColor("#047857")
C_VERDICT_MAL_BG = colors.HexColor("#FEF2F2")
C_VERDICT_SUS_BG = colors.HexColor("#FFFBEB")
C_VERDICT_CLN_BG = colors.HexColor("#ECFDF5")

# -- Title page --
C_TP_BG     = colors.HexColor("#111827")
C_TP_BAND   = colors.HexColor("#1A2744")
C_TP_ACCENT = colors.HexColor("#3B5BDB")
C_TP_TITLE  = colors.white
C_TP_SUB    = colors.HexColor("#93C5FD")
C_TP_META_L = colors.HexColor("#6B7280")
C_TP_META_V = colors.HexColor("#E5E7EB")

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

        "BodyMonoSmall": ps("BodyMonoSmall",
                            fontName="Courier", fontSize=7.5,
                            textColor=C_TEXT, leading=11),

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

        "AlertMono": ps("AlertMono",
                        fontName="Courier-Bold", fontSize=8,
                        textColor=C_RED, leading=12),

        "Warning": ps("Warning",
                      fontName="Helvetica-Bold", fontSize=9,
                      textColor=C_AMBER, leading=14),

        "Clean": ps("Clean",
                    fontName="Helvetica", fontSize=9,
                    textColor=C_GREEN, leading=14),

        # ── Executive Summary ───────────────────────────────────────────
        "VerdictLabel": ps("VerdictLabel",
                           fontName="Helvetica-Bold", fontSize=28,
                           textColor=C_WHITE, leading=36,
                           alignment=TA_CENTER),

        "SeverityScore": ps("SeverityScore",
                            fontName="Helvetica-Bold", fontSize=14,
                            textColor=C_NAVY, leading=20,
                            alignment=TA_CENTER, spaceAfter=8),

        "ExecSummaryBody": ps("ExecSummaryBody",
                              fontName="Helvetica", fontSize=9.5,
                              textColor=C_TEXT, leading=16,
                              spaceAfter=6, spaceBefore=6,
                              leftIndent=4, rightIndent=4),

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
    c = canvas
    c.saveState()
    ts = datetime.datetime.now().strftime("%Y-%m-%d")

    c.setFillColor(C_TP_BG)
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

    panel_y = PAGE_H * 0.30
    panel_h = PAGE_H * 0.42
    c.setFillColor(C_TP_BAND)
    c.rect(0, panel_y, PAGE_W, panel_h, fill=1, stroke=0)

    stripe_w = 6
    c.setFillColor(C_TP_ACCENT)
    c.rect(MARGIN, panel_y, stripe_w, panel_h, fill=1, stroke=0)

    c.setFont("Helvetica-Bold", 72)
    c.setFillColor(C_TP_TITLE)
    c.drawCentredString(PAGE_W / 2, panel_y + panel_h - 1.2 * cm - 72 * 0.352778 * mm, "MARS")

    c.setFont("Helvetica", 15)
    c.setFillColor(C_TP_SUB)
    c.drawCentredString(
        PAGE_W / 2,
        panel_y + panel_h - 1.2 * cm - 72 * 0.352778 * mm - 1.0 * cm,
        "Malware Analysis & Reverse-engineering System",
    )

    rule_y = panel_y + panel_h * 0.38
    c.setStrokeColor(C_TP_ACCENT)
    c.setLineWidth(1.5)
    c.line(MARGIN + stripe_w + 10, rule_y, PAGE_W - MARGIN, rule_y)

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
        v = str(value)
        if len(v) > 55:
            v = v[:52] + "..."
        c.drawString(value_x, row_y, v)
        row_y -= row_step

    chip_w, chip_h = 5.2 * cm, 0.55 * cm
    chip_x = (PAGE_W - chip_w) / 2
    chip_y = panel_y - 1.6 * cm
    c.setFillColor(C_TP_ACCENT)
    c.roundRect(chip_x, chip_y, chip_w, chip_h, 3, fill=1, stroke=0)
    c.setFont("Helvetica-Bold", 8)
    c.setFillColor(colors.white)
    c.drawCentredString(PAGE_W / 2, chip_y + 0.145 * cm, "CONFIDENTIAL — INTERNAL USE ONLY")

    c.setFillColor(C_TP_ACCENT)
    c.rect(0, 0, PAGE_W, 0.45 * cm, fill=1, stroke=0)

    c.restoreState()


def _page_content(canvas, doc):
    c = canvas
    c.saveState()
    ts = datetime.datetime.now().strftime("%Y-%m-%d")

    c.setFillColor(C_WHITE)
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

    bar_h = 1.0 * cm
    c.setFillColor(C_NAVY)
    c.rect(0, PAGE_H - bar_h, PAGE_W, bar_h, fill=1, stroke=0)

    c.setFillColor(C_BLUE)
    c.rect(0, PAGE_H - bar_h, 5, bar_h, fill=1, stroke=0)

    c.setFont("Helvetica-Bold", 8.5)
    c.setFillColor(colors.white)
    c.drawString(MARGIN, PAGE_H - bar_h + 0.28 * cm,
                 "MARS  \u2014  Malware Analysis & Reverse-engineering System")

    c.setFont("Helvetica", 7.5)
    c.setFillColor(C_TP_META_L)
    c.drawRightString(PAGE_W - MARGIN, PAGE_H - bar_h + 0.28 * cm, ts)

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


def _clean_hash(v: str) -> str:
    """Normalise a hash string: strip duplicates/concatenations and trim to max 64 chars."""
    v = v.strip()
    # If a repeated pattern is detected (hash concatenated with itself), take first half
    half = len(v) // 2
    if half >= 32 and v[:half] == v[half:]:
        v = v[:half]
    # Trim excessively long values
    if len(v) > 64:
        v = v[:64]
    return v


def _trim_hash(v: str, max_len: int = 16) -> str:
    """Return abbreviated hash for display in narrow table cells."""
    v = _clean_hash(v)
    if len(v) > max_len:
        return v[:max_len] + "..."
    return v


def _is_hash_key(key: str) -> bool:
    k = key.upper()
    return any(tok in k for tok in ("SHA", "MD5", "HASH"))


def _is_mono_key(key: str) -> bool:
    """Keys whose values should be rendered in monospace."""
    k = key.upper()
    return any(tok in k for tok in (
        "SHA", "MD5", "HASH", "PATH", "ADDRESS", "ENTRY POINT",
        "IMAGE BASE", "E_LFANEW", "OFFSET", "MAGIC",
    ))


def _is_mono_value(v: str) -> bool:
    """Values that look like hex addresses, registry keys, or file paths."""
    v = v.strip()
    if re.match(r"^0x[0-9a-fA-F]+", v):
        return True
    if v.upper().startswith(("HKCU", "HKLM", "HKEY_", "SOFTWARE\\", "SYSTEM\\")):
        return True
    return False


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


def _sanitize_notable(v) -> str:
    """Replace '?' or None with 'N/A' to avoid making the report look incomplete."""
    if v is None or str(v).strip() in ("?", "", "None"):
        return "N/A"
    return str(v)


# ═══════════════════════════════════════════════════════════════════════════
# TABLE BUILDERS
# ═══════════════════════════════════════════════════════════════════════════
def _param_table(rows: list[tuple], styles: dict) -> Table:
    """Two-column key/value parameter table with optional description row.
    Hashes, addresses, and paths are automatically rendered in monospace.
    """
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
        key_str = str(k)
        val_raw = _safe(v)

        # Clean up hashes before display
        if _is_hash_key(key_str):
            val_raw = _clean_hash(val_raw)

        # Choose style: monospace for technical values
        if _is_mono_key(key_str) or _is_mono_value(val_raw):
            val_style = styles["BodyMono"]
        else:
            val_style = _flag_style(val_raw, styles)

        val_para = Paragraph(val_raw, val_style)
        d        = _desc(key_str)
        val_cell = [val_para, Paragraph(d, styles["Desc"])] if d else [val_para]
        data.append([
            Paragraph(_safe(key_str), styles["BodyBold"]),
            val_cell,
        ])

        # Tint alert/warning rows (only if not already overridden by monospace)
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
    mono_cols: list[int] | None = None,
) -> Table:
    """
    Generic tabular data table with zebra striping and conditional row tinting.
    mono_cols — column indices whose values should use monospace font.
    """
    col_w   = [CONTENT_W * f for f in col_fracs]
    th_row  = [Paragraph(_safe(h), styles["TH"]) for h in headers]
    table_rows = [th_row]
    mono_cols  = mono_cols or []
    ts_cmds = [
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
        for ci, cell in enumerate(row):
            if isinstance(cell, str):
                val_text = _safe(cell)
                if ci in mono_cols:
                    sty = styles["BodyMonoSmall"]
                else:
                    sty = _flag_style(val_text, styles)
                built.append(Paragraph(val_text, sty))
            else:
                built.append(cell)
        table_rows.append(built)

        # Row-level tinting based on flag column
        if flag_col is not None:
            raw    = row[flag_col] if isinstance(row[flag_col], str) else ""
            raw_up = raw.upper()
            ri     = i + 1
            if any(k in raw_up for k in ("FLAGGED", "[CRITICAL]", "INJECT", "RANSOM", "MALICIOUS")):
                ts_cmds.append(("BACKGROUND", (0, ri), (-1, ri), C_RED_BG))
                ts_cmds.append(("TEXTCOLOR",  (flag_col, ri), (flag_col, ri), C_RED))
                ts_cmds.append(("FONTNAME",   (flag_col, ri), (flag_col, ri), "Helvetica-Bold"))
            elif any(k in raw_up for k in ("[WARNING]", "DNS", "HTTP", "NETWORK", "SUSPICIOUS")):
                ts_cmds.append(("BACKGROUND", (0, ri), (-1, ri), C_AMBER_BG))
            elif any(k in raw_up for k in ("CLEAN", "OK", "NONE")):
                ts_cmds.append(("BACKGROUND", (0, ri), (-1, ri), C_GREEN_BG))
                ts_cmds.append(("TEXTCOLOR",  (flag_col, ri), (flag_col, ri), C_GREEN))

    tbl = Table(table_rows, colWidths=col_w, repeatRows=1)
    tbl.setStyle(TableStyle(ts_cmds))
    return tbl


# ═══════════════════════════════════════════════════════════════════════════
# VERDICT & IoC HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def _compute_verdict(data: dict) -> tuple[str, float, str]:
    """
    Analyse the compiled report data and return (verdict, score, summary_text).
    verdict  — "MALICIOUS" | "SUSPICIOUS" | "CLEAN"
    score    — float 0.0–10.0
    summary  — one-paragraph plain-English description
    """
    score = 0.0
    indicators: list[str] = []

    static = data.get("Static_Analysis_Results", {})
    for _tgt, result in static.items():
        if not isinstance(result, dict):
            continue
        # YARA hits
        for cat, cat_data in result.items():
            if "yara" in cat.lower() and isinstance(cat_data, dict):
                hits = int(cat_data.get("Hits", 0) or 0)
                if hits > 0:
                    score += min(hits * 1.5, 4.0)
                    indicators.append(f"{hits} YARA rule(s) matched")
            # Suspicious APIs
            if "import" in cat.lower() and isinstance(cat_data, dict):
                tracked = int(cat_data.get("Tracked APIs Found", 0) or 0)
                if tracked > 0:
                    score += min(tracked * 0.4, 2.0)
                    indicators.append(f"{tracked} suspicious API import(s) detected")
            # Packing / entropy
            if isinstance(cat_data, list):
                for item in cat_data:
                    t = str(item).upper()
                    if "[CRITICAL]" in t or "[PACKED" in t:
                        score += 1.5
                        indicators.append("High-entropy / packed section detected")
                        break
            if isinstance(cat_data, dict):
                for v in cat_data.values():
                    t = str(v).upper()
                    if "[CRITICAL]" in t:
                        score += 0.5
                        indicators.append("Critical static flag")
                        break

    # Dynamic indicators
    dyn = data.get("Dynamic_Analysis_Results", {})
    for _tgt, telemetry in dyn.items():
        if not isinstance(telemetry, dict):
            continue
        for cat, events in telemetry.items():
            if not isinstance(events, list):
                continue
            for ev in events:
                t = str(ev).upper()
                if any(k in t for k in ("INJECT", "RANSOM", "HOLLOW", "PROCESS_HOLLOW")):
                    score += 1.0
                    indicators.append(f"High-risk dynamic event: {str(ev)[:60]}")
                    break
                if any(k in t for k in ("REG_RUN_KEY", "PERSISTENCE", "STARTUP")):
                    score += 0.5
                    indicators.append("Persistence mechanism observed")
                    break

    # Flagged packages
    pkg = data.get("Package_Extraction", [])
    flagged_pkg = [p for p in pkg if isinstance(p, dict) and p.get("Is_Flagged")]
    if flagged_pkg:
        score += min(len(flagged_pkg) * 0.5, 1.5)
        indicators.append(f"{len(flagged_pkg)} executable payload(s) extracted from archive")

    score = round(min(score, 10.0), 1)

    if score >= 6.0:
        verdict = "MALICIOUS"
    elif score >= 3.0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    # Build one-paragraph summary
    if not indicators:
        summary = (
            "No significant threat indicators were identified during static or dynamic analysis. "
            "The sample appears clean based on available evidence; manual review is still recommended "
            "for high-value targets."
        )
    else:
        unique = list(dict.fromkeys(indicators))[:5]
        joined = "; ".join(unique)
        if verdict == "MALICIOUS":
            summary = (
                f"The sample exhibits strong malicious characteristics. Key findings include: {joined}. "
                "Immediate containment and further IOC-based hunting across the environment is advised."
            )
        else:
            summary = (
                f"The sample raised {len(indicators)} indicator(s) of potentially suspicious behaviour. "
                f"Key findings: {joined}. "
                "Further investigation and contextual review are recommended before making a final determination."
            )

    return verdict, score, summary


def _extract_iocs(data: dict) -> dict:
    """
    Walk the compiled report data and extract Indicators of Compromise.
    Returns dict with keys: hashes, domains, ips, file_paths, registry_keys.
    """
    iocs: dict = {
        "hashes":       [],   # (type, value)
        "domains":      [],
        "ips":          [],
        "file_paths":   [],
        "registry_keys": [],
    }
    seen: set = set()

    def _add(bucket: str, val: str):
        val = val.strip()
        if val and val not in seen and val not in ("N/A", "?", "-", "\u2014"):
            seen.add(val)
            iocs[bucket].append(val)

    # Hashes from intake metadata
    meta = data.get("Analysis_Summary", {})
    for htype in ("MD5", "SHA1", "SHA256"):
        v = str(meta.get(htype, "")).strip()
        if v and v not in ("N/A", "?"):
            v = _clean_hash(v)
            key = f"{htype}:{v}"
            if key not in seen:
                seen.add(key)
                iocs["hashes"].append((htype, v))

    # Hashes from extracted packages
    for pkg in data.get("Package_Extraction", []):
        if not isinstance(pkg, dict) or not pkg.get("Is_Flagged"):
            continue
        sha = _clean_hash(str(pkg.get("SHA256", "")))
        if sha:
            key = f"SHA256:{sha}"
            if key not in seen:
                seen.add(key)
                iocs["hashes"].append(("SHA256 (pkg)", sha))
        _add("file_paths", str(pkg.get("Relative_Path", "")))

    # Static: dropped paths, PE artefacts
    static = data.get("Static_Analysis_Results", {})
    for _tgt, result in static.items():
        if not isinstance(result, dict):
            continue
        for cat, cat_data in result.items():
            if isinstance(cat_data, list):
                for item in cat_data:
                    t = str(item)
                    # Paths
                    if re.search(r"[A-Za-z]:\\|/tmp/|/var/|C:/", t):
                        _add("file_paths", t[:120])
            if isinstance(cat_data, dict):
                for k, v in cat_data.items():
                    t = str(v)
                    if re.search(r"[A-Za-z]:\\|/tmp/|C:/", t):
                        _add("file_paths", t[:120])

    # Dynamic: network (domains/IPs), file drops, registry run keys
    dyn = data.get("Dynamic_Analysis_Results", {})
    for _tgt, telemetry in dyn.items():
        if not isinstance(telemetry, dict):
            continue
        net_events = telemetry.get("Network", [])
        for ev in net_events:
            t = str(ev)
            # Extract domain-like strings
            dom = re.findall(
                r"\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|ru|cn|tk|xyz|info|biz|onion)\b", t
            )
            for d in dom:
                _add("domains", d)
            # Extract IPs
            ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t)
            for ip in ips:
                if not ip.startswith(("127.", "0.", "255.")):
                    _add("ips", ip)

        reg_events = telemetry.get("Registry", [])
        for ev in reg_events:
            t = str(ev)
            keys = re.findall(r"HK[A-Z_]+(?:\\[^\s,\]]+)+", t)
            for rk in keys:
                _add("registry_keys", rk)

        fs_events = telemetry.get("Filesystem", [])
        for ev in fs_events:
            t = str(ev)
            if "FILE_DROP" in t.upper() or "CREATE" in t.upper():
                paths = re.findall(r"[A-Za-z]:\\(?:[^\s,\]]+)", t)
                for p in paths:
                    _add("file_paths", p[:120])

    return iocs


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
        scoring_results: dict | None = None,
    ):
        pub.sendMessage("gui.log", msg="\n[*] --- Starting Reporting Module ---")

        analysis_id = metadata.get(
            "Analysis ID",
            f"MARS_UNKNOWN_{datetime.datetime.now().strftime('%H%M%S')}",
        )
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

        # JSON
        json_path = f"{base}.json"
        with open(json_path, "w") as fh:
            json.dump(compiled, fh, indent=4)
        pub.sendMessage("gui.log", msg=f"  [+] JSON Report Saved: {json_path}")

        # PDF
        pdf_path = f"{base}.pdf"
        try:
            self._build_pdf(compiled, pdf_path, scoring_results=scoring_results)
            pub.sendMessage("gui.log", msg=f"  [+] PDF Report Saved: {pdf_path}")
        except Exception as exc:
            pub.sendMessage("gui.log", msg=f"  [!] PDF generation failed: {exc}")
            raise

    # ── PDF orchestrator ───────────────────────────────────────────────
    def _build_pdf(self, data: dict, path: str, *, scoring_results: dict | None = None):
        st   = _styles()
        meta = data.get("Analysis_Summary", {})
        scoring_results = scoring_results or {}

        doc = _MARSDoc(
            path,
            pagesize=A4,
            leftMargin=MARGIN, rightMargin=MARGIN,
            topMargin=1.2 * cm, bottomMargin=1.1 * cm,
        )
        doc._mars_meta = meta

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

        toc = TableOfContents()
        toc.dotsMinLevel = 0
        toc.levelStyles  = [st["TOC1"], st["TOC2"]]

        # Derive executive-summary values: prefer ScoringResult if available
        if scoring_results:
            # Pick the highest-scoring target as the primary verdict
            primary_sr = max(scoring_results.values(), key=lambda r: r.total_score)
            verdict    = primary_sr.verdict
            score      = primary_sr.total_score
            summary    = self._build_summary_text(primary_sr)
        else:
            verdict, score, summary = _compute_verdict(data)
            primary_sr = None

        iocs = _extract_iocs(data)

        story: list = []
        story += self._page_title(st)
        story += self._page_toc(toc, st)
        story += self._sec_executive_summary(verdict, score, summary, meta, st)
        if scoring_results:
            story += self._sec_scoring(scoring_results, st)
        story += self._sec_ioc_summary(iocs, st)
        story += self._sec_intake(meta, st)
        story += self._sec_packages(data.get("Package_Extraction") or [], st)
        story += self._sec_static(data.get("Static_Analysis_Results", {}), st)
        story += self._sec_dynamic(
            data.get("Dynamic_Analysis_Results", {}),
            data.get("Dynamic_Summary",          {}),
            st,
        )

        doc.multiBuild(story)

    @staticmethod
    def _build_summary_text(sr) -> str:
        """Produce a one-paragraph executive summary from a ScoringResult."""
        findings = sr.top_findings(5)
        if not findings:
            return (
                "No significant threat indicators were identified during analysis. "
                "The sample appears clean based on available evidence; manual review "
                "is still recommended for high-value targets."
            )
        joined = "; ".join(findings)
        if sr.verdict == "MALICIOUS":
            return (
                f"The sample is assessed as MALICIOUS with a threat score of "
                f"{sr.total_score}/10.0 ({sr.confidence} confidence). "
                f"Key findings: {joined}. "
                "Immediate containment and environment-wide IOC hunting is advised."
            )
        if sr.verdict == "HIGH RISK":
            return (
                f"The sample exhibits high-risk characteristics (score {sr.total_score}/10.0, "
                f"{sr.confidence} confidence). Key findings: {joined}. "
                "Escalate for analyst review and consider quarantine pending investigation."
            )
        return (
            f"The sample raised {len(findings)} indicator(s) of suspicious behaviour "
            f"(score {sr.total_score}/10.0, {sr.confidence} confidence). "
            f"Findings: {joined}. "
            "Further investigation and contextual review are recommended."
        )

    # ══════════════════════════════════════════════════════════════════
    # PAGE 1 — Title
    # ══════════════════════════════════════════════════════════════════
    def _page_title(self, st: dict) -> list:
        return [
            NextPageTemplate("Content"),
            PageBreak(),
        ]

    # ══════════════════════════════════════════════════════════════════
    # PAGE 2 — Table of Contents
    # ══════════════════════════════════════════════════════════════════
    def _page_toc(self, toc: TableOfContents, st: dict) -> list:
        elems: list = [NextPageTemplate("Content")]
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
    # PAGE 3 — Executive Summary
    # ══════════════════════════════════════════════════════════════════
    def _sec_executive_summary(
        self,
        verdict: str,
        score:   float,
        summary: str,
        meta:    dict,
        st:      dict,
    ) -> list:
        elems: list = []
        elems.append(Paragraph("Executive Summary", st["H1"]))

        # Verdict colour mapping
        v_color, v_bg = {
            "MALICIOUS":  (C_VERDICT_MAL, C_VERDICT_MAL_BG),
            "SUSPICIOUS": (C_VERDICT_SUS, C_VERDICT_SUS_BG),
            "CLEAN":      (C_VERDICT_CLN, C_VERDICT_CLN_BG),
        }.get(verdict, (C_NAVY, C_ROW_B))

        # Verdict + score panel (rendered as a 2-column table)
        verdict_label_style = ParagraphStyle(
            "VL", fontName="Helvetica-Bold", fontSize=22,
            textColor=v_color, alignment=TA_CENTER, leading=28,
        )
        score_label_style = ParagraphStyle(
            "SL", fontName="Helvetica-Bold", fontSize=13,
            textColor=C_NAVY, alignment=TA_CENTER, leading=18,
        )
        score_sub_style = ParagraphStyle(
            "SS", fontName="Helvetica", fontSize=8,
            textColor=C_MUTED, alignment=TA_CENTER, leading=12,
        )

        verdict_cell = [
            Paragraph(verdict, verdict_label_style),
        ]
        score_cell = [
            Paragraph(f"{score} / 10.0", score_label_style),
            Paragraph("Severity Score", score_sub_style),
        ]

        panel_data = [[verdict_cell, score_cell]]
        panel_style = TableStyle([
            ("BACKGROUND",   (0, 0), (0, 0), v_bg),
            ("BACKGROUND",   (1, 0), (1, 0), C_ROW_B),
            ("BOX",          (0, 0), (-1, -1), 1.5, v_color),
            ("LINEBEFORE",   (1, 0), (1, 0), 1.5, v_color),
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",   (0, 0), (-1, -1), 14),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 14),
            ("LEFTPADDING",  (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ])
        panel = Table(panel_data, colWidths=[CONTENT_W * 0.55, CONTENT_W * 0.45])
        panel.setStyle(panel_style)
        elems.append(Spacer(1, 0.2 * cm))
        elems.append(panel)
        elems.append(Spacer(1, 0.3 * cm))

        # Summary paragraph
        elems.append(Paragraph("Analysis Summary", st["H2"]))
        elems.append(Paragraph(_safe(summary), st["ExecSummaryBody"]))
        elems.append(Spacer(1, 0.2 * cm))

        # Quick-reference metadata strip
        elems.append(Paragraph("Sample Identification", st["H2"]))
        elems.append(Spacer(1, 0.1 * cm))
        quick_rows = []
        for k in ("Filename", "MD5", "SHA256", "Submission Timestamp"):
            v = str(meta.get(k, "N/A"))
            if _is_hash_key(k):
                v = _clean_hash(v)
            quick_rows.append((k, v))
        elems.append(_param_table(quick_rows, st))
        elems.append(Spacer(1, 0.4 * cm))
        elems.append(PageBreak())
        return elems

    # ══════════════════════════════════════════════════════════════════
    # IoC Summary
    # ══════════════════════════════════════════════════════════════════
    def _sec_ioc_summary(self, iocs: dict, st: dict) -> list:
        elems: list = []
        elems.append(Paragraph("Indicators of Compromise (IoC Summary)", st["H1"]))
        elems.append(Paragraph(
            "Consolidated, copy-pasteable indicators extracted from all analysis phases. "
            "Use these directly for threat hunting, firewall rules, and SIEM ingestion.",
            st["IntroText"],
        ))

        has_any = any(iocs.get(k) for k in iocs)
        if not has_any:
            elems.append(Paragraph("No indicators of compromise were identified.", st["Body"]))
            elems.append(Spacer(1, 0.4 * cm))
            return elems

        # Hashes
        if iocs["hashes"]:
            elems.append(Paragraph("Cryptographic Hashes", st["H2"]))
            elems.append(Spacer(1, 0.1 * cm))
            hash_rows = [[htype, _safe(hval)] for htype, hval in iocs["hashes"]]
            elems.append(_data_table(
                ["Type", "Value"],
                hash_rows,
                [0.18, 0.82],
                st,
                mono_cols=[1],
            ))
            elems.append(Spacer(1, 0.25 * cm))

        # Domains
        if iocs["domains"]:
            elems.append(Paragraph("Malicious Domains", st["H2"]))
            elems.append(Spacer(1, 0.1 * cm))
            dom_rows = [[d] for d in iocs["domains"]]
            elems.append(_data_table(
                ["Domain / Hostname"],
                dom_rows,
                [1.0],
                st,
                mono_cols=[0],
            ))
            elems.append(Spacer(1, 0.25 * cm))

        # IPs
        if iocs["ips"]:
            elems.append(Paragraph("Malicious IP Addresses", st["H2"]))
            elems.append(Spacer(1, 0.1 * cm))
            ip_rows = [[ip] for ip in iocs["ips"]]
            elems.append(_data_table(
                ["IP Address"],
                ip_rows,
                [1.0],
                st,
                mono_cols=[0],
            ))
            elems.append(Spacer(1, 0.25 * cm))

        # File paths
        if iocs["file_paths"]:
            elems.append(Paragraph("Dropped / Created File Paths", st["H2"]))
            elems.append(Spacer(1, 0.1 * cm))
            fp_rows = [[_safe(p)] for p in iocs["file_paths"]]
            elems.append(_data_table(
                ["File Path"],
                fp_rows,
                [1.0],
                st,
                mono_cols=[0],
            ))
            elems.append(Spacer(1, 0.25 * cm))

        # Registry keys
        if iocs["registry_keys"]:
            elems.append(Paragraph("Suspicious Registry Keys", st["H2"]))
            elems.append(Spacer(1, 0.1 * cm))
            rk_rows = [[_safe(rk)] for rk in iocs["registry_keys"]]
            elems.append(_data_table(
                ["Registry Key"],
                rk_rows,
                [1.0],
                st,
                mono_cols=[0],
            ))
            elems.append(Spacer(1, 0.25 * cm))

        elems.append(PageBreak())
        return elems

    # ══════════════════════════════════════════════════════════════════
    # THREAT SCORECARD
    # ══════════════════════════════════════════════════════════════════
    def _sec_scoring(self, scoring_results: dict, st: dict) -> list:
        """
        Render a per-target threat scorecard section.
        For each ScoringResult:
          • A visual score gauge (10-cell progress bar table)
          • A category breakdown table (name, score, max, bar, findings)
          • A findings bullet list
        """
        from reportlab.lib import colors as rl_colors

        elems: list = []
        elems.append(Paragraph("Threat Scoring", st["H1"]))
        elems.append(Paragraph(
            "Each analysed executable is scored across six evidence categories. "
            "Scores are normalised to 0.0\u201310.0. "
            "Verdict thresholds: CLEAN \u2264 2.9 \u2022 SUSPICIOUS 3.0\u20134.9 "
            "\u2022 HIGH RISK 5.0\u20137.4 \u2022 MALICIOUS \u2265 7.5.",
            st["IntroText"],
        ))

        for target, sr in scoring_results.items():
            elems.append(Paragraph(f"Target: {_safe(target)}", st["H2"]))
            elems.append(Spacer(1, 0.15 * cm))

            # ── Verdict / score header panel ──────────────────────────────
            v_hex    = sr.verdict_color_hex
            v_bg_hex = sr.verdict_bg_hex
            try:
                v_color  = rl_colors.HexColor(v_hex)
                v_bg     = rl_colors.HexColor(v_bg_hex)
            except Exception:
                v_color, v_bg = C_NAVY, C_ROW_B

            verdict_style = ParagraphStyle(
                f"VS_{target}", fontName="Helvetica-Bold", fontSize=18,
                textColor=v_color, alignment=TA_CENTER, leading=24,
            )
            score_style = ParagraphStyle(
                f"SS_{target}", fontName="Helvetica-Bold", fontSize=12,
                textColor=C_NAVY, alignment=TA_CENTER, leading=18,
            )
            conf_style = ParagraphStyle(
                f"CS_{target}", fontName="Helvetica", fontSize=8,
                textColor=C_MUTED, alignment=TA_CENTER, leading=12,
            )
            header_data = [[
                [Paragraph(sr.verdict, verdict_style)],
                [
                    Paragraph(f"{sr.total_score:.1f} / 10.0", score_style),
                    Paragraph(f"Confidence: {sr.confidence}", conf_style),
                ],
            ]]
            header_tbl = Table(
                header_data,
                colWidths=[CONTENT_W * 0.55, CONTENT_W * 0.45],
            )
            header_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (0, 0), v_bg),
                ("BACKGROUND",    (1, 0), (1, 0), C_ROW_B),
                ("BOX",           (0, 0), (-1, -1), 1.5, v_color),
                ("LINEBEFORE",    (1, 0), (1, 0), 1.5, v_color),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",    (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ]))
            elems.append(header_tbl)
            elems.append(Spacer(1, 0.25 * cm))

            # ── 10-cell score gauge bar ───────────────────────────────────
            gauge_cells = 10
            filled      = int(round(sr.total_score))
            gauge_row   = []
            for i in range(gauge_cells):
                if i < filled:
                    cell_bg = v_color
                    label   = Paragraph("\u25a0", ParagraphStyle(
                        f"GB_{i}", fontName="Helvetica-Bold", fontSize=10,
                        textColor=rl_colors.white, alignment=TA_CENTER,
                    ))
                else:
                    cell_bg = C_ROW_B
                    label   = Paragraph("\u25a1", ParagraphStyle(
                        f"GE_{i}", fontName="Helvetica", fontSize=10,
                        textColor=C_HINT, alignment=TA_CENTER,
                    ))
                gauge_row.append(label)

            gauge_tbl = Table(
                [gauge_row],
                colWidths=[CONTENT_W / gauge_cells] * gauge_cells,
                rowHeights=[0.55 * cm],
            )
            gauge_cmds = [
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
                ("BOX",           (0, 0), (-1, -1), 0.5, C_ROW_BORDER),
                ("GRID",          (0, 0), (-1, -1), 0.3, C_ROW_BORDER),
            ]
            for i in range(gauge_cells):
                cell_bg = v_color if i < filled else C_ROW_B
                gauge_cmds.append(("BACKGROUND", (i, 0), (i, 0), cell_bg))
            gauge_tbl.setStyle(TableStyle(gauge_cmds))
            elems.append(gauge_tbl)
            elems.append(Spacer(1, 0.25 * cm))

            # ── Category breakdown table ──────────────────────────────────
            elems.append(Paragraph("Score Breakdown by Category", st["H3"]))
            elems.append(Spacer(1, 0.1 * cm))

            if sr.categories:
                cat_rows = []
                for cat in sr.categories:
                    bar_cells   = 10
                    filled_cat  = int(round(cat.normalised))
                    bar_str = ("\u25a0" * filled_cat) + ("\u25a1" * (bar_cells - filled_cat))
                    findings_str = "; ".join(cat.findings[:3]) if cat.findings else "None"
                    cat_rows.append([
                        _safe(cat.name),
                        f"{cat.score:.1f}/{cat.max_score:.0f}",
                        bar_str,
                        _safe(findings_str),
                    ])

                cat_tbl = _data_table(
                    ["Category", "Score", "Gauge (0–10)", "Key Findings"],
                    cat_rows,
                    [0.22, 0.10, 0.18, 0.50],
                    st,
                    mono_cols=[1, 2],
                )
                elems.append(cat_tbl)
            else:
                elems.append(Paragraph("No category data available.", st["Body"]))

            # ── Full findings bullet list ─────────────────────────────────
            all_findings = sr.top_findings(20)
            if all_findings:
                elems.append(Spacer(1, 0.2 * cm))
                elems.append(Paragraph("All Findings", st["H3"]))
                elems.append(Spacer(1, 0.05 * cm))
                for finding in all_findings:
                    txt = _safe(finding)
                    upper = txt.upper()
                    if any(k in upper for k in (
                        "INJECT", "RANSOM", "HOLLOW", "ESCALAT",
                        "SHADOW COPY", "TERMINATE", "UAC BYPASS",
                    )):
                        sty = st["Alert"]
                    elif any(k in upper for k in (
                        "NETWORK", "HTTP", "DNS", "RWE", "YARA", "PERSIST",
                        "SERVICE", "SCHEDULED",
                    )):
                        sty = st["Warning"]
                    else:
                        sty = st["BodySmall"]
                    elems.append(Paragraph(f"\u2022  {txt}", sty))

            elems.append(Spacer(1, 0.4 * cm))

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
            # Sanitize any hash values before passing to param table
            cleaned = {}
            for k, v in metadata.items():
                if _is_hash_key(k):
                    cleaned[k] = _clean_hash(str(v))
                else:
                    cleaned[k] = v
            elems.append(_param_table(list(cleaned.items()), st))
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

        elems.append(_param_table([
            ("Total Extracted Files", len(pkg)),
            ("Flagged Payloads",      len(flagged)),
        ], st))
        elems.append(Spacer(1, 0.3 * cm))

        elems.append(Paragraph("Extracted Artefacts", st["H2"]))
        elems.append(Spacer(1, 0.15 * cm))
        rows = []
        for item in pkg:
            raw_sha   = _safe(item.get("SHA256", "N/A"))
            sha_abbrev = _trim_hash(raw_sha, max_len=20)
            flag_str   = "FLAGGED" if item.get("Is_Flagged") else "clean"
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
            mono_cols=[3],
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
                    # Sanitize hashes in static sub-dicts
                    cleaned = {}
                    for k, v in cat_data.items():
                        if _is_hash_key(str(k)):
                            cleaned[k] = _clean_hash(str(v))
                        else:
                            cleaned[k] = v
                    elems.append(_param_table(
                        [(k, v) for k, v in cleaned.items()], st
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
                label   = CATEGORY_LABELS.get(cat, cat)
                cat_s   = summary_target.get(cat, {})
                count   = cat_s.get("count", len(telemetry.get(cat, [])))
                # Sanitize count: replace "?" or None with 0
                count_str = _sanitize_notable(count) if str(count).strip() in ("?", "", "None") else str(count)
                notable = cat_s.get("notable", [])
                # Sanitize notable: replace "?" with "N/A", calculate count if it's a list
                if isinstance(notable, list):
                    notable_str = f"{len(notable)} flagged" if notable else "0"
                else:
                    notable_str = _sanitize_notable(notable)
                sum_rows.append([label, count_str, notable_str])

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
                        "INJECT", "RANSOM", "PROCESS_SPAWN", "REG_RUN_KEY", "FILE_DROP",
                        "HOLLOW", "ESCALAT",
                    )):
                        sty = st["Alert"]
                    elif any(k in upper for k in ("NETWORK", "DNS", "HTTP", "TLS", "CONNECT")):
                        sty = st["Warning"]
                    elif _is_mono_value(txt):
                        sty = st["BodyMono"]
                    else:
                        sty = st["BodySmall"]
                    block.append(Paragraph(f"\u2022  {txt}", sty))

                block.append(Spacer(1, 0.2 * cm))
                elems.append(KeepTogether(block))

            elems.append(Spacer(1, 0.5 * cm))

        return elems
