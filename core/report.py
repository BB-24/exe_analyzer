import os
import json
import datetime
from fpdf import FPDF, XPos, YPos
from pubsub import pub

from core.dynamic import TELEMETRY_KEYS

# Human-readable labels for telemetry categories
CATEGORY_LABELS = {
    "Filesystem":  "Filesystem Activity (FR-DYN-01)",
    "Registry":    "Registry Mutations (FR-DYN-02)",
    "Persistence": "Persistence Mechanisms (FR-DYN-03)",
    "Processes":   "Process Activity (FR-DYN-04)",
    "Memory":      "Memory Forensics (FR-DYN-05)",
    "Network":     "Network Telemetry (FR-DYN-06)",
    "Hardware":    "Hardware / System Stress (FR-DYN-07)",
    "System":      "System & Agent Events",
}


class PDFReport(FPDF):
    """Custom FPDF class with a consistent header and footer."""

    def header(self):
        self.set_font("helvetica", "B", 15)
        self.cell(
            0, 10,
            "MARS -- Malware Analysis & Reverse-engineering System",
            border=0,
            align="C",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.set_font("helvetica", "I", 10)
        self.cell(
            0, 8,
            f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            border=0,
            align="C",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")


class ReportGenerator:
    def __init__(self, config):
        self.reports_dir = config.get("system", {}).get("reports_dir", "./workspace/reports")
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate_reports(self, metadata, package_data, static_data, dynamic_data=None, dynamic_summary=None):
        pub.sendMessage("gui.log", msg="\n[*] --- Starting Reporting Module ---")

        analysis_id = metadata.get(
            "Analysis ID",
            f"MARS_UNKNOWN_{datetime.datetime.now().strftime('%H%M%S')}",
        )
        base_filename = os.path.join(self.reports_dir, f"{analysis_id}_Report")

        compiled_report = {
            "Analysis_Summary":         metadata,
            "Package_Extraction":       package_data,
            "Static_Analysis_Results":  static_data,
            "Dynamic_Analysis_Results": dynamic_data or {},
            "Dynamic_Summary":          dynamic_summary or {},
        }

        # JSON
        json_path = f"{base_filename}.json"
        with open(json_path, "w") as f:
            json.dump(compiled_report, f, indent=4)
        pub.sendMessage("gui.log", msg=f"  [+] JSON Report Saved: {json_path}")

        # PDF
        pdf_path = f"{base_filename}.pdf"
        self._build_pdf(compiled_report, pdf_path)
        pub.sendMessage("gui.log", msg=f"  [+] PDF Report Saved: {pdf_path}")

    # ------------------------------------------------------------------
    # PDF builder
    # ------------------------------------------------------------------

    def _build_pdf(self, data, output_path):
        pdf = PDFReport()
        pdf.alias_nb_pages()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # ---- Section helpers ----------------------------------------

        def section_header(pdf_obj, number, title):
            pdf_obj.set_font("helvetica", "B", 12)
            pdf_obj.set_fill_color(30, 40, 70)
            pdf_obj.set_text_color(220, 235, 255)
            pdf_obj.cell(
                0, 9,
                f"  {number}. {title}",
                fill=True,
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
            pdf_obj.set_text_color(0, 0, 0)
            pdf_obj.ln(2)

        def subsection_header(pdf_obj, title, color=(0, 50, 150)):
            pdf_obj.set_font("helvetica", "B", 11)
            pdf_obj.set_text_color(*color)
            pdf_obj.cell(
                0, 8,
                f">>  {title}",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
            pdf_obj.set_text_color(0, 0, 0)

        def kv_row(pdf_obj, key, value, col_width=65):
            clean_key = str(key).encode("latin-1", "replace").decode("latin-1")
            clean_val = str(value).encode("latin-1", "replace").decode("latin-1")

            critical = "[CRITICAL]" in clean_val or "[WARNING]" in clean_val

            pdf_obj.set_font("helvetica", "B", 10)
            if critical:
                pdf_obj.set_text_color(200, 0, 0)
            pdf_obj.cell(col_width, 6, f"  {clean_key}:")
            pdf_obj.set_font("helvetica", "", 10)
            pdf_obj.multi_cell(0, 6, clean_val)
            pdf_obj.set_x(pdf_obj.l_margin)
            pdf_obj.set_text_color(0, 0, 0)

        def write_dict(pdf_obj, dictionary, indent="", col_width=65):
            for key, value in dictionary.items():
                if isinstance(value, dict):
                    pdf_obj.set_font("helvetica", "B", 10)
                    pdf_obj.cell(
                        0, 6,
                        f"{indent}  {key}:",
                        new_x=XPos.LMARGIN,
                        new_y=YPos.NEXT,
                    )
                    write_dict(pdf_obj, value, indent + "    ", col_width)
                elif isinstance(value, list):
                    pdf_obj.set_font("helvetica", "B", 10)
                    pdf_obj.cell(
                        0, 6,
                        f"{indent}  {key}:",
                        new_x=XPos.LMARGIN,
                        new_y=YPos.NEXT,
                    )
                    pdf_obj.set_font("helvetica", "", 10)
                    for item in value:
                        clean = str(item).encode("latin-1", "replace").decode("latin-1")
                        pdf_obj.multi_cell(0, 6, f"{indent}      * {clean}")
                        pdf_obj.set_x(pdf_obj.l_margin)
                else:
                    kv_row(pdf_obj, f"{indent}{key}", value, col_width)

        # ================================================================
        # Section 1 -- File Intake Summary
        # ================================================================
        section_header(pdf, "1", "File Intake Summary")
        write_dict(pdf, data.get("Analysis_Summary", {}))
        pdf.ln(4)

        # ================================================================
        # Section 2 -- Package & Archive Unpacking
        # ================================================================
        pkg_data = data.get("Package_Extraction")
        if pkg_data:
            section_header(pdf, "2", "Package & Archive Unpacking")
            pdf.set_font("helvetica", "", 10)
            flagged = [f for f in pkg_data if f.get("Is_Flagged")]
            kv_row(pdf, "Total Extracted Files", len(pkg_data))
            kv_row(pdf, "Flagged Payloads",      len(flagged))
            pdf.ln(2)

            pdf.set_font("helvetica", "B", 10)
            pdf.cell(
                0, 6,
                "  Extracted Artifacts:",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
            pdf.set_font("helvetica", "", 9)
            for item in pkg_data:
                path  = item.get("Relative_Path", "Unknown")
                ext   = item.get("Extension", "")
                size  = item.get("Size_Bytes", 0)
                sha   = item.get("SHA256", "N/A")
                flag  = " [FLAGGED]" if item.get("Is_Flagged") else ""
                line  = f"  {path} | {ext} | {size} bytes | SHA256: {sha}{flag}"
                if item.get("Is_Flagged"):
                    pdf.set_text_color(200, 0, 0)
                pdf.multi_cell(0, 5, line.encode("latin-1", "replace").decode("latin-1"))
                pdf.set_x(pdf.l_margin)
                pdf.set_text_color(0, 0, 0)
            pdf.ln(4)

        # ================================================================
        # Section 3 -- Static Analysis
        # ================================================================
        pdf.add_page()
        section_header(pdf, "3", "Deep Static Analysis")

        static_res = data.get("Static_Analysis_Results", {})
        if not static_res:
            pdf.set_font("helvetica", "I", 10)
            pdf.cell(
                0, 6,
                "  No static analysis performed (not a PE file).",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
        else:
            for target_exe, results in static_res.items():
                subsection_header(pdf, f"Target: {target_exe}")
                write_dict(pdf, results)
                pdf.ln(4)

        # ================================================================
        # Section 4 -- Dynamic Sandbox Analysis
        # ================================================================
        pdf.add_page()
        section_header(pdf, "4", "Dynamic Sandbox Analysis")

        dynamic_res = data.get("Dynamic_Analysis_Results", {})
        dynamic_sum = data.get("Dynamic_Summary", {})

        if not dynamic_res:
            pdf.set_font("helvetica", "I", 10)
            pdf.cell(
                0, 6,
                "  No dynamic analysis performed.",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
        else:
            for target_exe, telemetry in dynamic_res.items():
                if "Error" in telemetry:
                    subsection_header(pdf, f"Target: {target_exe}", color=(180, 0, 0))
                    kv_row(pdf, "Error", telemetry["Error"])
                    continue

                subsection_header(pdf, f"Target: {target_exe}")
                pdf.ln(2)

                # ---- 4a. Telemetry Summary Table -------------------
                pdf.set_font("helvetica", "B", 10)
                pdf.set_fill_color(40, 55, 90)
                pdf.set_text_color(220, 235, 255)
                pdf.cell(90, 7, "  Category", fill=True, border=0)
                pdf.cell(25, 7, "Events",     fill=True, border=0, align="C")
                pdf.cell(0,  7, "Notable / High-Risk", fill=True, border=0)
                pdf.ln()
                pdf.set_text_color(0, 0, 0)

                summary_for_target = dynamic_sum.get(target_exe, {})
                row_fill = False
                for cat in TELEMETRY_KEYS:
                    label   = CATEGORY_LABELS.get(cat, cat)
                    cat_sum = summary_for_target.get(cat, {})
                    count   = cat_sum.get("count", len(telemetry.get(cat, [])))
                    notable = cat_sum.get("notable", [])
                    notable_str = str(len(notable)) + " flagged" if notable else "-"

                    pdf.set_font("helvetica", "B" if count else "", 9)
                    if row_fill:
                        pdf.set_fill_color(28, 38, 60)
                    else:
                        pdf.set_fill_color(22, 30, 50)
                    pdf.set_text_color(230, 230, 230)
                    pdf.cell(90, 6, f"  {label}", fill=True)
                    color_count = (255, 100, 100) if count > 0 else (120, 120, 120)
                    pdf.set_text_color(*color_count)
                    pdf.cell(25, 6, str(count), fill=True, align="C")
                    if notable:
                        pdf.set_text_color(255, 200, 80)
                    else:
                        pdf.set_text_color(100, 100, 100)
                    pdf.cell(0, 6, notable_str, fill=True)
                    pdf.ln()
                    row_fill = not row_fill

                pdf.set_text_color(0, 0, 0)
                pdf.ln(4)

                # ---- 4b. Per-category event detail -----------------
                for cat in TELEMETRY_KEYS:
                    events = telemetry.get(cat, [])
                    if not events:
                        continue

                    label = CATEGORY_LABELS.get(cat, cat)
                    pdf.set_font("helvetica", "B", 10)
                    pdf.set_fill_color(200, 220, 255)
                    pdf.set_text_color(0, 20, 80)
                    pdf.cell(
                        0, 7,
                        f"  {label}  ({len(events)} events)",
                        fill=True,
                        new_x=XPos.LMARGIN,
                        new_y=YPos.NEXT,
                    )
                    pdf.set_text_color(0, 0, 0)
                    pdf.set_font("helvetica", "", 8)

                    for ev in events:
                        clean = str(ev).encode("latin-1", "replace").decode("latin-1")
                        upper = clean.upper()
                        if any(kw in upper for kw in ("INJECT", "RANSOM", "PROCESS_SPAWN", "REG_RUN_KEY", "FILE_DROP")):
                            pdf.set_text_color(200, 0, 0)
                        elif any(kw in upper for kw in ("NETWORK", "DNS", "HTTP", "TLS")):
                            pdf.set_text_color(0, 80, 180)
                        else:
                            pdf.set_text_color(50, 50, 50)

                        pdf.multi_cell(0, 5, f"    * {clean}")
                        pdf.set_x(pdf.l_margin)
                        pdf.set_text_color(0, 0, 0)

                    pdf.ln(3)

                pdf.ln(4)

        pdf.output(output_path)
