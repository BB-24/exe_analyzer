import os
import sys
import argparse
import threading
import time

# Add parent directory to sys.path to allow running directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


from pubsub import pub


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="mars",
        description="MARS — Malware Analysis & Reverse-engineering System (CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python main.py sample.exe
  python main.py sample.exe --no-dynamic
  python main.py archive.zip --no-static --output /tmp/reports
  python main.py sample.dll --quiet
        """,
    )
    parser.add_argument(
        "file",
        metavar="FILE",
        help="Path to the file to analyse (.exe, .dll, .sys, .zip, .msi)",
    )
    parser.add_argument(
        "--no-static",
        action="store_true",
        default=False,
        help="Skip the static analysis phase",
    )
    parser.add_argument(
        "--no-dynamic",
        action="store_true",
        default=False,
        help="Skip the dynamic (VM sandbox) analysis phase",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="DIR",
        default=None,
        help="Override the report output directory (default: workspace/reports)",
    )
    parser.add_argument(
        "--config", "-c",
        metavar="FILE",
        default="config/config.yaml",
        help="Path to config.yaml (default: config/config.yaml)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        default=False,
        help="Suppress per-event log lines; only show phase headers and final result",
    )
    return parser


class CLIRunner:
    """
    Subscribes to all PyPubSub topics the pipeline emits and prints them to
    stdout.  Runs the pipeline synchronously (blocks until complete).
    """

    HEADER = "=" * 60
    PHASE  = "-" * 60

    # ANSI colour codes (graceful fallback when terminal doesn't support them)
    _ANSI = {
        "MALICIOUS":  "\033[1;31m",   # bold red
        "HIGH RISK":  "\033[1;33m",   # bold yellow
        "SUSPICIOUS": "\033[1;33m",   # bold yellow
        "CLEAN":      "\033[1;32m",   # bold green
        "RESET":      "\033[0m",
        "BOLD":       "\033[1m",
        "DIM":        "\033[2m",
        "CYAN":       "\033[36m",
    }

    def __init__(self, quiet: bool = False):
        self.quiet       = quiet
        self._done       = threading.Event()
        self._status     = "Unknown"
        self._scores: list = []

        pub.subscribe(self._on_log,          "gui.log")
        pub.subscribe(self._on_table_update, "gui.update_table")
        pub.subscribe(self._on_complete,     "analysis.complete")
        pub.subscribe(self._on_score,        "scoring.result")

    # ------------------------------------------------------------------
    # PubSub handlers
    # ------------------------------------------------------------------

    def _on_log(self, msg: str):
        if self.quiet:
            if any(kw in msg for kw in ("---", "===", "[CRITICAL", "[!]", "[SCORE]")):
                print(msg)
        else:
            print(msg)

    def _on_table_update(self, module: str, data):
        if self.quiet:
            return
        if isinstance(data, dict):
            for k, v in data.items():
                if v:
                    print(f"    [{module}] {k}: {v}")
        else:
            print(f"    [{module}] {data}")

    def _on_score(self, result):
        """Accumulate scoring results for display in the final summary banner."""
        self._scores.append(result)

    def _on_complete(self, status: str):
        self._status = status
        self._done.set()

    # ------------------------------------------------------------------
    # Public entry-point
    # ------------------------------------------------------------------

    def run(self, filepath, run_static, run_dynamic, config_path, output_dir):
        import yaml
        from core.pipeline import AnalysisPipeline

        print(self.HEADER)
        print(" MARS — Malware Analysis & Reverse-engineering System (CLI)")
        print(self.HEADER)
        print(f"[*] Target   : {os.path.abspath(filepath)}")
        print(f"[*] Static   : {'enabled' if run_static  else 'SKIPPED'}")
        print(f"[*] Dynamic  : {'enabled' if run_dynamic else 'SKIPPED'}")
        print(f"[*] Config   : {config_path}")
        if output_dir:
            print(f"[*] Output   : {output_dir}")
        print(self.PHASE)

        config = {}
        try:
            with open(config_path, "r") as fh:
                import yaml as _yaml
                config = _yaml.safe_load(fh) or {}
        except FileNotFoundError:
            print(f"[WARNING] Config file not found: {config_path}. Using built-in defaults.")
        except Exception as exc:
            print(f"[WARNING] Could not parse config: {exc}. Using built-in defaults.")

        if output_dir:
            config.setdefault("system", {})
            config["system"]["reports_dir"] = output_dir
            os.makedirs(output_dir, exist_ok=True)

        # Override extract directory to use system temp directory instead of workspace
        import tempfile
        temp_workspace = os.path.join(tempfile.gettempdir(), "mars_workspace")
        config.setdefault("system", {})
        config["system"]["extract_dir"] = os.path.join(temp_workspace, "extracted")

        pipeline = AnalysisPipeline.__new__(AnalysisPipeline)
        pipeline.config_path = config_path
        pipeline.config      = config

        from core.intake   import IntakeModule
        from core.package  import PackageModule
        from core.static   import StaticModule
        from core.report   import ReportGenerator
        from core.dynamic  import DynamicController
        from core.scoring  import MARSScorer

        pipeline.intake_module  = IntakeModule(config)
        pipeline.package_module = PackageModule(config)
        pipeline.static_module  = StaticModule(config)
        pipeline.reporter       = ReportGenerator(config)
        pipeline.scorer         = MARSScorer()

        try:
            pipeline.dynamic_module = DynamicController(config_path)
        except Exception as exc:
            print(f"[!] Dynamic module unavailable ({exc}). Dynamic analysis will be skipped.")
            pipeline.dynamic_module = None

        pub.subscribe(pipeline._on_analysis_start, "analysis.start")

        pub.sendMessage(
            "analysis.start",
            filepath=filepath,
            run_static=run_static,
            run_dynamic=run_dynamic,
        )

        self._done.wait(timeout=600)

        print(self.PHASE)
        self._print_score_banner()
        if self._status == "Success":
            print("[+] Analysis complete — reports saved to:",
                  config.get("system", {}).get("reports_dir", "./workspace/reports"))
        else:
            print(f"[!] Analysis finished with status: {self._status}")
        print(self.HEADER)

        return 0 if self._status == "Success" else 1

    # ------------------------------------------------------------------
    # Score banner
    # ------------------------------------------------------------------

    def _print_score_banner(self):
        """Print a formatted threat-score summary table to stdout."""
        if not self._scores:
            return

        A = self._ANSI
        W = 60

        try:
            "─".encode(sys.stdout.encoding or 'ascii')
            char_line = "─"
            char_block = "█"
            char_shade = "░"
            char_bullet = "•"
        except Exception:
            char_line = "-"
            char_block = "#"
            char_shade = "-"
            char_bullet = "*"

        print(f"\n{A['BOLD']}{char_line * W}{A['RESET']}")
        print(f"{A['BOLD']}  THREAT SCORING RESULTS{A['RESET']}")
        print(f"{A['BOLD']}{char_line * W}{A['RESET']}")

        for sr in self._scores:
            colour = A.get(sr.verdict, A["BOLD"])
            reset  = A["RESET"]
            bold   = A["BOLD"]
            dim    = A["DIM"]
            cyan   = A["CYAN"]

            # Gauge bar (20 chars wide)
            filled   = int(round(sr.total_score * 2))   # 0–20 chars
            gauge    = (char_block * filled) + (char_shade * (20 - filled))
            conf_tag = f"[{sr.confidence} confidence]"

            print(f"\n  {bold}Target :{reset} {sr.target}")
            print(f"  {bold}Verdict:{reset} {colour}{sr.verdict}{reset}  "
                  f"{cyan}{sr.total_score:.1f}/10.0{reset}  {dim}{conf_tag}{reset}")
            print(f"  Score  : {colour}{gauge}{reset}")

            if sr.categories:
                print(f"  {dim}{'Category':<24} {'Score':>8}  Bar{reset}")
                for cat in sr.categories:
                    bar_filled = int(round(cat.normalised))
                    bar = char_block * bar_filled + char_shade * (10 - bar_filled)
                    print(f"    {cat.name:<24} {cat.score:>4.1f}/{cat.max_score:<4.0f}  {bar}")

            top = sr.top_findings(3)
            if top:
                print(f"  {dim}Top findings:{reset}")
                for f in top:
                    print(f"    {dim}{char_bullet}{reset} {f}")

        print(f"\n{A['BOLD']}{char_line * W}{A['RESET']}\n")



def run_cli(args=None):
    parser = _build_parser()
    opts   = parser.parse_args(args)

    if not os.path.isfile(opts.file):
        print(f"[ERROR] File not found: {opts.file}", file=sys.stderr)
        sys.exit(2)

    runner = CLIRunner(quiet=opts.quiet)
    exit_code = runner.run(
        filepath    = opts.file,
        run_static  = not opts.no_static,
        run_dynamic = not opts.no_dynamic,
        config_path = opts.config,
        output_dir  = opts.output,
    )
    sys.exit(exit_code)

if __name__ == "__main__":
    run_cli()

