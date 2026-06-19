import os
import sys
import argparse
import threading
import time

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

    def __init__(self, quiet: bool = False):
        self.quiet  = quiet
        self._done  = threading.Event()
        self._status = "Unknown"

        pub.subscribe(self._on_log,          "gui.log")
        pub.subscribe(self._on_table_update, "gui.update_table")
        pub.subscribe(self._on_complete,     "analysis.complete")

    # ------------------------------------------------------------------
    # PubSub handlers
    # ------------------------------------------------------------------

    def _on_log(self, msg: str):
        if self.quiet:
            if any(kw in msg for kw in ("---", "===", "[CRITICAL", "[!]")):
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

        pipeline = AnalysisPipeline.__new__(AnalysisPipeline)
        pipeline.config_path = config_path
        pipeline.config      = config

        from core.intake  import IntakeModule
        from core.package import PackageModule
        from core.static  import StaticModule
        from core.report  import ReportGenerator
        from core.dynamic import DynamicController

        pipeline.intake_module  = IntakeModule(config)
        pipeline.package_module = PackageModule(config)
        pipeline.static_module  = StaticModule(config)
        pipeline.reporter       = ReportGenerator(config)

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
        if self._status == "Success":
            print("[+] Analysis complete — reports saved to:",
                  config.get("system", {}).get("reports_dir", "./workspace/reports"))
        else:
            print(f"[!] Analysis finished with status: {self._status}")
        print(self.HEADER)

        return 0 if self._status == "Success" else 1


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
