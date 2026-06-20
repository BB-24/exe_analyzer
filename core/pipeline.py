import os
import threading
import yaml
from pubsub import pub

from core.intake import IntakeModule
from core.package import PackageModule
from core.static import StaticModule
from core.report import ReportGenerator
from core.dynamic import DynamicController, TELEMETRY_KEYS
from core.scoring import MARSScorer


class AnalysisPipeline:
    def __init__(self, config_path="config/config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()

        self.intake_module  = IntakeModule(self.config)
        self.package_module = PackageModule(self.config)
        self.static_module  = StaticModule(self.config)
        self.reporter       = ReportGenerator(self.config)
        self.scorer         = MARSScorer()

        try:
            self.dynamic_module = DynamicController(self.config_path)
        except Exception as e:
            pub.sendMessage(
                "gui.log",
                msg=f"[!] Dynamic analysis module failed to initialize "
                    f"(likely VM configuration or vmrun path missing): {str(e)}",
            )
            self.dynamic_module = None

        pub.subscribe(self._on_analysis_start, "analysis.start")
        pub.sendMessage("gui.log", msg="[*] Analysis Pipeline Orchestrator Initialized and Ready.")

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def _load_config(self):
        try:
            with open(self.config_path, "r") as f:
                return yaml.safe_load(f)
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # PubSub entry point
    # ------------------------------------------------------------------

    def _on_analysis_start(self, filepath, run_static=True, run_dynamic=True):
        pub.sendMessage("gui.log", msg=f"\n[*] Pipeline triggered for: {filepath}")
        thread = threading.Thread(
            target=self._execute_pipeline,
            args=(filepath, run_static, run_dynamic),
            daemon=True,
        )
        thread.start()

    # ------------------------------------------------------------------
    # Main pipeline
    # ------------------------------------------------------------------

    def _execute_pipeline(self, filepath, run_static=True, run_dynamic=True):
        try:
            report_pkg_data     = []
            report_static_data  = {}
            report_dynamic_data = {}
            dynamic_summary     = {}

            # ======================================================
            # Phase 1: Intake & Validation
            # ======================================================
            metadata = self.intake_module.process_file(filepath)
            if not metadata:
                pub.sendMessage("gui.log", msg="[!] Pipeline aborted during Intake phase.")
                pub.sendMessage("analysis.complete", status="Failed")
                return

            analysis_id = metadata.get("Analysis ID")
            ext = metadata.get("Extension", "").lower()
            extracted_executables = []

            # ======================================================
            # Phase 2: Package Analysis (Unpacking)
            # ======================================================
            if ext in [".zip", ".msi"]:
                extract_dir, inventory = self.package_module.process_file(filepath, analysis_id)
                report_pkg_data = inventory

                for item in inventory:
                    if item["Extension"] in [".exe", ".dll", ".sys"]:
                        full_path = os.path.join(extract_dir, item["Relative_Path"])
                        extracted_executables.append(full_path)

            # ======================================================
            # Phase 3: Static Analysis
            # ======================================================
            if run_static:
                if ext in [".exe", ".dll", ".sys"]:
                    static_res = self.static_module.process_file(filepath)
                    if static_res:
                        report_static_data[os.path.basename(filepath)] = static_res

                if extracted_executables:
                    pub.sendMessage(
                        "gui.log",
                        msg=f"\n[*] --- Pushing {len(extracted_executables)} extracted payload(s) to Static Analysis ---",
                    )
                    for exec_path in extracted_executables:
                        target_name = os.path.basename(exec_path)
                        pub.sendMessage("gui.update_table", module="Nested Execution", data={"Target": target_name})
                        static_res = self.static_module.process_file(exec_path)
                        if static_res:
                            report_static_data[target_name] = static_res
            else:
                pub.sendMessage("gui.log", msg="\n[*] Static Analysis skipped by user option.")

            # ======================================================
            # Phase 3.5: Dynamic Analysis (VM Detonation)
            # ======================================================
            if run_dynamic:
                pub.sendMessage("gui.log", msg="\n[+] --- Starting Dynamic Analysis Module ---")

                if not self.dynamic_module:
                    pub.sendMessage(
                        "gui.log",
                        msg="[!] Dynamic Analysis skipped: dynamic controller is not initialized.",
                    )
                else:
                    targets_to_detonate = []
                    if ext in [".exe", ".dll", ".sys"]:
                        targets_to_detonate.append(filepath)
                    targets_to_detonate.extend(extracted_executables)

                    for target_path in targets_to_detonate:
                        target_name = os.path.basename(target_path)
                        pub.sendMessage(
                            "gui.log",
                            msg=f"[*] Detonating '{target_name}' in VM Sandbox...",
                        )

                        dyn_res = self.dynamic_module.run_sandbox_analysis(target_path)

                        if dyn_res and "error" in dyn_res:
                            pub.sendMessage(
                                "gui.log",
                                msg=f"[!] Dynamic Analysis error for '{target_name}': {dyn_res['error']}",
                            )
                            report_dynamic_data[target_name] = {"Error": dyn_res["error"]}
                        elif dyn_res:
                            report_dynamic_data[target_name] = dyn_res

                            # Build summary for this target and publish to GUI
                            summary = self.dynamic_module.get_summary()
                            dynamic_summary[target_name] = summary

                            # Push per-category batch update (for treeview refresh)
                            for category in TELEMETRY_KEYS:
                                events = dyn_res.get(category, [])
                                pub.sendMessage(
                                    "gui.update_table",
                                    module=f"Dynamic: {category}",
                                    data={"Events": "\n".join(events) if events else ""},
                                )

                            # Push aggregated summary so Overview card can refresh
                            pub.sendMessage(
                                "gui.update_table",
                                module="Dynamic: Summary",
                                data=summary,
                            )
            else:
                pub.sendMessage("gui.log", msg="\n[*] Dynamic Analysis skipped by user option.")

            # ======================================================
            # Phase 4: Threat Scoring
            # ======================================================
            pub.sendMessage("gui.log", msg="\n[*] --- Starting Threat Scoring Engine ---")
            scoring_results = self.scorer.score_all(
                report_static_data,
                report_dynamic_data,
                pkg_data=report_pkg_data,
            )

            # ======================================================
            # Phase 5: Reporting
            # ======================================================
            self.reporter.generate_reports(
                metadata,
                report_pkg_data,
                report_static_data,
                report_dynamic_data,
                dynamic_summary,
                scoring_results=scoring_results,
            )

            pub.sendMessage("gui.log", msg="\n[*] === Pipeline Execution Completed Successfully ===")
            pub.sendMessage("analysis.complete", status="Success")

        except Exception as e:
            pub.sendMessage("gui.log", msg=f"\n[!] Critical Pipeline Fault: {str(e)}")
            pub.sendMessage("analysis.complete", status="Error")
