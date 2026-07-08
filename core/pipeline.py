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
    cancelled_hashes = set()

    @classmethod
    def cancel_analysis(cls, sha256_hash):
        cls.cancelled_hashes.add(sha256_hash.lower().strip())

    @classmethod
    def clear_cancelled(cls, sha256_hash):
        cls.cancelled_hashes.discard(sha256_hash.lower().strip())

    def _is_cancelled(self, filepath, metadata=None):
        basename = os.path.basename(filepath)
        name_no_ext, _ = os.path.splitext(basename)
        hashes_to_check = [name_no_ext.lower().strip()]
        if metadata and "SHA256" in metadata:
            hashes_to_check.append(metadata["SHA256"].lower().strip())
        for h in hashes_to_check:
            if h in self.cancelled_hashes:
                return True
        return False

    def _handle_cancellation(self, filepath, metadata=None):
        pub.sendMessage("gui.log", msg="\n[!] Analysis has been terminated by user request.")
        pub.sendMessage("analysis.complete", status="Terminated")

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
                config = yaml.safe_load(f) or {}
        except Exception:
            config = {}
        
        # Override extract directory to use system temp directory instead of workspace
        import tempfile
        temp_workspace = os.path.join(tempfile.gettempdir(), "mars_workspace")
        if "system" not in config:
            config["system"] = {}
        config["system"]["extract_dir"] = os.path.join(temp_workspace, "extracted")
        return config

    # ------------------------------------------------------------------
    # PubSub entry point
    # ------------------------------------------------------------------

    def _on_analysis_start(self, filepath, run_static=True, run_dynamic=True, original_filename="", duration_seconds=120, headless=False, mode="detonate", analysis_type="full_detonation"):
        pub.sendMessage("gui.log", msg=f"\n[*] Pipeline triggered for: {filepath}")
        thread = threading.Thread(
            target=self._execute_pipeline,
            args=(filepath, run_static, run_dynamic, original_filename, duration_seconds, mode, analysis_type),
            daemon=True,
        )
        thread.start()

    # ------------------------------------------------------------------
    # Main pipeline
    # ------------------------------------------------------------------

    def _execute_pipeline(self, filepath, run_static=True, run_dynamic=True, original_filename="", duration_seconds=120, mode="detonate", analysis_type="full_detonation"):
        try:
            report_pkg_data     = []
            report_static_data  = {}
            report_dynamic_data = {}
            dynamic_summary     = {}

            # ======================================================
            # Phase 1: Intake & Validation
            # ======================================================
            if self._is_cancelled(filepath):
                self._handle_cancellation(filepath)
                return

            metadata = self.intake_module.process_file(filepath, original_filename=original_filename)
            if not metadata:
                pub.sendMessage("gui.log", msg="[!] Pipeline aborted during Intake phase.")
                pub.sendMessage("analysis.complete", status="Failed")
                return

            # Patch the filename with the user's actual uploaded name so the
            # report shows the real filename instead of the hash-based temp path.
            if original_filename:
                metadata["Original File Name"] = original_filename

            analysis_id = metadata.get("Analysis ID")
            metadata["Analysis Type"] = analysis_type
            ext = metadata.get("Extension", "").lower()
            # Use the real filename as the display key; fall back to basename of filepath
            display_name = original_filename or os.path.basename(filepath)
            extracted_executables = []

            # ======================================================
            # Phase 2: Package Analysis (Unpacking)
            # ======================================================
            if self._is_cancelled(filepath, metadata):
                self._handle_cancellation(filepath, metadata)
                return

            if ext in [".zip", ".msi"]:
                extract_dir, inventory = self.package_module.process_file(filepath, analysis_id)
                report_pkg_data = inventory
                pub.sendMessage("gui.update_table", module="Package Unpacker: Inventory", data={"inventory": inventory})

                for item in inventory:
                    if item["Extension"] in [".exe", ".dll", ".sys"]:
                        full_path = os.path.join(extract_dir, item["Relative_Path"])
                        extracted_executables.append(full_path)

            # ======================================================
            # Phase 3: Static Analysis
            # ======================================================
            if self._is_cancelled(filepath, metadata):
                self._handle_cancellation(filepath, metadata)
                return

            if run_static:
                if ext in [".exe", ".dll", ".sys"]:
                    static_res = self.static_module.process_file(filepath)
                    if static_res:
                        report_static_data[display_name] = static_res

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
            if self._is_cancelled(filepath, metadata):
                self._handle_cancellation(filepath, metadata)
                return

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
                        if self._is_cancelled(filepath, metadata):
                            self._handle_cancellation(filepath, metadata)
                            return
                        target_name = os.path.basename(target_path)
                        pub.sendMessage(
                            "gui.log",
                            msg=f"[*] Detonating '{target_name}' in VM Sandbox...",
                        )

                        try:
                            dyn_res = self.dynamic_module.run_sandbox_analysis(target_path, duration_seconds=duration_seconds, mode=mode, analysis_type=analysis_type)
                        except Exception as e:
                            pub.sendMessage(
                                "gui.log",
                                msg=f"[!] Dynamic Analysis failed with exception for '{target_name}': {str(e)}",
                            )
                            dyn_res = {"error": f"Exception during execution: {str(e)}"}

                        if self._is_cancelled(filepath, metadata):
                            self._handle_cancellation(filepath, metadata)
                            return
                        elif dyn_res and "error" in dyn_res:
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
            if self._is_cancelled(filepath, metadata):
                self._handle_cancellation(filepath, metadata)
                return

            pub.sendMessage("gui.log", msg="\n[*] --- Starting Threat Scoring Engine ---")
            scoring_results = self.scorer.score_all(
                report_static_data,
                report_dynamic_data,
                pkg_data=report_pkg_data,
            )

            # ======================================================
            # Phase 5: Reporting
            # ======================================================
            if self._is_cancelled(filepath, metadata):
                self._handle_cancellation(filepath, metadata)
                return

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
        finally:
            basename = os.path.basename(filepath)
            name_no_ext, _ = os.path.splitext(basename)
            self.clear_cancelled(name_no_ext)
            if 'metadata' in locals() and metadata and "SHA256" in metadata:
                self.clear_cancelled(metadata["SHA256"])
