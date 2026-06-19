import os
import time
import subprocess
import threading
import yaml
from pubsub import pub
from core.network import ScapyInterceptor

# Mapping from FR tag to canonical category key
_TAG_TO_CATEGORY = {
    "[FR-DYN-01]": "Filesystem",
    "[FR-DYN-02]": "Registry",
    "[FR-DYN-03]": "Persistence",
    "[FR-DYN-04]": "Processes",
    "[FR-DYN-05]": "Memory",
    "[FR-DYN-06]": "Network",
    "[FR-DYN-07]": "Hardware",
}

TELEMETRY_KEYS = [
    "Filesystem",
    "Registry",
    "Persistence",
    "Processes",
    "Memory",
    "Network",
    "Hardware",
    "System",
]


class DynamicController:
    def __init__(self, config_path="config/config.yaml"):
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.vmx = self.config["sandbox"]["vmx_path"]
        self.vmrun = self.config["sandbox"]["vmrun_path"]
        self.auth = [
            "-gu", self.config["sandbox"]["guest_user"],
            "-gp", self.config["sandbox"]["guest_pass"],
        ]
        self.serial_pipe = self.config["sandbox"]["serial_pipe"]
        self.timeout = self.config["sandbox"].get("timeout_seconds", 60)

        self.is_analyzing = False

        # Structured telemetry — keyed by canonical category name
        self.telemetry = {k: [] for k in TELEMETRY_KEYS}

        try:
            self.network_interceptor = ScapyInterceptor(config_path)
        except Exception as e:
            pub.sendMessage("gui.log", msg=f"[-] Failed to initialize Network Interceptor: {e}")
            self.network_interceptor = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _execute_vmrun(self, cmd_list, description=""):
        if description:
            pub.sendMessage("gui.log", msg=f"[*] {description}...")

        base_cmd = [self.vmrun, "-T", "ws"] + self.auth
        full_cmd = base_cmd + cmd_list

        try:
            subprocess.run(full_cmd, capture_output=True, text=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            pub.sendMessage("gui.log", msg=f"[-] vmrun error during '{description}': {e.stderr.strip()}")
            return False
        except Exception as e:
            pub.sendMessage("gui.log", msg=f"[-] OS error running vmrun during '{description}': {str(e)}")
            return False

    def _category_for_line(self, line):
        for tag, cat in _TAG_TO_CATEGORY.items():
            if tag in line:
                return cat
        return "System"

    def _parse_and_route_telemetry(self, line):
        category = self._category_for_line(line)
        self.telemetry[category].append(line)

        # Emit live pubsub event for real-time GUI updates
        pub.sendMessage("dynamic.telemetry", category=category, event=line)
        pub.sendMessage("gui.log", msg=f"  [VM] {line}")

    def _telemetry_listener(self):
        pub.sendMessage("gui.log", msg="[*] Telemetry listener waiting for VM serial pipe...")

        pipe_connected = False
        while self.is_analyzing and not pipe_connected:
            try:
                with open(self.serial_pipe, "rb") as pipe:
                    pipe_connected = True
                    pub.sendMessage("gui.log", msg="[+] Serial telemetry pipe connected.")

                    while self.is_analyzing:
                        raw = pipe.readline()
                        if not raw:
                            continue
                        line = raw.decode("utf-8", errors="ignore").strip()
                        if line:
                            self._parse_and_route_telemetry(line)

            except FileNotFoundError:
                time.sleep(1)
            except Exception as e:
                pub.sendMessage("gui.log", msg=f"[-] Telemetry pipe error: {e}")
                break

    # ------------------------------------------------------------------
    # Summary helper (called after analysis completes)
    # ------------------------------------------------------------------

    def get_summary(self):
        """Returns a dict with per-category event counts and notable events."""
        summary = {}
        for cat, events in self.telemetry.items():
            notable = []
            for ev in events:
                # Flag events that look high-severity
                upper = ev.upper()
                if any(kw in upper for kw in (
                    "FATAL", "INJECT", "HOLLOW", "ROOTKIT", "RANSOM",
                    "NETWORK", "PROCESS_SPAWN", "REG_RUN_KEY", "FILE_DROP",
                    "PROCESS_ROOT", "MEM_SCAN",
                )):
                    notable.append(ev)
            summary[cat] = {
                "count": len(events),
                "notable": notable[:10],   # cap to 10 notable events
            }
        return summary

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run_sandbox_analysis(self, target_exe_path):
        """Orchestrates the entire dynamic analysis lifecycle."""
        # Reset telemetry for this run
        self.telemetry = {k: [] for k in TELEMETRY_KEYS}
        self.is_analyzing = True

        # 1. Revert to clean snapshot
        snapshot = self.config["sandbox"]["snapshot_name"]
        if not self._execute_vmrun(
            ["revertToSnapshot", self.vmx, snapshot],
            f"Reverting to snapshot '{snapshot}'",
        ):
            self.is_analyzing = False
            return {"error": "Failed to revert snapshot. Aborting dynamic analysis."}

        # 2. Power on sandbox VM
        if not self._execute_vmrun(["start", self.vmx, "gui"], "Starting Sandbox VM"):
            self.is_analyzing = False
            return {"error": "Failed to start VM."}

        # 3. Start telemetry listener thread
        listener = threading.Thread(target=self._telemetry_listener, daemon=True)
        listener.start()

        # 3.5. Start network interceptor
        if self.network_interceptor:
            pub.sendMessage("gui.log", msg="[*] Starting Network Interceptor...")
            self.network_interceptor.start()

        # Wait for VMware Tools to initialize
        pub.sendMessage("gui.log", msg="[*] Waiting 15 s for Windows & VMware Tools to initialize...")
        time.sleep(15)

        # 4. Transfer payloads to sandbox
        guest_exe   = r"C:\Users\Admin\Desktop\sample.exe"
        guest_agent = r"C:\Users\Admin\Desktop\unified_agent.py"
        host_agent  = os.path.abspath("sandbox_agents/unified_agents.py")

        self._execute_vmrun(
            ["copyFileFromHostToGuest", self.vmx, target_exe_path, guest_exe],
            "Uploading malware sample",
        )
        self._execute_vmrun(
            ["copyFileFromHostToGuest", self.vmx, host_agent, guest_agent],
            "Uploading Unified Agent",
        )

        # 5. Execute detonation
        pub.sendMessage("gui.log", msg=f"[*] Detonating sample — analysis window: {self.timeout}s")
        self._execute_vmrun(
            [
                "runProgramInGuest", self.vmx, "-noWait", "-interactive",
                "C:\\Python39\\python.exe", guest_agent,
            ],
            "Launching Unified Agent inside sandbox",
        )

        # 6. Wait for analysis window + buffer
        time.sleep(self.timeout + 5)

        # 7. Teardown
        pub.sendMessage("gui.log", msg="[*] Dynamic analysis window complete. Tearing down...")
        self.is_analyzing = False
        listener.join(timeout=2)

        # Collect network telemetry
        if self.network_interceptor:
            pub.sendMessage("gui.log", msg="[*] Stopping Network Interceptor...")
            captured_net = self.network_interceptor.stop()
            for item in captured_net:
                entry = f"[{item['time']}] {item['type']} | {item['src']} -> {item['dst']} | {item['detail']}"
                self.telemetry["Network"].append(entry)
                pub.sendMessage("dynamic.telemetry", category="Network", event=entry)

        self._execute_vmrun(["stop", self.vmx, "hard"], "Powering off Sandbox")

        pub.sendMessage("gui.log", msg="[+] Dynamic analysis complete. Telemetry collected:")
        for cat, events in self.telemetry.items():
            pub.sendMessage("gui.log", msg=f"    {cat}: {len(events)} event(s)")

        return self.telemetry


# ==========================================
# Standalone test stub
# ==========================================
if __name__ == "__main__":
    print("Testing DynamicController (requires valid config.yaml and VM setup)")
