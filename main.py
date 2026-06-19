import os
import sys
from tkinter import messagebox

# ==========================================
# 1. Dependency Pre-flight Checks
# ==========================================
try:
    import yaml
    from pubsub import pub
    import pefile
    import yara
    import customtkinter
except ImportError as e:
    print(f"[CRITICAL ERROR] Missing Python dependency: {e}")
    print("Please install the required libraries by running:")
    print("  pip install -r requirements.txt")
    sys.exit(1)

# Import internal packages
from core.pipeline import AnalysisPipeline
from gui.app import MalwareAnalysisGUI

# ==========================================
# 2. Workspace Initialization
# ==========================================
def initialize_workspace():
    """
    Ensures that the required directory structure exists before the app launches.
    Prevents runtime crashes when the pipeline attempts to write logs or extract files.
    """
    required_dirs = [
        "config",
        "rules",
        "workspace",
        "workspace/extracted",
        "workspace/reports"
    ]
    
    print("[*] Verifying workspace directories...")
    for directory in required_dirs:
        if not os.path.exists(directory):
            print(f"  [+] Creating missing directory: {directory}")
            os.makedirs(directory, exist_ok=True)

def verify_critical_files():
    """Checks for the config and rule files to warn the user if they are missing."""
    if not os.path.exists("config/config.yaml"):
        print("[WARNING] config/config.yaml is missing! The pipeline will use empty defaults and likely fail.")
    if not os.path.exists("rules/rules.yar"):
        print("[WARNING] rules/rules.yar is missing! YARA scanning will be skipped.")

# ==========================================
# 3. Main Application Loop
# ==========================================
def main():
    print("======================================================")
    print(" MARS - Malware Analysis & Reverse-engineering System")
    print("======================================================")
    
    initialize_workspace()
    verify_critical_files()

    try:
        print("[*] Initializing Core Backend Pipeline...")
        # Instantiate the decoupled backend (connects PyPubSub internally)
        pipeline = AnalysisPipeline(config_path="config/config.yaml")
        
        print("[*] Initializing Graphical User Interface...")
        app = MalwareAnalysisGUI()
        
        print("[*] System Online. Waiting for user input via GUI.")
        app.mainloop()
        
    except Exception as e:
        print(f"\n[CRITICAL ERROR] Application failed to launch: {str(e)}")
        messagebox.showerror("Initialization Error", f"The MARS application encountered a fatal error during startup:\n\n{str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()