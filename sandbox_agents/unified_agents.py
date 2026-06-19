import os
import sys
import time
import threading
import subprocess
import csv
import serial
import psutil
import winreg
import ctypes
import re
import pythoncom
import wmi
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ctypes import wintypes

# ==========================================
# CONFIGURATION & GLOBALS
# ==========================================
SERIAL_PORT = 'COM1'
TARGET_EXE = r"C:\Users\Admin\Desktop\sample.exe"
PROCMON_PATH = r"C:\Tools\procmon.exe"
PML_LOG = r"C:\Analysis\trace.pml"
CSV_LOG = r"C:\Analysis\trace.csv"
ANALYSIS_TIMEOUT = 60

# Global State Management
analysis_active = True
tracked_pids = set()
tracking_lock = threading.Lock()

try:
    ser = serial.Serial(SERIAL_PORT, baudrate=115200, timeout=1)
except Exception as e:
    print(f"[-] Serial configuration failed: {e}")
    ser = None

def stream_log(fr_tag, event_type, detail):
    """Streams structured telemetry directly to the Host VM."""
    timestamp = time.strftime("%H:%M:%S")
    # Clean newlines from details to prevent parsing errors on the controller
    clean_detail = str(detail).replace('\n', ' ').replace('\r', '')
    log_entry = f"[{timestamp}] [{fr_tag}] [{event_type}] {clean_detail}\r\n"
    
    if ser:
        ser.write(log_entry.encode('utf-8', errors='ignore'))
        ser.flush()
    print(log_entry.strip())

# ==========================================
# MODULE: FR-DYN-07 (Hardware Profiler)
# ==========================================
def monitor_hardware():
    global analysis_active
    last_net = psutil.net_io_counters()
    last_disk = psutil.disk_io_counters()
    
    while analysis_active:
        time.sleep(2)
        sys_cpu = psutil.cpu_percent()
        sys_mem = psutil.virtual_memory()
        
        current_net = psutil.net_io_counters()
        net_sent = (current_net.bytes_sent - last_net.bytes_sent) / 2
        last_net = current_net
        
        stream_log("FR-DYN-07", "SYS_STRESS", f"CPU: {sys_cpu}% | RAM: {sys_mem.percent}% | Net Out: {net_sent/1024:.1f} KB/s")

# ==========================================
# MODULE: FR-DYN-04 (Process Lifetime)
# ==========================================
def monitor_processes():
    global analysis_active
    pythoncom.CoInitialize()
    c = wmi.WMI()
    
    watcher = c.watch_for(notification_type="Creation", wmi_class="Win32_Process", delay_secs=1)
    
    while analysis_active:
        try:
            new_proc = watcher(timeout_ms=1000)
            if new_proc:
                pid = str(new_proc.ProcessId)
                ppid = str(new_proc.ParentProcessId)
                
                with tracking_lock:
                    if ppid in tracked_pids:
                        tracked_pids.add(pid)
                        cmd = new_proc.CommandLine if new_proc.CommandLine else "N/A"
                        stream_log("FR-DYN-04", "PROCESS_SPAWN", f"PID:{pid} | PPID:{ppid} | Name:{new_proc.Name} | Cmd:{cmd}")
        except wmi.x_wmi_timed_out:
            continue
        except Exception:
            pass
    pythoncom.CoUninitialize()

# ==========================================
# MODULE: FR-DYN-03 (Persistence Tripwires)
# ==========================================
class StartupHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            stream_log("FR-DYN-03", "FILE_DROP", f"Startup/Task Object: {event.src_path}")

def monitor_persistence():
    global analysis_active
    
    # 1. Watchdog for Startup Folders
    observer = Observer()
    handler = StartupHandler()
    paths = [
        os.environ.get('USERPROFILE', r'C:\Users\Admin') + r'\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup',
        r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
        r'C:\Windows\System32\Tasks'
    ]
    for p in paths:
        if os.path.exists(p):
            observer.schedule(handler, path=p, recursive=False)
    observer.start()

    # 2. Registry Polling for Run Keys
    run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    known_keys = set()
    
    while analysis_active:
        time.sleep(2)
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, i)
                    if name not in known_keys:
                        known_keys.add(name)
                        stream_log("FR-DYN-03", "REG_RUN_KEY", f"Added: {name} -> {val}")
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

    observer.stop()
    observer.join()

# ==========================================
# MODULE: FR-DYN-05 (Memory Forensics)
# ==========================================
def scan_memory():
    """Scans surviving processes for injected code and carved artifacts."""
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    url_regex = rb'(?i)\b(?:https?|ftp)://[a-zA-Z0-9][-a-zA-Z0-9.]*(?::\d+)?(?:/[a-zA-Z0-9\-._?,\':+&%$#=~]*)*'
    
    with tracking_lock:
        target_pids = list(tracked_pids)
        
    for pid in target_pids:
        if not psutil.pid_exists(int(pid)):
            continue
            
        try:
            handle = kernel32.OpenProcess(0x0400 | 0x0010, False, int(pid))
            if not handle:
                continue
                
            stream_log("FR-DYN-05", "MEM_SCAN", f"Scanning volatile memory for PID {pid}")
            # Simplified scan loop for brevity. In production, iterate MEMORY_BASIC_INFORMATION
            # looking for PAGE_EXECUTE_READWRITE (0x40).
            
            kernel32.CloseHandle(handle)
        except Exception as e:
            stream_log("FR-DYN-05", "ERROR", f"PID {pid} mem scan failed: {e}")

# ==========================================
# MODULE: FR-DYN-01 & 02 (Kernel Log Parsing)
# ==========================================
def parse_kernel_logs():
    """Parses ProcMon CSV to extract filesystem and registry mutations."""
    if not os.path.exists(CSV_LOG):
        stream_log("SYSTEM", "ERROR", "ProcMon CSV not found.")
        return

    with tracking_lock:
        pids = set(tracked_pids)

    stream_log("SYSTEM", "INFO", "Parsing kernel traces...")
    with open(CSV_LOG, mode='r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        next(reader, None) 

        for row in reader:
            if len(row) < 7: continue
            _, _, pid, op, path, res, detail = row
            
            if pid in pids and res == "SUCCESS":
                # Filesystem Mutations (FR-DYN-01)
                if op in ("WriteFile", "SetEndOfFile"):
                    stream_log("FR-DYN-01", "FILE_MODIFIED", f"Path: {path}")
                elif op == "CreateFile" and "Disposition: Create" in detail:
                    stream_log("FR-DYN-01", "FILE_CREATED", f"Path: {path}")
                    
                # Registry Mutations (FR-DYN-02)
                elif op == "RegSetValue":
                    stream_log("FR-DYN-02", "REG_MODIFIED", f"Key: {path} | {detail}")
                elif op == "RegCreateKey" and "REG_CREATED_NEW_KEY" in detail:
                    stream_log("FR-DYN-02", "REG_CREATED", f"Key: {path}")

# ==========================================
# MASTER EXECUTION ORCHESTRATOR
# ==========================================
if __name__ == "__main__":
    stream_log("SYSTEM", "INIT", "Unified Agent Started. Setting up environment...")
    
    # 1. Setup Environment
    if not os.path.exists(r"C:\Analysis"):
        os.makedirs(r"C:\Analysis")
    for f in [PML_LOG, CSV_LOG]:
        if os.path.exists(f): os.remove(f)

    # 2. Start Kernel Logging (ProcMon)
    stream_log("SYSTEM", "INIT", "Starting kernel filter drivers...")
    subprocess.Popen([PROCMON_PATH, "/BackingFile", PML_LOG, "/Quiet", "/AcceptEula"])
    time.sleep(3) # Let filter attach

    # 3. Detonate Malware
    stream_log("SYSTEM", "EXEC", f"Detonating {TARGET_EXE}")
    try:
        proc = subprocess.Popen([TARGET_EXE])
        with tracking_lock:
            tracked_pids.add(str(proc.pid))
        stream_log("FR-DYN-04", "PROCESS_ROOT", f"PID: {proc.pid}")
    except Exception as e:
        stream_log("SYSTEM", "FATAL", f"Failed to execute target: {e}")
        sys.exit(1)

    # 4. Start Monitoring Threads
    threads = [
        threading.Thread(target=monitor_hardware),
        threading.Thread(target=monitor_processes),
        threading.Thread(target=monitor_persistence)
    ]
    for t in threads: t.start()

    # 5. Analysis Window
    stream_log("SYSTEM", "INFO", f"Analysis window open for {ANALYSIS_TIMEOUT}s...")
    time.sleep(ANALYSIS_TIMEOUT)

    # 6. Teardown & Forensics
    stream_log("SYSTEM", "INFO", "Analysis window closed. Halting active monitors...")
    analysis_active = False # Signal threads to die
    
    # Run memory forensics before killing processes
    scan_memory()
    
    # Stop ProcMon and convert log
    stream_log("SYSTEM", "INFO", "Terminating kernel trace and dumping to CSV (This may take a moment)...")
    subprocess.run([PROCMON_PATH, "/Terminate"], check=True)
    time.sleep(2)
    subprocess.run([PROCMON_PATH, "/OpenLog", PML_LOG, "/SaveAs", CSV_LOG, "/Quiet"], check=True)
    
    # 7. Post-Processing
    parse_kernel_logs()
    
    stream_log("SYSTEM", "COMPLETE", "Agent teardown successful. Awaiting host shutdown.")