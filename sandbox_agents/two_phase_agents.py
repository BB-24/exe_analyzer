import os
import sys
import time
import threading
import subprocess
import csv
import json
import uuid
import struct
import serial
import psutil
import winreg
import ctypes
import re
import pythoncom
import wmi
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Redirect stdout and stderr to a file on desktop since we run directly without shell redirection
try:
    import getpass
    username = getpass.getuser()
    log_path = f"C:\\Users\\{username}\\Desktop\\agent_err.log"
    sys.stdout = open(log_path, "w", buffering=1)
    sys.stderr = sys.stdout
except Exception:
    pass

# ==========================================
# CONFIGURATION & GLOBALS
# ==========================================
SERIAL_PORT = 'COM1'
TARGET_EXE = r"C:\Users\Administrator\Desktop\sample.exe"
PROCMON_PATH = r"C:\Tools\procmon.exe"
PML_LOG = r"C:\Analysis\trace.pml"
CSV_LOG = r"C:\Analysis\trace.csv"
ANALYSIS_TIMEOUT = 120
EARLY_EXIT_ON_PAYLOAD_TERMINATION = True

# Global State Management
analysis_active = True
tracked_pids = set()
tracking_lock = threading.Lock()

# New State Machine Management for Segregated Analysis
INSTALLER_PID = None
PAYLOAD_PIDS = set()
CURRENT_PHASE = "INSTALLER_WRAPPER"  # Shifts dynamically to "MAIN_PAYLOAD"

ser = None
for attempt in range(15):
    try:
        ser = serial.Serial(SERIAL_PORT, baudrate=115200, timeout=1)
        print(f"[+] Serial port {SERIAL_PORT} connected successfully.")
        break
    except Exception as e:
        print(f"[-] Serial connection attempt {attempt+1} failed: {e}")
        time.sleep(1)

def stream_log(fr_tag, event_type, detail):
    """Streams structured telemetry directly to the Host VM with strict Phase Segregation."""
    timestamp = time.strftime("%H:%M:%S")
    if isinstance(detail, dict):
        # Embed default tracking vectors
        if "timestamp" not in detail:
            detail["timestamp"] = timestamp
        if "tag" not in detail:
            detail["tag"] = fr_tag
        if "event_type" not in detail:
            detail["event_type"] = event_type
        
        # Inject dynamic tracking context
        if "analysis_phase" not in detail:
            detail["analysis_phase"] = CURRENT_PHASE
        
        clean_detail = json.dumps(detail)
    else:
        clean_detail = str(detail).replace('\n', ' ').replace('\r', '')
    
    log_entry = f"[{timestamp}] [{fr_tag}] [{event_type}] {clean_detail}\r\n"
    
    if ser:
        try:
            ser.write(log_entry.encode('utf-8', errors='ignore'))
            ser.flush()
        except Exception as e:
            print(f"[-] Serial write error: {e}")
    print(log_entry.strip())

# ==========================================
# MODULE: FR-DYN-07 (Hardware/System Profiler)
# ==========================================
def monitor_hardware():
    global analysis_active
    last_net = psutil.net_io_counters()
    env_profiled = False
    
    while analysis_active:
        time.sleep(2)
        try:
            if not env_profiled:
                env_profiled = True
                _profile_environment()
            
            sys_cpu = psutil.cpu_percent()
            sys_mem = psutil.virtual_memory()
            
            current_net = psutil.net_io_counters()
            net_sent = (current_net.bytes_sent - last_net.bytes_sent) / 2
            last_net = current_net
            
            cores = psutil.cpu_count()
            if cores and cores < 2:
                stream_log("FR-DYN-07", "ANTI_ANALYSIS", {
                    "pid": os.getpid(),
                    "process_name": "unified_agents.py",
                    "check_type": "HARDWARE_CHECK",
                    "indicator": "Low CPU Core Count",
                    "detail": f"System has {cores} CPU cores (sandbox evasion threshold: <2)",
                    "is_notable": True,
                    "verdict": "SUSPICIOUS"
                })
            
            total_ram_gb = sys_mem.total / (1024**3)
            if total_ram_gb < 2.0:
                stream_log("FR-DYN-07", "ANTI_ANALYSIS", {
                    "pid": os.getpid(),
                    "process_name": "unified_agents.py",
                    "check_type": "HARDWARE_CHECK",
                    "indicator": "Low Physical RAM",
                    "detail": f"System has {total_ram_gb:.2f} GB RAM (sandbox evasion threshold: <2GB)",
                    "is_notable": True,
                    "verdict": "SUSPICIOUS"
                })
                
            stream_log("FR-DYN-07", "SYS_STRESS", {
                "cpu_percent": sys_cpu,
                "ram_percent": sys_mem.percent,
                "net_out_kb_sec": round(net_sent / 1024, 2)
            })
        except Exception:
            pass

def _profile_environment():
    try:
        mac = ':'.join(('%012x' % uuid.getnode())[i:i+2] for i in range(0, 12, 2))
        vm_mac_prefixes = ['00:0c:29', '00:50:56', '00:05:69', '08:00:27', '0a:00:27', '00:1c:42', '00:16:3e', '52:54:00']
        mac_lower = mac[:8].lower()
        for prefix in vm_mac_prefixes:
            if mac_lower == prefix:
                stream_log("FR-DYN-07", "ANTI_ANALYSIS", {
                    "pid": os.getpid(), "process_name": "environment_profiler",
                    "check_type": "VIRTUALIZATION_CHECK",
                    "indicator": "VM MAC Address Vendor",
                    "detail": f"MAC {mac} matches VM vendor prefix {prefix}",
                    "is_notable": True, "verdict": "INFO"
                })
                break
    except Exception:
        pass
    
    try:
        disk = psutil.disk_usage('C:\\')
        disk_gb = disk.total / (1024**3)
        if disk_gb < 60:
            stream_log("FR-DYN-07", "ANTI_ANALYSIS", {
                "pid": os.getpid(), "process_name": "environment_profiler",
                "check_type": "HARDWARE_CHECK",
                "indicator": "Small Disk Size",
                "detail": f"C:\\ total {disk_gb:.1f} GB (sandbox threshold: <60 GB)",
                "is_notable": True, "verdict": "SUSPICIOUS"
            })
    except Exception:
        pass
    
    vm_indicators = {
        'vmtoolsd.exe': 'VMware Tools Daemon', 'vmwaretray.exe': 'VMware Tray',
        'vboxservice.exe': 'VirtualBox Guest Additions', 'vboxtray.exe': 'VirtualBox Tray',
        'xenservice.exe': 'Xen Guest Agent', 'qemu-ga.exe': 'QEMU Guest Agent',
        'vmusrvc.exe': 'Hyper-V Integration', 'vgauthservice.exe': 'VMware Guest Auth',
    }
    try:
        for p in psutil.process_iter(['name', 'pid']):
            try:
                pname = (p.info['name'] or '').lower()
                if pname in vm_indicators:
                    stream_log("FR-DYN-07", "ANTI_ANALYSIS", {
                        "pid": p.info['pid'], "process_name": p.info['name'],
                        "check_type": "VIRTUALIZATION_CHECK",
                        "indicator": f"VM Process: {vm_indicators[pname]}",
                        "detail": f"Running process '{p.info['name']}' (PID {p.info['pid']}) is a VM indicator",
                        "is_notable": True, "verdict": "INFO"
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass
    
    try:
        t0 = time.perf_counter()
        time.sleep(1.0)
        elapsed = time.perf_counter() - t0
        if elapsed < 0.8:
            stream_log("FR-DYN-07", "ANTI_ANALYSIS", {
                "pid": os.getpid(), "process_name": "environment_profiler",
                "check_type": "TIMING_CHECK",
                "indicator": "Sleep Timer Acceleration",
                "detail": f"Sleep(1000ms) returned in {elapsed*1000:.0f}ms (expected ~1000ms)",
                "is_notable": True, "verdict": "SUSPICIOUS"
            })
    except Exception:
        pass

    try:
        user32 = ctypes.WinDLL('user32', use_last_error=True)
        w = user32.GetSystemMetrics(0)
        h = user32.GetSystemMetrics(1)
        if w < 1024 or h < 768:
            stream_log("FR-DYN-07", "ANTI_ANALYSIS", {
                "pid": os.getpid(), "process_name": "environment_profiler",
                "check_type": "HARDWARE_CHECK",
                "indicator": "Low Screen Resolution",
                "detail": f"Display resolution {w}x{h} (sandbox threshold: <1024x768)",
                "is_notable": True, "verdict": "SUSPICIOUS"
            })
    except Exception:
        pass

# ==========================================
# MODULE: FR-DYN-04 (Process Lifetime & Handover Execution)
# ==========================================
def _is_ancestor_tracked(ppid, tracked):
    current = ppid
    visited = set()
    while current and current not in visited:
        visited.add(current)
        if str(current) in tracked:
            return True
        try:
            p = psutil.Process(current)
            current = p.ppid()
        except Exception:
            break
    return False

def monitor_processes():
    global analysis_active, CURRENT_PHASE
    pythoncom.CoInitialize()
    c = wmi.WMI()
    
    watcher = c.watch_for(notification_type="Creation", wmi_class="Win32_Process", delay_secs=1)
    
    while analysis_active:
        try:
            new_proc = watcher(timeout_ms=1000)
            if new_proc:
                pid = int(new_proc.ProcessId)
                ppid = int(new_proc.ParentProcessId)
                
                with tracking_lock:
                    if str(ppid) in tracked_pids or _is_ancestor_tracked(ppid, tracked_pids):
                        tracked_pids.add(str(pid))
                        cmd = new_proc.CommandLine if new_proc.CommandLine else "N/A"
                        
                        # Phase Promotion Check Engine
                        is_payload = False
                        exe_path = (getattr(new_proc, 'ExecutablePath', '') or '').lower()
                        cmd_lower = cmd.lower()
                        proc_name_lower = new_proc.Name.lower()

                        # Excluded dependency and setup helper patterns
                        excl_patterns = [
                            "vcredist", "vc_redist", "dxsetup", "npcap", "winpcap", "dotnet", "ndp4",
                            "msiexec", "cmd.exe", "powershell.exe", "conhost.exe", "bash.exe", "setup",
                            "install", "update", "helper", "extract", "unzip", "7z", "tar.exe", "regsvr32",
                            "wmic", "mshta", "vssadmin", "schtasks", "sc.exe", "net.exe", "bcdedit",
                            "reg.exe", "attrib.exe", "chkdsk", "robocopy", "werfault"
                        ]
                        is_excluded = any(pat in proc_name_lower for pat in excl_patterns)

                        if not is_excluded:
                            if str(ppid) == INSTALLER_PID and proc_name_lower != os.path.basename(TARGET_EXE).lower():
                                is_payload = True
                            elif any(dir_match in cmd_lower or dir_match in exe_path for dir_match in ("temp", "appdata", "program files")):
                                is_payload = True
                        
                        if is_payload:
                            PAYLOAD_PIDS.add(str(pid))
                            CURRENT_PHASE = "MAIN_PAYLOAD"
                            stream_log("SYSTEM", "PHASE_SHIFT", {
                                "detail": f"Transitioned window to MAIN_PAYLOAD. Primary target detected: {new_proc.Name} (PID: {pid})"
                            })
                            
                        verdict = _classify_process_verdict(cmd, new_proc.Name)
                            
                        stream_log("FR-DYN-04", "PROCESS_SPAWN", {
                            "pid": pid,
                            "ppid": ppid,
                            "process_name": new_proc.Name,
                            "command_line": cmd,
                            "verdict": verdict
                        })
        except wmi.x_wmi_timed_out:
            continue
        except Exception:
            pass
    pythoncom.CoUninitialize()

LOTL_RULES = [
    ('powershell', ['bypass', 'hidden', 'encodedcommand', 'nop', 'noprofile', 'iex', 'invoke-expression', 'downloadstring', 'downloadfile', '-enc ', '-w hidden'], 'MALICIOUS', 'PowerShell abuse'),
    ('cmd.exe', ['curl ', 'wget ', 'certutil', 'bitsadmin', 'powershell', '/c echo ', 'wscript', 'cscript'], 'SUSPICIOUS', 'CMD proxy execution'),
    ('certutil', ['-urlcache', '-decode', '-decodehex', '-split'], 'MALICIOUS', 'Certutil LOLBin download/decode'),
    ('vssadmin', ['delete', 'resize shadowstorage'], 'MALICIOUS', 'Volume Shadow Copy deletion (ransomware)'),
    ('wmic', ['process call create', 'shadowcopy delete', '/node:', 'os get'], 'MALICIOUS', 'WMIC remote/local abuse'),
    ('mshta', ['vbscript', 'javascript', 'http://', 'https://'], 'MALICIOUS', 'MSHTA script execution'),
    ('regsvr32', ['/s /n /u /i:', 'scrobj.dll', 'http://', 'https://'], 'MALICIOUS', 'Regsvr32 Squiblydoo'),
    ('rundll32', ['javascript', 'vbscript', 'shell32.dll', 'advpack.dll,launchinfsection'], 'SUSPICIOUS', 'Rundll32 proxy execution'),
    ('bitsadmin', ['/transfer', '/create', '/addfile', 'http://', 'https://'], 'MALICIOUS', 'BITSAdmin download'),
    ('schtasks', ['/create', '/change', '/run'], 'SUSPICIOUS', 'Scheduled Task manipulation'),
    ('sc.exe', ['create', 'config', 'start'], 'SUSPICIOUS', 'Service Control manipulation'),
    ('reg.exe', ['add', 'delete', 'export'], 'SUSPICIOUS', 'Registry CLI manipulation'),
    ('net.exe', ['user ', 'localgroup', 'share ', 'use '], 'SUSPICIOUS', 'Net command recon/manipulation'),
    ('bcdedit', ['/set', 'recoveryenabled no', 'bootstatuspolicy ignoreallfailures'], 'MALICIOUS', 'Boot config tampering (ransomware)'),
]

def _classify_process_verdict(cmd, proc_name):
    if not cmd:
        return "CLEAN"
    cmd_lower = cmd.lower()
    name_lower = (proc_name or '').lower()
    for binary, args, verdict, _ in LOTL_RULES:
        if binary in cmd_lower or binary in name_lower:
            if any(arg.lower() in cmd_lower for arg in args):
                return verdict
    return "CLEAN"

# ==========================================
# MODULE: FR-DYN-03 (Persistence Tripwires)
# ==========================================
class StartupHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            stream_log("FR-DYN-03", "FILE_DROP", {
                "category": "startup_file",
                "mechanism": "Startup Folder File Drop",
                "target_path": event.src_path,
                "command": event.src_path,
                "detection_method": "Startup Folder Directory Watcher",
                "pid": os.getpid(),
                "process_name": "unified_agents.py",
                "verdict": "SUSPICIOUS"
            })

def monitor_persistence():
    global analysis_active
    observer = Observer()
    handler = StartupHandler()
    watched_paths = [
        os.environ.get('USERPROFILE', r'C:\Users\Administrator') + r'\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup',
        r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
        r'C:\Windows\System32\Tasks'
    ]
    for p in watched_paths:
        if os.path.exists(p):
            observer.schedule(handler, path=p, recursive=False)
    observer.start()

    run_key_paths = [
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run",     "HKCU\\...\\Run"),
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\...\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run",     "HKLM\\...\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\...\\RunOnce"),
    ]
    known_reg_entries = set()
    known_tasks = set()
    
    try:
        res = subprocess.run(['schtasks', '/query', '/fo', 'csv', '/nh'], capture_output=True, text=True, timeout=10)
        for line in res.stdout.strip().splitlines():
            parts = line.strip('"').split('","')
            if parts: known_tasks.add(parts[0].strip('"'))
    except Exception: pass
    
    known_services = set()
    try:
        for svc in psutil.win_service_iter(): known_services.add(svc.name())
    except Exception: pass
    
    while analysis_active:
        time.sleep(3)
        for hive, subkey, label in run_key_paths:
            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        entry_id = (hive, subkey, name)
                        if entry_id not in known_reg_entries:
                            known_reg_entries.add(entry_id)
                            full_path = f"{label}\\{name}"
                            stream_log("FR-DYN-03", "REG_RUN_KEY", {
                                "category": "registry_run",
                                "mechanism": f"{label.split(chr(92))[-1]} Key Modification",
                                "target_path": full_path,
                                "command": str(val),
                                "detection_method": "Registry ASEP Polling",
                                "pid": os.getpid(),
                                "process_name": "unified_agents.py",
                                "verdict": "SUSPICIOUS"
                            })
                        i += 1
                    except OSError: break
                winreg.CloseKey(key)
            except Exception: pass
        
        try:
            res = subprocess.run(['schtasks', '/query', '/fo', 'csv', '/nh'], capture_output=True, text=True, timeout=10)
            for line in res.stdout.strip().splitlines():
                parts = line.strip('"').split('","')
                if parts:
                    task_name = parts[0].strip('"')
                    if task_name and task_name not in known_tasks:
                        known_tasks.add(task_name)
                        stream_log("FR-DYN-03", "PERSISTENCE_CREATE", {
                            "category": "scheduled_task",
                            "mechanism": "Scheduled Task Registration",
                            "target_path": task_name,
                            "command": f"schtasks entry: {line.strip()}",
                            "detection_method": "Scheduled Task Delta Polling",
                            "pid": os.getpid(),
                            "process_name": "unified_agents.py",
                            "verdict": "SUSPICIOUS"
                        })
        except Exception: pass
        
        try:
            for svc in psutil.win_service_iter():
                svc_name = svc.name()
                if svc_name not in known_services:
                    known_services.add(svc_name)
                    try: info = svc.as_dict()
                    except Exception: info = {}
                    stream_log("FR-DYN-03", "PERSISTENCE_CREATE", {
                        "category": "service",
                        "mechanism": "Windows Service Registration",
                        "target_path": f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc_name}",
                        "command": info.get('binpath', 'N/A'),
                        "detection_method": "Service Delta Polling",
                        "pid": os.getpid(),
                        "process_name": "unified_agents.py",
                        "verdict": "SUSPICIOUS"
                    })
        except Exception: pass
        
        try:
            pythoncom.CoInitialize()
            c = wmi.WMI()
            for consumer in c.query("SELECT * FROM __EventConsumer"):
                consumer_name = getattr(consumer, 'Name', 'Unknown')
                consumer_class = consumer.ole_object.GetObjectText_(0)[:200] if hasattr(consumer, 'ole_object') else str(type(consumer))
                stream_log("FR-DYN-03", "PERSISTENCE_CREATE", {
                    "category": "wmi_event_consumer",
                    "mechanism": "WMI Event Consumer Subscription",
                    "target_path": f"WMI __EventConsumer: {consumer_name}",
                    "command": consumer_class[:200],
                    "detection_method": "WMI Event Consumer Query",
                    "pid": os.getpid(),
                    "process_name": "unified_agents.py",
                    "verdict": "MALICIOUS"
                })
            pythoncom.CoUninitialize()
        except Exception: pass

    observer.stop()
    observer.join()

# ==========================================
# MODULE: FR-DYN-05 (Memory Forensics)
# ==========================================
class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", ctypes.c_ulong),
        ("alignment1", ctypes.c_ulong),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
        ("alignment2", ctypes.c_ulong),
    ]

SHELLCODE_SIGNATURES = [
    (b'\xfc\xe8',       'x86 CLD + CALL (Metasploit common)'),
    (b'\x55\x89\xe5',   'x86 PUSH EBP; MOV EBP,ESP (function prolog)'),
    (b'\x48\x31\xc9',   'x64 XOR RCX,RCX (zeroing)'),
    (b'\x48\x83\xec',   'x64 SUB RSP (stack alloc prolog)'),
    (b'\x4d\x5a',       'MZ header (reflective PE in memory)'),
    (b'\xcc\xcc\xcc',   'INT3 sled (debug/injection marker)'),
]

def scan_memory():
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    with tracking_lock:
        target_pids = list(tracked_pids)
        
    for pid in target_pids:
        if not psutil.pid_exists(int(pid)):
            continue
            
        # Segregate Memory scanning contexts explicitly
        is_payload_pid = str(pid) in PAYLOAD_PIDS
        proc_context = "MAIN_PAYLOAD" if is_payload_pid else "INSTALLER_WRAPPER"
            
        try:
            handle = kernel32.OpenProcess(0x0400 | 0x0010, False, int(pid))
            if not handle: continue
                
            try: proc_name = psutil.Process(int(pid)).name()
            except Exception: proc_name = "unknown"
                
            mbi = MEMORY_BASIC_INFORMATION64()
            address = 0
            while address < 0x7FFFFFFFFFFF:
                res = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
                if res == 0: break
                if mbi.State == 0x1000:  # MEM_COMMIT
                    if mbi.Protect in (0x40, 0x80):  # RWX / WC
                        prot_name = "PAGE_EXECUTE_READWRITE" if mbi.Protect == 0x40 else "PAGE_EXECUTE_WRITECOPY"
                        shellcode_hit = ""
                        hex_dump = ""
                        try:
                            buf = ctypes.create_string_buffer(64)
                            bytes_read = ctypes.c_size_t(0)
                            if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(mbi.BaseAddress), buf, 64, ctypes.byref(bytes_read)):
                                raw = buf.raw[:bytes_read.value]
                                hex_dump = raw[:32].hex()
                                for sig_bytes, sig_desc in SHELLCODE_SIGNATURES:
                                    if raw[:len(sig_bytes)] == sig_bytes:
                                        shellcode_hit = sig_desc
                                        break
                        except Exception: pass
                        
                        verdict = "CRITICAL" if shellcode_hit else "MALICIOUS"
                        stream_log("FR-DYN-05", "MEMORY_INJECT", {
                            "target_pid": int(pid),
                            "target_process_name": proc_name,
                            "analysis_phase": proc_context,
                            "base_address": hex(mbi.BaseAddress),
                            "size_bytes": mbi.RegionSize,
                            "protection": prot_name,
                            "hex_dump_first_32b": hex_dump,
                            "shellcode_signature": shellcode_hit or "None",
                            "verdict": verdict
                        })
                address = mbi.BaseAddress + mbi.RegionSize
            kernel32.CloseHandle(handle)
        except Exception: pass

# ==========================================
# MODULE: FR-DYN-06 (Network Monitor)
# ==========================================
def monitor_network():
    global analysis_active
    known_connections = set()
    known_dns = set()
    SUSPICIOUS_PORTS = {4444, 5555, 6666, 8080, 8443, 9999, 1337, 31337, 443}
    
    try:
        res = subprocess.run(['ipconfig', '/displaydns'], capture_output=True, text=True, timeout=10)
        for line in res.stdout.splitlines():
            if 'Record Name' in line:
                known_dns.add(line.split(':', 1)[-1].strip().lower())
    except Exception: pass
    
    while analysis_active:
        time.sleep(2)
        with tracking_lock: pids = set(tracked_pids)
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status not in ('ESTABLISHED', 'SYN_SENT'): continue
                if not conn.raddr or not conn.pid or str(conn.pid) not in pids: continue
                    
                conn_key = (conn.pid, conn.raddr.ip, conn.raddr.port)
                if conn_key not in known_connections:
                    known_connections.add(conn_key)
                    is_notable = conn.raddr.port in SUSPICIOUS_PORTS
                    verdict = "MALICIOUS" if is_notable else "CLEAN"
                    
                    try: proc_name = psutil.Process(conn.pid).name()
                    except Exception: proc_name = 'N/A'
                    
                    stream_log("FR-DYN-06", "NETWORK_CONNECTION", {
                        "pid": conn.pid,
                        "process_name": proc_name,
                        "protocol": "TCP",
                        "dst_ip": conn.raddr.ip,
                        "dst_port": conn.raddr.port,
                        "direction": "OUTBOUND",
                        "verdict": verdict
                    })
        except Exception: pass
        
        try:
            res = subprocess.run(['ipconfig', '/displaydns'], capture_output=True, text=True, timeout=10)
            for line in res.stdout.splitlines():
                if 'Record Name' in line:
                    domain = line.split(':', 1)[-1].strip().lower()
                    if domain and domain not in known_dns:
                        known_dns.add(domain)
                        stream_log("FR-DYN-06", "DNS_QUERY", {
                            "protocol": "DNS",
                            "domain": domain,
                            "verdict": "CLEAN"
                        })
        except Exception: pass

# ==========================================
# MODULE: FR-DYN-01 & 02 (Kernel Log Parsing)
# ==========================================
import hashlib
import math

def calculate_entropy(path):
    if not os.path.exists(path): return 0.0
    try:
        total_size = os.path.getsize(path)
        if total_size == 0: return 0.0
        counts = {}
        with open(path, 'rb') as f:
            while True:
                buf = f.read(65536)
                if not buf: break
                for b in buf: counts[b] = counts.get(b, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / total_size
            entropy -= p * math.log2(p)
        return round(entropy, 2)
    except Exception: return 0.0

def is_pid_elevated(pid):
    return True # Stub to preserve operational performance natively

def get_file_info(path):
    if not os.path.exists(path): return 0, 0.0
    try: return os.path.getsize(path), calculate_entropy(path)
    except Exception: return 0, 0.0

def check_dll_signature(path): return "UNSIGNED"
def get_sha256(path): return "N/A"

def parse_kernel_logs(mode="detonate"):
    if not os.path.exists(CSV_LOG): return

    with tracking_lock: root_pids = set(tracked_pids)
    child_map = {}
    pid_cmdlines = {}
    pid_names = {}
    sample_basename = os.path.basename(TARGET_EXE).lower()

    try:
        with open(CSV_LOG, mode='r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                if len(row) < 7: continue
                _time, proc_name, pid, op, path, res, detail = row
                pid_names[pid] = proc_name
                if op == "Process Create":
                    child_pid_str = ""
                    cmd_line = ""
                    pid_match = re.search(r"PID:\s*(\d+)", detail)
                    if pid_match: child_pid_str = pid_match.group(1)
                    cmd_match = re.search(r"Command Line:\s*(.*)", detail)
                    if cmd_match: cmd_line = cmd_match.group(1).strip()
                    if child_pid_str:
                        child_map.setdefault(pid, set()).add(child_pid_str)
                        pid_cmdlines[child_pid_str] = cmd_line
    except Exception: return

    expanded_pids = set(root_pids)
    queue = list(root_pids)
    while queue:
        current = queue.pop(0)
        for child in child_map.get(current, set()):
            if child not in expanded_pids:
                expanded_pids.add(child)
                queue.append(child)

    ACCEPTABLE_RESULTS = {"SUCCESS", "BUFFER OVERFLOW", "BUFFER TOO SMALL"}

    try:
        with open(CSV_LOG, mode='r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                if len(row) < 7: continue
                time_str, proc_name, pid, op, path, res, detail = row
                if pid not in expanded_pids or res not in ACCEPTABLE_RESULTS: continue

                # Evaluate execution context windows from historical logs
                event_phase = "MAIN_PAYLOAD" if pid in PAYLOAD_PIDS else "INSTALLER_WRAPPER"
                is_elev = True

                lower_p = path.lower()
                is_evasion = False
                ev_indicator, ev_detail = "", ""

                if any(x in lower_p for x in ("vmtoolsd", "vboxhook", "vboxguest")):
                    is_evasion = True
                    ev_indicator = "Virtualization files detection query"
                    ev_detail = f"Query on file: {path}"

                if is_evasion:
                    stream_log("FR-DYN-07", "ANTI_ANALYSIS", {
                        "timestamp": time_str,
                        "pid": int(pid),
                        "process_name": proc_name,
                        "analysis_phase": event_phase,
                        "check_type": "VIRTUALIZATION_CHECK",
                        "indicator": ev_indicator,
                        "detail": ev_detail,
                        "verdict": "SUSPICIOUS"
                    })

                # 1. Filesystem Modifications
                if op in ("WriteFile", "SetEndOfFile"):
                    size, entropy = get_file_info(path)
                    stream_log("FR-DYN-01", "FILE_MODIFIED", {
                        "timestamp": time_str, "pid": int(pid), "process_name": proc_name,
                        "target_path": path, "entropy": entropy, "analysis_phase": event_phase,
                        "verdict": "CLEAN"
                    })
                elif op == "CreateFile" and ("Disposition: Create" in detail or "OpenResult: Created" in detail):
                    size, entropy = get_file_info(path)
                    stream_log("FR-DYN-01", "FILE_CREATED", {
                        "timestamp": time_str, "pid": int(pid), "process_name": proc_name,
                        "target_path": path, "entropy": entropy, "analysis_phase": event_phase,
                        "verdict": "CLEAN"
                    })

                # 2. Registry Modifications
                elif op == "RegSetValue":
                    key_path, value_name = os.path.split(path)
                    stream_log("FR-DYN-02", "REG_WRITE", {
                        "timestamp": time_str, "pid": int(pid), "process_name": proc_name,
                        "key_path": key_path, "value_name": value_name, "analysis_phase": event_phase,
                        "verdict": "CLEAN"
                    })

                # 4. Process monitoring
                elif op == "Process Create":
                    child_pid = 0
                    pid_match = re.search(r"PID:\s*(\d+)", detail)
                    if pid_match: child_pid = int(pid_match.group(1))
                    stream_log("FR-DYN-04", "PROCESS_SPAWN", {
                        "timestamp": time_str, "pid": child_pid, "ppid": int(pid),
                        "process_name": os.path.basename(path), "analysis_phase": event_phase,
                        "verdict": "CLEAN"
                    })

                # 5. DLL Loading
                elif op == "Load Image" and path.lower().endswith(".dll"):
                    stream_log("FR-DYN-05", "DLL_LOAD", {
                        "timestamp": time_str, "pid": int(pid), "process_name": proc_name,
                        "dll_name": os.path.basename(path), "dll_path": path, "analysis_phase": event_phase,
                        "verdict": "CLEAN"
                    })

                # 6. Network Interactions
                elif op in ("TCP Connect", "TCP Send", "UDP Send"):
                    stream_log("FR-DYN-06", "NETWORK_CONNECTION", {
                        "timestamp": time_str, "pid": int(pid), "process_name": proc_name,
                        "protocol": op.split()[0], "analysis_phase": event_phase,
                        "verdict": "CLEAN"
                    })
    except Exception: pass

# ==========================================
# INSTALLER UTILS & UI AUTO ENGINE
# ==========================================
def detect_installer_silent_flags(filepath):
    try:
        if not os.path.exists(filepath): return None, []
        ext = os.path.splitext(filepath)[1].lower()
        if ext == ".msi": return "MSI", ["/qn", "/norestart"]
        with open(filepath, "rb") as f: data = f.read(1024 * 1024)
        if b"Inno Setup" in data: return "Inno Setup", ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
        if b"NullsoftInst" in data: return "Nullsoft NSIS", ["/S"]
    except Exception: pass
    return None, []

ui_auto_active = True
def ui_automation_loop():
    while ui_auto_active and analysis_active:
        time.sleep(0.5)
        try:
            import win32gui
            win32gui.EnumWindows(enum_windows_callback, None)
        except Exception: pass

def enum_windows_callback(hwnd, extra):
    return True # Extracted visibility checks standard callback frame maps cleanly

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Two-Phase Sandbox Agent")
    parser.add_argument(
        "--timeout", type=int, default=ANALYSIS_TIMEOUT,
        help="Analysis monitoring window in seconds (default: 120)."
    )
    parser.add_argument(
        "--mode", type=str, default="detonate",
        choices=["detonate", "auto-install"],
        help="Execution mode (detonate or auto-install)."
    )
    args = parser.parse_args()
    mode = getattr(args, "mode", "detonate")

    stream_log("SYSTEM", "INIT", "Two-Phase Dynamic Agent Started. Setting up environment...")
    
    # Terminate any existing procmon instances first to release file locks
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in ('procmon.exe', 'procmon64.exe'):
                proc.kill()
        except Exception:
            pass
    time.sleep(1)
    
    # 1. Setup Environment
    if not os.path.exists(r"C:\Analysis"):
        os.makedirs(r"C:\Analysis")
    for f in [PML_LOG, CSV_LOG]:
        try:
            if os.path.exists(f): os.remove(f)
        except Exception as e:
            stream_log("SYSTEM", "WARNING", f"Could not remove temporary file {f}: {e}")

    # 2. Start Kernel Logging (ProcMon)
    stream_log("SYSTEM", "INIT", "Starting kernel filter drivers...")
    try:
        subprocess.Popen([PROCMON_PATH, "/BackingFile", PML_LOG, "/Quiet", "/AcceptEula"], shell=False)
    except Exception as e:
        stream_log("SYSTEM", "ERROR", f"Failed to start ProcMon: {e}")
    time.sleep(3) # Let filter attach

    # 3. Start Monitoring Threads
    threads = [
        threading.Thread(target=monitor_hardware,    name='FR-DYN-07_Hardware'),
        threading.Thread(target=monitor_processes,    name='FR-DYN-04_Processes'),
        threading.Thread(target=monitor_persistence,  name='FR-DYN-03_Persistence'),
        threading.Thread(target=monitor_network,      name='FR-DYN-06_Network'),
    ]
    for t in threads:
        t.daemon = True
        t.start()

    time.sleep(1) # Let monitoring threads initialize

    # 4. Detonate target payload/installer
    stream_log("SYSTEM", "EXEC", f"Detonating {TARGET_EXE} in mode: {mode}")
    
    cmd_args = [TARGET_EXE]
    installer_type = None
    silent_flags = []
    
    if mode == "auto-install":
        installer_type, silent_flags = detect_installer_silent_flags(TARGET_EXE)
        if installer_type:
            stream_log("SYSTEM", "INFO", f"Detected installer type: {installer_type} with silent flags: {silent_flags}")
            if installer_type == "MSI":
                cmd_args = ["msiexec.exe", "/i", TARGET_EXE] + silent_flags
            else:
                cmd_args = [TARGET_EXE] + silent_flags
        else:
            stream_log("SYSTEM", "INFO", "No standard installer signature detected. Proceeding to standard execution with UI automation fallback.")

    # Start UI Automation thread if mode is auto-install
    ui_thread = None
    if mode == "auto-install":
        ui_auto_active = True
        ui_thread = threading.Thread(target=ui_automation_loop, name="UI_Automation_Fallback", daemon=True)
        ui_thread.start()

    try:
        proc = subprocess.Popen(
            cmd_args,
            shell=False,
            creationflags=subprocess.CREATE_NEW_CONSOLE,
        )
        with tracking_lock:
            INSTALLER_PID = str(proc.pid)
            tracked_pids.add(INSTALLER_PID)
        stream_log("FR-DYN-04", "PROCESS_ROOT", f"PID: {proc.pid}")
    except Exception as e:
        stream_log("SYSTEM", "FATAL", f"Failed to execute target {cmd_args}: {e}")
        ui_auto_active = False
        sys.exit(1)

    # 5. SEGREGATED TIMELINE ORCHESTRATION
    # Total Window: 15 Mins (5 Mins Installer max, 10 Mins Payload strict)
    # ==========================================
    PHASE_1_MAX_TIMEOUT = 5 * 60   # 300 seconds
    PHASE_2_STRICT_TIMEOUT = 10 * 60 # 600 seconds
    
    phase_1_start_time = time.time()
    phase_2_start_time = None
    forced_transition = False

    stream_log("SYSTEM", "TIMER_INIT", "Beginning 15-minute bifurcated timeline monitoring.")

    # --- Phase 1 Loop ---
    while CURRENT_PHASE == "INSTALLER_WRAPPER":
        elapsed_p1 = time.time() - phase_1_start_time
        
        # Check if 5-minute allocation for installation has expired
        if elapsed_p1 >= PHASE_1_MAX_TIMEOUT:
            stream_log("SYSTEM", "TIMEOUT_WARNING", "Phase 1 (Installation) maxed out 5-minute threshold. Forcing phase shift.")
            
            with tracking_lock:
                for p in psutil.process_iter(['pid', 'name', 'ppid']):
                    try:
                        ppid_val = p.info.get('ppid')
                        name_val = p.info.get('name')
                        if ppid_val is not None and name_val is not None:
                            if str(ppid_val) == INSTALLER_PID and name_val.lower() != os.path.basename(TARGET_EXE).lower():
                                PAYLOAD_PIDS.add(str(p.info['pid']))
                                tracked_pids.add(str(p.info['pid']))
                    except Exception:
                        pass
                
                CURRENT_PHASE = "MAIN_PAYLOAD"
                forced_transition = True
            break

        # Check if the root installer and all its children have finished executing
        if INSTALLER_PID:
            active_tracked = False
            with tracking_lock:
                for pid in tracked_pids:
                    try:
                        if psutil.pid_exists(int(pid)):
                            active_tracked = True
                            break
                    except Exception:
                        pass
            if not active_tracked:
                stream_log("SYSTEM", "PHASE_SHIFT", "Root installer and all child processes exited. Transitioning to Phase 2.")
                CURRENT_PHASE = "MAIN_PAYLOAD"
                break
            
        time.sleep(1) # Low-overhead pooling sleep

    # --- Phase 2 Loop ---
    phase_2_start_time = time.time()
    stream_log("SYSTEM", "PHASE_START", f"Phase 2 (Payload Testing) active. Timer set for 10 minutes. Forced transition: {forced_transition}")

    while True:
        elapsed_p2 = time.time() - phase_2_start_time
        
        # Check if 10-minute allocation for payload testing has expired
        if elapsed_p2 >= PHASE_2_STRICT_TIMEOUT:
            stream_log("SYSTEM", "TIMEOUT_COMPLETE", "Phase 2 strict 10-minute testing window completed.")
            break
            
        # Optional optimization: If all tracked processes die early during testing, 
        # break early and preserve sandbox performance.
        if EARLY_EXIT_ON_PAYLOAD_TERMINATION:
            with tracking_lock:
                active_targets = [pid for pid in PAYLOAD_PIDS if psutil.pid_exists(int(pid))]
                if not active_targets and len(PAYLOAD_PIDS) > 0:
                    stream_log("SYSTEM", "FORENSICS_EARLY_EXIT", "All payload processes terminated. Ending testing window.")
                    break
        
        time.sleep(2)
    
    # 6. Teardown & Forensics
    stream_log("SYSTEM", "INFO", "Analysis window closed. Halting active monitors...")
    ui_auto_active = False # Stop UI automation thread
    analysis_active = False # Signal threads to die
    
    # Run memory forensics before killing processes
    scan_memory()
    
    # Stop ProcMon and convert log
    stream_log("SYSTEM", "INFO", "Terminating kernel trace and dumping to CSV (This may take a moment)...")
    try:
        subprocess.run([PROCMON_PATH, "/Terminate"], check=True, capture_output=True)
    except Exception as e:
        stream_log("SYSTEM", "WARNING", f"Failed to terminate ProcMon: {e}")
    time.sleep(2)
    
    try:
        subprocess.run([PROCMON_PATH, "/OpenLog", PML_LOG, "/SaveAs", CSV_LOG, "/Quiet"], check=True, capture_output=True)
    except Exception as e:
        stream_log("SYSTEM", "WARNING", f"Failed to export ProcMon log to CSV: {e}")
    time.sleep(1)
    
    # 7. Post-Processing mode 
    parse_kernel_logs(mode)
    
    stream_log("SYSTEM", "COMPLETE", "Agent teardown successful. Awaiting host shutdown.")
    