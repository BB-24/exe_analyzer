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
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
username = "Administrator"
try:
    import getpass
    username = getpass.getuser()
except Exception:
    pass

# Redirect stdout and stderr to a file on desktop since we run directly without shell redirection
try:
    log_path = f"C:\\Users\\{username}\\Desktop\\agent_err.log"
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
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

# Global State Management
analysis_active = True
tracked_pids = set()
tracking_lock = threading.Lock()

ser = None
for attempt in range(15):
    try:
        ser = serial.Serial(SERIAL_PORT, baudrate=115200, timeout=1, write_timeout=2)
        print(f"[+] Serial port {SERIAL_PORT} connected successfully.")
        break
    except Exception as e:
        print(f"[-] Serial connection attempt {attempt+1} failed: {e}")
        time.sleep(1)

def stream_log(fr_tag, event_type, detail):
    """Streams structured telemetry directly to the Host VM."""
    timestamp = time.strftime("%H:%M:%S")
    if isinstance(detail, dict):
        import json
        # Embed default timestamp/tag/event_type if not present
        if "timestamp" not in detail:
            detail["timestamp"] = timestamp
        if "tag" not in detail:
            detail["tag"] = fr_tag
        if "event_type" not in detail:
            detail["event_type"] = event_type
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
# Target APIs: GetSystemInfo, GlobalMemoryStatusEx,
#   GetDiskFreeSpaceEx, Sleep, NtDelayExecution,
#   GetAdaptersInfo, EnumDeviceDrivers
# ==========================================
def monitor_hardware():
    """FR-DYN-07: System environment queries, anti-analysis checks, and resource monitoring.
    Captures: CPU cores, RAM, MAC address, disk size, VM drivers, Sleep evasion timing."""
    global analysis_active
    last_net = psutil.net_io_counters()
    env_profiled = False
    
    while analysis_active:
        time.sleep(2)
        try:
            # === ONE-TIME ENVIRONMENT PROFILE (first iteration only) ===
            if not env_profiled:
                env_profiled = True
                _profile_environment()
            
            sys_cpu = psutil.cpu_percent()
            sys_mem = psutil.virtual_memory()
            
            current_net = psutil.net_io_counters()
            net_sent = (current_net.bytes_sent - last_net.bytes_sent) / 2
            last_net = current_net
            
            # CPU core evasion check (malware queries GetSystemInfo)
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
            
            # Physical RAM evasion check (malware queries GlobalMemoryStatusEx)
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
    """One-time environment fingerprint: MAC, disk, VM drivers, Sleep timing."""
    # 1. MAC Address VM Vendor Detection (GetAdaptersInfo)
    try:
        mac = ':'.join(('%012x' % uuid.getnode())[i:i+2] for i in range(0, 12, 2))
        vm_mac_prefixes = [
            '00:0c:29', '00:50:56', '00:05:69',  # VMware
            '08:00:27', '0a:00:27',               # VirtualBox
            '00:1c:42',                            # Parallels
            '00:16:3e',                            # Xen
            '52:54:00',                            # QEMU/KVM
        ]
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
    
    # 2. Disk Size Check (GetDiskFreeSpaceEx — malware expects >60GB)
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
    
    # 3. VM Process / Driver Enumeration (EnumDeviceDrivers, CreateToolhelp32Snapshot)
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
    
    # 4. Sleep() / NtDelayExecution Evasion Baseline
    try:
        t0 = time.perf_counter()
        time.sleep(1.0)
        elapsed = time.perf_counter() - t0
        if elapsed < 0.8:  # Timer acceleration detected
            stream_log("FR-DYN-07", "ANTI_ANALYSIS", {
                "pid": os.getpid(), "process_name": "environment_profiler",
                "check_type": "TIMING_CHECK",
                "indicator": "Sleep Timer Acceleration",
                "detail": f"Sleep(1000ms) returned in {elapsed*1000:.0f}ms (expected ~1000ms)",
                "is_notable": True, "verdict": "SUSPICIOUS"
            })
    except Exception:
        pass
    
    # 5. Screen Resolution Check (GetSystemMetrics — malware expects >=1024x768)
    try:
        user32 = ctypes.WinDLL('user32', use_last_error=True)
        w = user32.GetSystemMetrics(0)  # SM_CXSCREEN
        h = user32.GetSystemMetrics(1)  # SM_CYSCREEN
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
# MODULE: FR-DYN-04 (Process Lifetime)
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
    global analysis_active
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
                        
                        # Living-off-the-Land (LotL) Abuse Detection
                        # Target: CreateProcessA/W, ShellExecuteA/W, WinExec
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

# ==========================================
# MODULE: FR-DYN-04 HELPER — LotL Classifier
# Target APIs: CreateProcessA/W, ShellExecuteA/W,
#   WinExec, CreateRemoteThread, NtCreateThreadEx
# ==========================================
# LOLBAS (Living Off The Land Binaries And Scripts) classification rules
LOTL_RULES = [
    # (binary_substr, suspicious_args, verdict, description)
    ('powershell', ['bypass', 'hidden', 'encodedcommand', 'nop', 'noprofile', 'iex', 'invoke-expression', 'downloadstring', 'downloadfile', '-enc ', '-w hidden'], 'MALICIOUS', 'PowerShell abuse'),
    ('cmd.exe', ['curl ', 'wget ', 'certutil', 'bitsadmin', 'powershell', '/c echo ', 'wscript', 'cscript'], 'SUSPICIOUS', 'CMD proxy execution'),
    ('certutil', ['-urlcache', '-decode', '-decodehex', '-split'], 'MALICIOUS', 'Certutil LOLBin download/decode'),
    ('vssadmin', ['delete', 'resize shadowstorage'], 'MALICIOUS', 'Volume Shadow Copy deletion (ransomware)'),
    ('wmic', ['process call create', 'shadowcopy delete', '/node:', 'os get'], 'MALICIOUS', 'WMIC remote/local abuse'),
    ('mshta', ['vbscript', 'javascript', 'http://', 'https://'], 'MALICIOUS', 'MSHTA script execution'),
    ('regsvr32', ['/s /n /u /i:', 'scrobj.dll', 'http://', 'https://'], 'MALICIOUS', 'Regsvr32 Squiblydoo'),
    ('rundll32', ['javascript', 'vbscript', 'shell32.dll', 'advpack.dll,launchinfsection'], 'SUSPICIOUS', 'Rundll32 proxy execution'),
    ('bitsadmin', ['/transfer', '/create', '/addfile', 'http://', 'https://'], 'MALICIOUS', 'BITSAdmin download'),
    ('cscript', ['http://', 'https://', '.vbs', '.js', '.wsf'], 'SUSPICIOUS', 'CScript execution'),
    ('wscript', ['http://', 'https://', '.vbs', '.js', '.wsf'], 'SUSPICIOUS', 'WScript execution'),
    ('msiexec', ['/q', '/i http', '/i https', '/quiet'], 'SUSPICIOUS', 'MSIExec remote install'),
    ('schtasks', ['/create', '/change', '/run'], 'SUSPICIOUS', 'Scheduled Task manipulation'),
    ('sc.exe', ['create', 'config', 'start'], 'SUSPICIOUS', 'Service Control manipulation'),
    ('reg.exe', ['add', 'delete', 'export'], 'SUSPICIOUS', 'Registry CLI manipulation'),
    ('net.exe', ['user ', 'localgroup', 'share ', 'use '], 'SUSPICIOUS', 'Net command recon/manipulation'),
    ('bcdedit', ['/set', 'recoveryenabled no', 'bootstatuspolicy ignoreallfailures'], 'MALICIOUS', 'Boot config tampering (ransomware)'),
    ('wbadmin', ['delete catalog', 'delete systemstatebackup'], 'MALICIOUS', 'Backup deletion (ransomware)'),
    ('icacls', ['/grant', '/deny', '/reset'], 'SUSPICIOUS', 'Permission modification'),
    ('attrib', ['+h', '+s', '-r'], 'SUSPICIOUS', 'File attribute hiding'),
]

def _classify_process_verdict(cmd, proc_name):
    """Classifies a process spawn using LOLBAS rules."""
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
# Target APIs: RegSetValueExA/W, RegCreateKeyExA/W,
#   ITaskService::RegisterTaskDefinition (COM),
#   CreateServiceA/W, ChangeServiceConfigA/W,
#   IWbemServices::ExecMethodAsync (WMI)
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
    """FR-DYN-03: Monitors ASEPs — Run keys, Scheduled Tasks, Services, WMI consumers."""
    global analysis_active
    
    # 1. Watchdog for Startup Folders
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

    # 2. Baseline known registry Run values (HKCU + HKLM, Run + RunOnce)
    run_key_paths = [
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run",     "HKCU\\...\\Run"),
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\...\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run",     "HKLM\\...\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\...\\RunOnce"),
    ]
    known_reg_entries = set()  # (hive, subkey, name)
    
    # 3. Baseline known scheduled tasks
    known_tasks = set()
    try:
        res = subprocess.run(['schtasks', '/query', '/fo', 'csv', '/nh'], capture_output=True, text=True, timeout=10)
        for line in res.stdout.strip().splitlines():
            parts = line.strip('"').split('","')
            if parts:
                known_tasks.add(parts[0].strip('"'))
    except Exception:
        pass
    
    # 4. Baseline known services
    known_services = set()
    try:
        for svc in psutil.win_service_iter():
            known_services.add(svc.name())
    except Exception:
        pass
    
    # === POLLING LOOP ===
    while analysis_active:
        time.sleep(3)
        
        # A. Poll Registry Run/RunOnce Keys (RegSetValueExW, RegCreateKeyExW)
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
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception:
                pass
        
        # B. Poll Scheduled Tasks (ITaskService / schtasks.exe)
        try:
            res = subprocess.run(['schtasks', '/query', '/fo', 'csv', '/nh'],
                                 capture_output=True, text=True, timeout=10)
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
        except Exception:
            pass
        
        # C. Poll Windows Services (CreateServiceA/W)
        try:
            for svc in psutil.win_service_iter():
                svc_name = svc.name()
                if svc_name not in known_services:
                    known_services.add(svc_name)
                    try:
                        info = svc.as_dict()
                    except Exception:
                        info = {}
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
        except Exception:
            pass
        
        # D. Poll WMI Event Consumers (__EventConsumer subclass instances)
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
        except Exception:
            pass

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

# Common shellcode prologs (x86/x64) to detect injected code
# Format: (pattern_bytes, description)
SHELLCODE_SIGNATURES = [
    (b'\xfc\xe8',       'x86 CLD + CALL (Metasploit common)'),
    (b'\x55\x89\xe5',   'x86 PUSH EBP; MOV EBP,ESP (function prolog)'),
    (b'\x48\x31\xc9',   'x64 XOR RCX,RCX (zeroing)'),
    (b'\x48\x83\xec',   'x64 SUB RSP (stack alloc prolog)'),
    (b'\x4d\x5a',       'MZ header (reflective PE in memory)'),
    (b'\xcc\xcc\xcc',   'INT3 sled (debug/injection marker)'),
    (b'\x31\xc0\x50',   'x86 XOR EAX,EAX; PUSH EAX (null-push shellcode)'),
    (b'\xe8\x00\x00\x00\x00', 'x86 CALL $+5 (PIC position-independent code)'),
]

def scan_memory():
    """FR-DYN-05: Scans surviving processes for injected code,
    PAGE_EXECUTE_READWRITE allocations, and shellcode prologs.
    Target APIs traced: VirtualAllocEx, NtWriteVirtualMemory,
    NtMapViewOfSection, VirtualProtectEx, NtUnmapViewOfSection."""
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    
    with tracking_lock:
        target_pids = list(tracked_pids)
        
    for pid in target_pids:
        if not psutil.pid_exists(int(pid)):
            continue
            
        try:
            # PROCESS_QUERY_INFORMATION (0x0400) | PROCESS_VM_READ (0x0010)
            handle = kernel32.OpenProcess(0x0400 | 0x0010, False, int(pid))
            if not handle:
                continue
                
            try:
                proc_name = psutil.Process(int(pid)).name()
            except Exception:
                proc_name = "unknown"
                
            stream_log("FR-DYN-05", "MEM_SCAN", f"Scanning volatile memory for PID {pid} ({proc_name})")
            
            mbi = MEMORY_BASIC_INFORMATION64()
            address = 0
            rwx_count = 0
            while address < 0x7FFFFFFFFFFF:
                res = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
                if res == 0:
                    break
                # State 0x1000 = MEM_COMMIT
                if mbi.State == 0x1000:
                    # 0x40 = PAGE_EXECUTE_READWRITE, 0x80 = PAGE_EXECUTE_WRITECOPY
                    if mbi.Protect in (0x40, 0x80):
                        rwx_count += 1
                        prot_name = "PAGE_EXECUTE_READWRITE" if mbi.Protect == 0x40 else "PAGE_EXECUTE_WRITECOPY"
                        
                        # Read first 64 bytes for shellcode prolog detection
                        shellcode_hit = ""
                        hex_dump = ""
                        try:
                            buf = ctypes.create_string_buffer(64)
                            bytes_read = ctypes.c_size_t(0)
                            if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(mbi.BaseAddress),
                                                          buf, 64, ctypes.byref(bytes_read)):
                                raw = buf.raw[:bytes_read.value]
                                hex_dump = raw[:32].hex()
                                for sig_bytes, sig_desc in SHELLCODE_SIGNATURES:
                                    if raw[:len(sig_bytes)] == sig_bytes:
                                        shellcode_hit = sig_desc
                                        break
                        except Exception:
                            pass
                        
                        verdict = "CRITICAL" if shellcode_hit else "MALICIOUS"
                        stream_log("FR-DYN-05", "MEMORY_INJECT", {
                            "pid": os.getpid(),
                            "process_name": "unified_agents.py",
                            "target_pid": int(pid),
                            "target_process_name": proc_name,
                            "operation": "VirtualQueryEx + ReadProcessMemory",
                            "base_address": hex(mbi.BaseAddress),
                            "size_bytes": mbi.RegionSize,
                            "protection": prot_name,
                            "hex_dump_first_32b": hex_dump,
                            "shellcode_signature": shellcode_hit or "None",
                            "verdict": verdict
                        })
                address = mbi.BaseAddress + mbi.RegionSize
            
            if rwx_count > 0:
                stream_log("FR-DYN-05", "MEM_SCAN", f"PID {pid} ({proc_name}): Found {rwx_count} RWX memory region(s)")
            
            kernel32.CloseHandle(handle)
        except Exception as e:
            stream_log("FR-DYN-05", "ERROR", f"PID {pid} mem scan failed: {e}")

# ==========================================
# MODULE: FR-DYN-06 (Network Monitor)
# Target APIs: connect, send, recv, WSASend,
#   DnsQuery_A/W, InternetOpenA/W,
#   HttpSendRequestA/W, URLDownloadToFileA/W
# ==========================================
def monitor_network():
    """FR-DYN-06: Monitors DNS cache changes and active network connections.
    Uses psutil for connection tracking and ipconfig /displaydns for DNS."""
    global analysis_active
    
    known_connections = set()  # (pid, remote_ip, remote_port)
    known_dns = set()          # domain names
    
    # Known C2 / suspicious ports
    SUSPICIOUS_PORTS = {4444, 5555, 6666, 8080, 8443, 9999, 1337, 31337, 443, 4443}
    
    # Baseline DNS cache
    try:
        res = subprocess.run(['ipconfig', '/displaydns'], capture_output=True, text=True, timeout=10)
        for line in res.stdout.splitlines():
            line = line.strip()
            if 'Record Name' in line:
                domain = line.split(':', 1)[-1].strip()
                known_dns.add(domain.lower())
    except Exception:
        pass
    
    while analysis_active:
        time.sleep(2)
        
        # A. Active Connection Monitoring (connect/WSAConnect)
        with tracking_lock:
            pids = set(tracked_pids)
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status != 'ESTABLISHED' and conn.status != 'SYN_SENT':
                    continue
                if not conn.raddr or not conn.pid:
                    continue
                if str(conn.pid) not in pids:
                    continue
                    
                conn_key = (conn.pid, conn.raddr.ip, conn.raddr.port)
                if conn_key not in known_connections:
                    known_connections.add(conn_key)
                    
                    is_notable = conn.raddr.port in SUSPICIOUS_PORTS
                    verdict = "MALICIOUS" if is_notable else "CLEAN"
                    
                    # Check for non-standard HTTPS ports
                    if conn.raddr.port not in (80, 443, 8080) and conn.raddr.port > 1024:
                        verdict = "SUSPICIOUS"
                        is_notable = True
                    
                    try:
                        proc_name = psutil.Process(conn.pid).name()
                    except Exception:
                        proc_name = 'N/A'
                    
                    stream_log("FR-DYN-06", "NETWORK_CONNECTION", {
                        "pid": conn.pid,
                        "process_name": proc_name,
                        "protocol": "TCP",
                        "src_ip": conn.laddr.ip if conn.laddr else "0.0.0.0",
                        "src_port": conn.laddr.port if conn.laddr else 0,
                        "dst_ip": conn.raddr.ip,
                        "dst_port": conn.raddr.port,
                        "direction": "OUTBOUND",
                        "status": conn.status,
                        "detail": f"Active {conn.status} connection to {conn.raddr.ip}:{conn.raddr.port}",
                        "is_notable": is_notable,
                        "verdict": verdict
                    })
        except (psutil.AccessDenied, OSError):
            pass
        
        # B. DNS Cache Delta Monitoring (DnsQuery_A/W)
        try:
            res = subprocess.run(['ipconfig', '/displaydns'], capture_output=True, text=True, timeout=10)
            for line in res.stdout.splitlines():
                line = line.strip()
                if 'Record Name' in line:
                    domain = line.split(':', 1)[-1].strip().lower()
                    if domain and domain not in known_dns:
                        known_dns.add(domain)
                        
                        # Check for DGA-like domains (long random strings)
                        is_dga = False
                        parts = domain.split('.')
                        if len(parts) >= 2:
                            name_part = parts[0]
                            if len(name_part) > 15 and sum(1 for c in name_part if c.isdigit()) > len(name_part) * 0.3:
                                is_dga = True
                        
                        verdict = "SUSPICIOUS" if is_dga else "CLEAN"
                        stream_log("FR-DYN-06", "DNS_QUERY", {
                            "pid": 0,
                            "process_name": "dns_cache",
                            "protocol": "DNS",
                            "dst_ip": "0.0.0.0",
                            "dst_port": 53,
                            "direction": "OUTBOUND",
                            "detail": f"DNS resolution for: {domain}",
                            "domain": domain,
                            "is_dga_suspect": is_dga,
                            "is_notable": is_dga,
                            "verdict": verdict
                        })
        except Exception:
            pass

# ==========================================
# MODULE: FR-DYN-01 & 02 (Kernel Log Parsing)
# ==========================================
import hashlib
import math

pid_elevation_cache = {}

def calculate_entropy(path):
    if not os.path.exists(path):
        return 0.0
    try:
        total_size = os.path.getsize(path)
        if total_size == 0:
            return 0.0
        counts = {}
        with open(path, 'rb') as f:
            while True:
                buf = f.read(65536)
                if not buf:
                    break
                for b in buf:
                    counts[b] = counts.get(b, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / total_size
            entropy -= p * math.log2(p)
        return round(entropy, 2)
    except Exception:
        return 0.0

def is_pid_elevated(pid):
    try:
        pid = int(pid)
    except ValueError:
        return True
        
    if pid in pid_elevation_cache:
        return pid_elevation_cache[pid]
    
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        
        TOKEN_QUERY = 0x0008
        TokenElevation = 20
        
        h_proc = kernel32.OpenProcess(0x0400, False, pid)
        if not h_proc:
            pid_elevation_cache[pid] = True
            return True
        
        h_token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(h_proc, TOKEN_QUERY, ctypes.byref(h_token)):
            kernel32.CloseHandle(h_proc)
            pid_elevation_cache[pid] = True
            return True
            
        elevation = ctypes.c_ulong()
        size = ctypes.c_ulong()
        res = advapi32.GetTokenInformation(h_token, TokenElevation, ctypes.byref(elevation), 4, ctypes.byref(size))
        
        kernel32.CloseHandle(h_token)
        kernel32.CloseHandle(h_proc)
        
        is_el = (elevation.value != 0) if res else True
        pid_elevation_cache[pid] = is_el
        return is_el
    except Exception:
        pid_elevation_cache[pid] = True
        return True

def get_file_info(path):
    if not os.path.exists(path):
        return 0, 0.0
    try:
        size = os.path.getsize(path)
        entropy = calculate_entropy(path)
        return size, entropy
    except Exception:
        return 0, 0.0

def check_dll_signature(path):
    if not os.path.exists(path):
        return "UNSIGNED"
    try:
        res = subprocess.run([
            "powershell", "-Command",
            f"(Get-AuthenticodeSignature '{path}').Status"
        ], capture_output=True, text=True)
        status = res.stdout.strip()
        return "SIGNED" if status == "Valid" else "UNSIGNED"
    except Exception:
        return "UNSIGNED"

def get_sha256(path):
    if not os.path.exists(path):
        return "N/A"
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "N/A"

def parse_kernel_logs(mode="detonate"):
    """Parses ProcMon CSV to extract filesystem, registry, memory, and network mutations.
    
    Uses a two-pass approach:
      Pass 1: Build the complete process tree from Process Create events. Start from the
              root sample PID and walk the tree to discover ALL descendant PIDs. Also
              include system service processes (like msiexec.exe) whose command lines
              reference the sample path or temp installer paths.
      Pass 2: Re-scan the CSV with the expanded PID set to capture all file, registry,
              network, DLL, and process events from the full tree.
    """
    if not os.path.exists(CSV_LOG):
        stream_log("SYSTEM", "ERROR", "ProcMon CSV not found.")
        return

    created_exes = []

    with tracking_lock:
        root_pids = set(tracked_pids)

    stream_log("SYSTEM", "INFO", "Pass 1: Building complete process tree from kernel traces...")

    # ── PASS 1: Build full process tree ──────────────────────────────────
    # parent_pid -> set of child PIDs
    child_map = {}   # str(ppid) -> set(str(child_pid))
    # pid -> command line (for service-process matching)
    pid_cmdlines = {}  # str(pid) -> command_line
    # pid -> process name
    pid_names = {}  # str(pid) -> process_name

    

    sample_basename = os.path.basename(TARGET_EXE).lower()

    try:
        with open(CSV_LOG, mode='r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            next(reader, None)  # skip header

            for row in reader:
                if len(row) < 7:
                    continue
                _time, proc_name, pid, op, path, res, detail = row

                if proc_name.lower() in ("python.exe", "procmon.exe", "procmon64.exe"):
                    continue

                pid_names[pid] = proc_name

                if op in ("Process Create", "Process Start", "Thread Create", "Thread Start"):
                    child_pid_str = ""
                    cmd_line = ""
                    pid_match = re.search(r"PID:\s*(\d+)", detail)
                    if pid_match:
                        child_pid_str = pid_match.group(1)
                    cmd_match = re.search(r"Command Line:\s*(.*)", detail)
                    if cmd_match:
                        cmd_line = cmd_match.group(1).strip()

                    if child_pid_str:
                        child_map.setdefault(pid, set()).add(child_pid_str)
                        pid_cmdlines[child_pid_str] = cmd_line
                        child_name = os.path.basename(path) if path else "Unknown"
                        pid_names.setdefault(child_pid_str, child_name)

    except Exception as e:
        stream_log("SYSTEM", "ERROR", f"Pass 1 CSV read failed: {e}")
        return

    # Walk the tree from root PIDs to find all descendants
    expanded_pids = set(root_pids)
    queue = list(root_pids)
    while queue:
        current = queue.pop(0)
        for child in child_map.get(current, set()):
            if child not in expanded_pids:
                expanded_pids.add(child)
                queue.append(child)

    # In auto-install mode or as fallback, scan all processes to find installer-related ones
    # (e.g., msiexec.exe, setup.exe, install.exe, anything referencing temp or the sample)
    for pid_str, proc_name in pid_names.items():
        p_lower = proc_name.lower()
        cmdline = pid_cmdlines.get(pid_str, "").lower()
        
        is_installer_process = False
        if p_lower in ("msiexec.exe", "setup.exe", "install.exe") or "msiexec" in cmdline or "setup" in cmdline or "install" in cmdline or "temp" in cmdline:
            is_installer_process = True
        elif sample_basename in cmdline or "sample.exe" in cmdline:
            is_installer_process = True
            
        if is_installer_process and pid_str not in expanded_pids:
            expanded_pids.add(pid_str)
            # Also recursively add all children of this process
            sub_queue = [pid_str]
            while sub_queue:
                cur = sub_queue.pop(0)
                for child in child_map.get(cur, set()):
                    if child not in expanded_pids:
                        expanded_pids.add(child)
                        sub_queue.append(child)

    stream_log("SYSTEM", "INFO",
               f"Pass 1 complete: {len(expanded_pids)} PIDs in process tree "
               f"(root: {len(root_pids)}, discovered: {len(expanded_pids) - len(root_pids)})")

    # Update global tracked_pids for other modules
    with tracking_lock:
        tracked_pids.update(expanded_pids)

    # ── PASS 2: Parse events with expanded PID set ───────────────────────
    stream_log("SYSTEM", "INFO", "Pass 2: Extracting filesystem, registry, and behavioral events...")

    # Acceptable result codes — SUCCESS is primary, but some operations produce
    # meaningful non-SUCCESS results that should still be captured
    ACCEPTABLE_RESULTS = {"SUCCESS", "BUFFER OVERFLOW", "BUFFER TOO SMALL"}

    try:
        with open(CSV_LOG, mode='r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            next(reader, None)

            for row in reader:
                if len(row) < 7:
                    continue
                time_str, proc_name, pid, op, path, res, detail = row

                if proc_name.lower() in ("python.exe", "procmon.exe", "procmon64.exe"):
                    continue

                if pid not in expanded_pids:
                    continue

                # For write/mutation operations, accept SUCCESS and buffer-related results
                # For read/query operations that we check for evasion, also accept SUCCESS
                if res not in ACCEPTABLE_RESULTS:
                    continue

                is_elev = is_pid_elevated(pid)

                # Anti-Analysis Checks (FR-DYN-07)
                lower_p = path.lower()
                is_evasion = False
                ev_indicator = ""
                ev_detail = ""

                if any(x in lower_p for x in ("vmtoolsd.exe", "vboxhook.dll", "vboxmrxnp.dll", "vboxguest", "vboxservice", "vboxcontrol", "vboxtray")):
                    is_evasion = True
                    ev_indicator = "Virtualization files detection query"
                    ev_detail = f"Process {proc_name} queried file: {path}"
                elif any(x in lower_p for x in ("hardware\\acpi\\dsdt", "hardware\\description\\system\\bios", "services\\vbox", "services\\vmtools", "services\\vmware")):
                    is_evasion = True
                    ev_indicator = "Virtualization registry detection query"
                    ev_detail = f"Process {proc_name} queried Registry Key: {path}"

                if is_evasion:
                    stream_log("FR-DYN-07", "ANTI_ANALYSIS", {
                        "timestamp": time_str,
                        "tag": "FR-DYN-07",
                        "event_type": "ANTI_ANALYSIS",
                        "pid": int(pid),
                        "process_name": proc_name,
                        "check_type": "VIRTUALIZATION_CHECK",
                        "indicator": ev_indicator,
                        "detail": ev_detail,
                        "is_notable": True,
                        "verdict": "SUSPICIOUS"
                    })

                
                CRITICAL_SECURITY_PATHS = [
                    "system32\\drivers\\etc\\hosts",       # DNS/hosts hijacking
                    "system32\\config\\",                   # Registry hives (SAM, SYSTEM, SECURITY)
                    "system32\\lsass.exe",                  # LSASS binary manipulation
                    "authorized_keys",                      # SSH unauthorized backdoor
                    "microsoft\\windows\\start menu\\programs\\startup", # Persistence
                    "microsoft\\windows\\start menu\\programs\\startup", # Classic persistence
                    ]

                SUSPICIOUS_DIRECTORIES = ["appdata\\local\\temp", "system32\\drivers", "programdata","users\\public"]
                EXECUTABLE_EXTENSIONS = (".exe", ".dll", ".sys", ".bat", ".vbs", ".ps1", ".scr")
                RUN_KEYS = ("software\\microsoft\\windows\\currentversion\\run", "software\\microsoft\\windows\\currentversion\\runonce")
                SERVICE_KEYS = ("system\\currentcontrolset\\services", "system\\controlset001\\services")
                COM_HIJACK_KEYS = ("software\\classes\\clsid", "software\\classes\\interface")
                IMAGE_HIJACK_KEYS = "software\\microsoft\\windows nt\\currentversion\\image file execution options"
                WINLOGON_KEYS = "software\\microsoft\\windows nt\\currentversion\\winlogon"

                SUSPICIOUS_EXEC_PATHS = ["appdata\\local\\temp", "users\\public", "programdata", "windows\\tasks"]
                SHELL_PROCESSES = ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe")

                SUSPICIOUS_DLL_PATHS = ["appdata", "temp", "users\\public", "programdata", "windows\\tasks"]

                # --- Comprehensive Network Threat Hunting Profiles ---
                SUSPICIOUS_PORTS = {
                    4444, 8080, 8888, 9999,  # Metasploit, Cobalt Strike, Netcat defaults
                    6667, 6697,        # IRC Botnets (C2 channels)
                    1337, 31337,       # Traditional/Exploit kit default ports
                    22, 23, 3389, 5985 # Core Remote management (Notable if used by non-admin utilities)
                    }
                
                # Processes that have no business interacting with network sockets
                SYSTEM_ISOLATED_PROCESSES = ("calc.exe", "notepad.exe", "lsass.exe", "spoolsv.exe",
                "taskhostw.exe", "werfault.exe", "winlogon.exe", "critical_agent.exe")
                
                # Common scripting/shell utilities used in Living-off-the-Land (LotL) attacks
                LOTL_INTERPRETERS = ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "scrcons.exe")

                
                # 1. Filesystem Mutations (FR-DYN-01)
                if op in ("WriteFile", "SetEndOfFile","SetEndOfFileInformation", "SetAllocationInformation", "SetBasicInformationFile", "SetSecurityInformation"):
                    size, entropy = get_file_info(path)

                    is_notable = False
                    verdict = "CLEAN"
                    if "vssadmin" in lower_p or "\\\\.\\physicaldrive" in lower_p:
                        is_notable = True
                        verdict = "CRITICAL"
                    elif op in ("SetAllocationInformation", "SetBasicInformationFile"):
                        is_notable = True
                        verdict = "SUSPICIOUS"
                    elif op == "SetSecurityInformation":
                        is_notable = True
                        verdict = "CRITICAL"
                    elif any(crit_path in lower_p for crit_path in CRITICAL_SECURITY_PATHS):
                        is_notable = True
                        verdict = "CRITICAL"
                    # PARAMETER: Hidden File Attribute Toggling
                    elif "Attributes:" in detail and any(attr in detail for attr in ["H", "S"]):  # Hidden or System attributes
                        is_notable = True
                        verdict = "SUSPICIOUS"


                    stream_log("FR-DYN-01", "FILE_MODIFIED", {
                        "timestamp": time_str,
                        "tag": "FR-DYN-01",
                        "event_type": "FILE_MODIFIED",
                        "pid": int(pid),
                        "process_name": proc_name,
                        "target_path": path,
                        "entropy": entropy,
                        "size_bytes": size,
                        "is_elevated": is_elev,
                        "is_notable": is_notable,
                        "verdict": verdict
                    })
                elif op == "CreateFile":
                    size = 0
                    entropy = 0.0

                    is_created = any(x in detail for x in ["Disposition: Create", "Disposition: New", "OpenResult: Created"])
                    is_overwritten = any(x in detail for x in ["Disposition: Overwrite", "Disposition: OverwriteIf", "OpenResult: Overwritten"])

                    has_ads = ":" in os.path.basename(path) and not path.startswith("\\\\")

                    if is_created or is_overwritten or has_ads:
                        size, entropy = get_file_info(path)
                        if path.lower().endswith(".exe") and path not in created_exes:
                            created_exes.append(path)
                    
                    is_notable = False
                    verdict = "CLEAN"
                    ext = os.path.splitext(path)[1].lower()
                    
                    event_tag = "FILE_CREATED" if is_created else "FILE_OVERWRITTEN"
                    if has_ads:
                        event_tag = "FILE_ADS_DETECTED"
                        is_notable = True
                        verdict = "CRITICAL"
                    
                    # PARAMETER: Execute Access validation (Process trying to write AND execute out of unmapped zones)
                    has_execute_access = "Desired Access: Execute" in detail or "Generic Execute" in detail

                    if ext in EXECUTABLE_EXTENSIONS or has_execute_access:
                        if any(susp_dir in lower_p for susp_dir in SUSPICIOUS_DIRECTORIES):
                            is_notable = True
                            verdict = "SUSPICIOUS"
                    
                    if any(crit_path in lower_p for crit_path in CRITICAL_SECURITY_PATHS):
                        is_notable = True
                        verdict = "CRITICAL"
                    

                    stream_log("FR-DYN-01", event_tag, {
                        "timestamp": time_str,
                        "tag": "FR-DYN-01",
                        "event_type": event_tag,
                        "pid": int(pid),
                        "process_name": proc_name,
                        "target_path": path,
                        "entropy": entropy,
                        "size_bytes": size,
                        "is_elevated": is_elev,
                        "is_notable": is_notable,
                        "verdict": verdict
                    })
                
                elif (op == "SetDispositionInformationFile" and "Delete: True" in detail) or (op == "CreateFile" and "Options: Delete On Close" in detail):
                    is_notable = False
                    verdict = "CLEAN"

                        # PARAMETER: Identify if the target was a high value security file
                    if any(crit_path in lower_p for crit_path in CRITICAL_SECURITY_PATHS):
                        is_notable = True
                        verdict = "CRITICAL"

                        # PARAMETER: Detect self-deleting malware techniques or log scrubbing in temp directories
                    elif lower_p.endswith(EXECUTABLE_EXTENSIONS) and "appdata" in lower_p:
                        is_notable = True
                        verdict = "SUSPICIOUS"
                    

                    stream_log("FR-DYN-01", "FILE_DELETED", {
                        "timestamp": time_str,
                        "tag": "FR-DYN-01",
                        "event_type": "FILE_DELETED",
                        "pid": int(pid),
                        "process_name": proc_name,
                        "target_path": path,
                        "is_elevated": is_elev,
                        "is_notable": is_notable,
                        "verdict": verdict
                    })
                elif op == "SetRenameInformationFile":
                    size = 0
                    entropy = 0.0
                    
                    dest_path = path
                    dest_match = re.search(r"FileName:\s*([^\s,]+)", detail)
                    
                    if dest_match:
                        dest_path = dest_match.group(1).strip()
                        size, entropy = get_file_info(dest_path)
                    
                    is_notable = False
                    verdict = "CLEAN"
                    dest_lower = dest_path.lower()
                    
                    # PARAMETER: Detect Masquerading/Extension spoofing (e.g., calc.txt -> calc.exe)
                    orig_ext = os.path.splitext(path)[1].lower()
                    dest_ext = os.path.splitext(dest_path)[1].lower()
                    
                    if orig_ext != dest_ext and dest_ext in EXECUTABLE_EXTENSIONS:
                        is_notable = True
                        verdict = "CRITICAL"  # High fidelity indicator of payload shifting
                        
                    
                    # PARAMETER: Target directory shift detection
                    elif any(crit_path in dest_lower for crit_path in CRITICAL_SECURITY_PATHS):
                        is_notable = True
                        verdict = "CRITICAL"

                    stream_log("FR-DYN-01", "FILE_RENAMED", {
                        "timestamp": time_str,
                        "tag": "FR-DYN-01",
                        "event_type": "FILE_RENAMED",
                        "pid": int(pid),
                        "process_name": proc_name,
                        "target_path": dest_path,
                        "previous_path": path,
                        "entropy": entropy,
                        "size_bytes": size,
                        "is_elevated": is_elev,
                        "is_notable": is_notable,
                        "verdict": verdict
                    })

                # 2. Registry Mutations (FR-DYN-02)
                elif op == "RegSetValue":
                    key_path, value_name = os.path.split(path)
                    val_type = "REG_SZ"
                    val_data = ""

                        # Capture all possible parameter fields from Procmon's Detail column
                    type_match = re.search(r"Type:\s*([^\s,]+)", detail)
                    if type_match:
                        val_type = type_match.group(1).strip()
                    data_match = re.search(r"Data:\s*(.*)", detail)
                    if data_match:
                        val_data = data_match.group(1).strip()

                    is_notable = False
                    verdict = "CLEAN"
                    lower_val = value_name.lower()

                    if lower_val in ("disableantispyware", "disablerealtimemonitoring", "disablebehaviormonitoring") and "1" in val_data:
                        is_notable = True
                        verdict = "CRITICAL"
                    elif lower_val in ("disabletaskmgr", "disableregistrytools") and "1" in val_data:
                        is_notable = True
                        verdict = "CRITICAL"
                    elif lower_val == "enablelua" and "0" in val_data:
                        is_notable = True
                        verdict = "CRITICAL"
                    # Parameter Analysis: Disabling Windows Update / Safeboot modifications
                    elif "wuauserv" in lower_p and "start" in lower_val and "4" in val_data: # Disabled State
                        is_notable = True
                        verdict = "CRITICAL"

                    stream_log("FR-DYN-02", "REG_WRITE", {
                        "timestamp": time_str,
                        "tag": "FR-DYN-02",
                        "event_type": "REG_WRITE",
                        "pid": int(pid),
                        "process_name": proc_name,
                        "key_path": key_path,
                        "value_name": value_name,
                        "value_type": val_type,
                        "value_data": val_data,
                        "is_notable": is_notable,
                        "verdict": verdict
                    })

                    # 3. Persistence Registry Tripwire (FR-DYN-03)
                    if any(rk in lower_p for rk in RUN_KEYS):
                        stream_log("FR-DYN-03", "PERSISTENCE_CREATE", {
                            "timestamp": time_str, 
                            "tag": "FR-DYN-03", 
                            "event_type": "PERSISTENCE_CREATE",
                            "pid": int(pid), 
                            "process_name": proc_name, 
                            "category": "registry_run",
                            "mechanism": "Run Key Modification", 
                            "target_path": path, 
                            "command": val_data,
                            "is_notable": True, 
                            "verdict": "SUSPICIOUS"
                            })

                    elif any(sk in lower_p for sk in SERVICE_KEYS):
                        stream_log("FR-DYN-03", "PERSISTENCE_CREATE", {
                            "timestamp": time_str, 
                            "tag": "FR-DYN-03", 
                            "event_type": "PERSISTENCE_CREATE",
                            "pid": int(pid), 
                            "process_name": proc_name, 
                            "category": "windows_service",
                            "mechanism": "Windows Service Registration", 
                            "target_path": path, 
                            "command": val_data,
                            "is_notable": True, 
                            "verdict": "SUSPICIOUS"
                            })
                    
                    elif COM_HIJACK_KEYS[0] in lower_p and "inprocserver32" in lower_p:
                        stream_log("FR-DYN-03", "PERSISTENCE_CREATE", {
                            "timestamp": time_str, 
                            "tag": "FR-DYN-03", 
                            "event_type": "PERSISTENCE_CREATE",
                            "pid": int(pid), 
                            "process_name": proc_name, 
                            "category": "com_hijack",
                            "mechanism": "COM Object Server Override", 
                            "target_path": path, 
                            "command": val_data,
                            "is_notable": True, 
                            "verdict": "HIGH RISK"
                            })

                    elif IMAGE_HIJACK_KEYS in lower_p and lower_val == "debugger":
                        stream_log("FR-DYN-03", "PERSISTENCE_CREATE", {
                            "timestamp": time_str, 
                            "tag": "FR-DYN-03", 
                            "event_type": "PERSISTENCE_CREATE",
                            "pid": int(pid), 
                            "process_name": proc_name, 
                            "category": "ifeo_hijack",
                            "mechanism": "Image File Execution Options Debugger Hook", 
                            "target_path": path, 
                            "command": val_data,
                            "is_notable": True, 
                            "verdict": "CRITICAL"
                            })

                elif op == "RegCreateKey":
                    is_created_new = "REG_CREATED_NEW_KEY" in detail
                    is_notable = False
                    verdict = "CLEAN"
                    
                    # Parameter Analysis: Capturing Desired Access permissions
                    # Look for Keys created requesting administrative control or configuration rights
                    
                    has_write_access = any(x in detail for x in ["Desired Access: Write", "All Access", "Maximum Allowed"])
                    
                    if is_created_new and (IMAGE_HIJACK_KEYS in lower_p or WINLOGON_KEYS in lower_p):
                        is_notable = True
                        verdict = "CRITICAL"
                    
                    stream_log("FR-DYN-02", "REG_CREATED", {
                        "timestamp": time_str,
                        "tag": "FR-DYN-02",
                        "event_type": "REG_CREATED",
                        "pid": int(pid),
                        "process_name": proc_name,
                        "key_path": path,
                        "is_newly_spawned": is_created_new,
                        "is_notable": is_notable,
                        "verdict": verdict
                        })

                # 4. REGISTRY DISCOVERY & RECONNAISSANCE QUERIES
                elif op in ("RegQueryValue", "RegEnumValue", "RegOpenKey", "RegQueryKeySecurity"):
                    is_notable = False
                    verdict = "CLEAN"

                    if op == "RegSetKeySecurity":
                        is_notable = True
                        verdict = "SUSPICIOUS"
                    
                    # Parameter Analysis: Query Length and Result State
                    # # Attackers often parse length bounds or look for error codes like "NAME NOT FOUND" to check if defenses exist
                    is_not_found = "NAME NOT FOUND" in detail
                    
                    # Security Recon checking: Untrusted processes aggressively scanning system security controls
                    if any(def_val in lower_p for def_val in ["disableantispyware", "real-time protection", "windows defender"]):
                        if proc_name.lower() not in ("services.exe", "msmpeng.exe", "explorer.exe"):
                            is_notable = True
                            verdict = "SUSPICIOUS"  # Discovery activity mapping
                    
                    stream_log("FR-DYN-02", "REG_QUERY", {
                        "timestamp": time_str,
                        "tag": "FR-DYN-02",
                        "event_type": "REG_QUERY",
                        "pid": int(pid),
                        "process_name": proc_name,
                        "key_path": path,
                        "query_operation": op,
                        "is_missing": is_not_found,
                        "is_notable": is_notable,
                        "verdict": verdict
                        })
                    
                    # 5. REGISTRY DELETIONS & SECURITY ALTERATIONS
                elif op in ("RegDeleteKey", "RegDeleteValue", "RegSetKeySecurity"):

                    is_notable = False
                    verdict = "CLEAN"
                    event_type = "REG_DELETED"
                    
                    # Parameter Analysis: Detect Permission Tampering vs Direct Elimination
                    if op == "RegSetKeySecurity":
                        event_type = "REG_SECURITY_MODIFIED"
                        is_notable = True
                        verdict = "CRITICAL"  # Changing ownership or DACL objects on registry key

                    # Check if the deleted path was a critical persistence hook or security marker
                    else:
                        if any(rk in lower_p for rk in RUN_KEYS) or "services" in lower_p:
                            is_notable = True
                            verdict = "SUSPICIOUS"
                    
                    stream_log("FR-DYN-02", event_type, {
                        "timestamp": time_str,
                        "tag": "FR-DYN-02",
                        "event_type": event_type,
                        "pid": int(pid),
                        "process_name": proc_name,
                        "key_path": path,
                        "is_notable": is_notable,
                        "verdict": verdict
                        })

                # 4. Process monitoring (FR-DYN-04)
                # 1. PROCESS SPRAWL AND CREATION
                
                if op == "Process Create":
                    child_pid = 0
                    cmd_line = ""
                    
                    # Capture all possible parameter fields from Procmon's Detail column
                    pid_match = re.search(r"PID:\s*(\d+)", detail)
                    if pid_match:
                        child_pid = int(pid_match.group(1))
                    
                    cmd_match = re.search(r"Command Line:\s*(.*)", detail)
                    if cmd_match:
                        cmd_line = cmd_match.group(1).strip()
                    
                    # Extract advanced Procmon properties
                    parent_pid_match = re.search(r"Parent PID:\s*(\d+)", detail)
                    ppid = int(parent_pid_match.group(1)) if parent_pid_match else int(pid)
                    
                    # Procmon Token Properties: e.g., Integrity: Medium, Integrity: High, or Elevated: True
                    token_integrity = "Medium"
                    if "Integrity: High" in detail or "Integrity: System" in detail:
                        token_integrity = "High/System"
                    elif "Integrity: Low" in detail:
                        token_integrity = "Low"
                    
                    proc_basename = os.path.basename(path)
                    verdict = _classify_process_verdict(cmd_line, proc_basename)
                    is_notable = verdict != "CLEAN"
                    
                    # Parameter Analysis: Execution out of unmapped or user-writable paths
                    if not is_notable and any(susp_path in path.lower() for susp_path in SUSPICIOUS_EXEC_PATHS):
                        is_notable = True
                        verdict = "SUSPICIOUS"
                    
                    # Parameter Analysis: Defensive evasion checks (e.g., LSASS dumping via taskmgr or comsvcs)
                    elif "lsass" in cmd_line.lower() and proc_basename.lower() in ("rundll32.exe", "comsvcs.dll", "taskmgr.exe"):
                        is_notable = True
                        verdict = "CRITICAL"
                    
                    # Parameter Analysis: Living off the Land (LotL) Binary spawned by a web server or script host
                    elif proc_basename.lower() in SHELL_PROCESSES and proc_name.lower() in ("w3wp.exe", "nginx.exe", "httpd.exe", "sqlservr.exe"):
                        is_notable = True
                        verdict = "CRITICAL"  # High-fidelity indicator of a web shell execution
                        
                    stream_log("FR-DYN-04", "PROCESS_SPAWN", {
                        "timestamp": time_str,
                        "tag": "FR-DYN-04",
                        "event_type": "PROCESS_SPAWN",
                        "pid": child_pid,
                        "ppid": ppid,
                        "process_name": proc_basename,
                        "command_line": cmd_line,
                        "integrity_level": token_integrity,
                        "is_notable": is_notable,
                        "verdict": verdict
                        })
                
                elif op == "Thread Create":
                    is_notable = False
                    verdict = "CLEAN"
                    target_pid = 0
                    
                    # Procmon Parameter Details identify cross-process targets: e.g., "Target PID: 432"
                    target_pid_match = re.search(r"Target PID:\s*(\d+)", detail)
                    
                    if target_pid_match:
                        target_pid = int(target_pid_match.group(1))
                        # If the issuing PID does not match the target PID, it's a Remote Thread Creation
                        if target_pid != int(pid):
                            is_notable = True
                            verdict = "CRITICAL"  # High indicators of Process Hollowing or DLL Injection
                    
                    stream_log("FR-DYN-04", "CROSS_PROCESS_INJECTION", {
                        "timestamp": time_str,
                        "tag": "FR-DYN-04",
                        "event_type": "REMOTE_THREAD_CREATE",
                        "source_pid": int(pid),
                        "source_process": proc_name,
                        "target_pid": target_pid,
                        "is_notable": is_notable,
                        "verdict": verdict
                        })
                
                # 4. PROCESS TERMINATIONS & LIFECYCLE CLOSURE
                elif op == "Process Exit":
                    # Capture exit status codes from Procmon (e.g., "Exit Status: 0" vs crash/termination codes)
                    
                    exit_status = 0
                    status_match = re.search(r"Exit Status:\s*(-?\d+)", detail)
                    if status_match:
                        exit_status = int(status_match.group(1))
                    
                    # Check if a critical agent or security process was forcefully shut down
                    is_notable = False
                    verdict = "CLEAN"
                    
                    if any(fw_proc in proc_name.lower() for fw_proc in ["msmpeng", "cbdaemon", "edragent", "cybereason"]):
                        if exit_status != 0:  # Terminated abnormally or killed
                            is_notable = True
                            verdict = "CRITICAL"
                    
                    stream_log("FR-DYN-04", "PROCESS_EXIT", {
                        "timestamp": time_str,
                        "tag": "FR-DYN-04",
                        "event_type": "PROCESS_EXIT",
                        "pid": int(pid),
                        "process_name": proc_name,
                        "exit_code": exit_status,
                        "is_notable": is_notable,
                        "verdict": verdict
                        })

                # 5. Memory / DLL loading (FR-DYN-05)
                if (op == "CreateFile" and ("Disposition: Create" in detail or "Disposition: New" in detail or "OpenResult: Created" in detail)) or (op == "WriteFile"):
                    if path.lower().endswith(".dll"):
                        sig = check_dll_signature(path)
                        sha = get_sha256(path)
                        risk_indicators = ["DLL dropped on filesystem"]
                        is_notable = False
                        verdict = "CLEAN"
                        
                        if sig == "UNSIGNED":
                            risk_indicators.append("Unsigned binary drop")
                            is_notable = True
                            verdict = "SUSPICIOUS"
                        
                        if any(susp_path in path.lower() for susp_path in SUSPICIOUS_DLL_PATHS):
                            risk_indicators.append("Dropped in userland/temp directory")
                            is_notable = True
                            verdict = "SUSPICIOUS"
                        
                    stream_log("FR-DYN-05", "DLL_DROPPED", {
                        "timestamp": time_str,
                        "tag": "FR-DYN-05",
                        "event_type": "DLL_DROPPED",
                        "pid": int(pid),
                        "process_name": proc_name,
                        "dll_name": os.path.basename(path),
                        "dll_path": path,
                        "signature_status": sig,
                        "sha256": sha,
                        "risk_indicators": risk_indicators,
                        "is_notable": is_notable,
                        "verdict": verdict
                        })
                
                # CAPTURE RUNTIME DLL EXECUTIONS (Loaded into Memory)
                
                elif op == "Load Image" and path.lower().endswith(".dll"):
                    sig = check_dll_signature(path)
                    sha = get_sha256(path)
                    risk_indicators = ["DLL loaded into memory"]
                    is_notable = False
                    verdict = "CLEAN"
                    
                    # Check for Unsigned Loading
                    
                    if sig == "UNSIGNED":
                        risk_indicators.append("Unsigned binary execution")
                        is_notable = True
                        verdict = "SUSPICIOUS"
                    
                    # Check for Loading from Hostile Environments
                    if any(susp_path in path.lower() for susp_path in SUSPICIOUS_DLL_PATHS):
                        risk_indicators.append("Loaded from unmapped userland/temp directory")
                        is_notable = True
                        verdict = "SUSPICIOUS"
                    
                    # DETECT DLL HIJACKING: Legitimate Windows processes loading non-system DLLs
                    is_system_proc = any(sys_p in proc_name.lower() for sys_p in ["svchost.exe", "explorer.exe", "cmd.exe", "powershell.exe"])
                    is_system_dll = "system32" in path.lower() or "syswow64" in path.lower() or "winsxs" in path.lower()
                    
                    if is_system_proc and not is_system_dll:
                        risk_indicators.append("Potential DLL Search Order Hijack (System process loading userland DLL)")
                        is_notable = True
                        verdict = "HIGH RISK"
                        
                    stream_log("FR-DYN-05", "DLL_LOAD", {
                        "timestamp": time_str,
                        "tag": "FR-DYN-05",
                        "event_type": "DLL_LOAD",
                        "pid": int(pid),
                        "process_name": proc_name,
                        "dll_name": os.path.basename(path),
                        "dll_path": path,
                        "signature_status": sig,
                        "sha256": sha,
                        "risk_indicators": risk_indicators,
                        "is_notable": is_notable,
                        "verdict": verdict
                        })

                # 6. Network / Winsock Sockets (FR-DYN-06)
                # Match all possible network telemetry events generated by Procmon
                
                if op.startswith(("TCP", "UDP")):
                    # Default variables initialization
                    
                    src_ip, src_port = "0.0.0.0", 0
                    dst_ip, dst_port = "0.0.0.0", 0
                    direction = "OUTBOUND"
                    packet_length = 0
                    
                    # 1. Parse Procmon directional path formatting: "local_host:port -> remote_host:port"
                    if "->" in path:
                        try:
                            local_side, remote_side = path.split("->")
                            local_side = local_side.strip()
                            remote_side = remote_side.strip()
                            
                            if ":" in local_side:            
                                parts_src = local_side.rsplit(":", 1)
                                src_ip = parts_src[0].strip("[]") # Strip brackets if parsing IPv6
                                src_port = int(parts_src[1])
                                
                                # Safely split remote (Destination) details
                            if ":" in remote_side:
                                parts_dst = remote_side.rsplit(":", 1)
                                dst_ip = parts_dst[0].strip("[]")
                                dst_port = int(parts_dst[1])
                        
                        except (ValueError, IndexError):
                            dst_ip = path
                    
                    # 2. Extract advanced packet metrics from Procmon's Detail column 
                    # (Extracts properties like: "Length: 1024, seqNum: ...")
                    len_match = re.search(r"Length:\s*(\d+)", detail)
                    if len_match:
                        packet_length = int(len_match.group(1))
                    
                    # 3. Dynamic Lifecycle Directionality Mapping
                    if "Receive" in op or "Accept" in op:
                        direction = "INBOUND"
                    
                    is_notable = False
                    verdict = "CLEAN"
                    risk_indicators = []
                    proc_lower = proc_name.lower()
                    
                    # Heuristic Rule A: Outbound calls to suspicious default malicious infrastructure ports
                    if dst_port in SUSPICIOUS_PORTS and direction == "OUTBOUND":
                        is_notable = True
                        verdict = "SUSPICIOUS"
                        risk_indicators.append(f"Connection attempt to high-fidelity target threat port: {dst_port}")
                    
                    # Heuristic Rule B: Code injection / Local binary subversion tracking
                    if proc_lower in SYSTEM_ISOLATED_PROCESSES:
                        is_notable = True
                        verdict = "CRITICAL"
                        risk_indicators.append(f"System Isolated process spawned a raw network transaction")
                    
                    # Heuristic Rule C: Scripting engines or execution shells performing network tasks
                    if proc_lower in LOTL_INTERPRETERS:
                        if op in ("TCP Connect", "TCP Send") or (op == "UDP Send" and dst_port != 53):
                            is_notable = True
                            verdict = "HIGH RISK"
                            risk_indicators.append("Administrative script/command terminal making an outbound connection")
                    
                    # Heuristic Rule D: Exfiltration metric profiling (Flagging large chunks over data pipes)
                    if packet_length > 10485760 and op in ("TCP Send", "UDP Send"): # > 10MB individual buffer
                        is_notable = True
                        
                        if verdict != "CRITICAL": verdict = "SUSPICIOUS"
                        risk_indicators.append(f"High-volume data burst detected over single payload transaction ({packet_length} bytes)")
                    
                    # 4. Ship complete normalized telemetry record
                    
                    stream_log("FR-DYN-06", "NETWORK_ACTIVITY", {
                        "timestamp": time_str,
                        "tag": "FR-DYN-06",
                        "event_type": "NETWORK_ACTIVITY",
                        "pid": int(pid),
                        "process_name": proc_name,
                        "protocol": op.split()[0],            # Normalizes to 'TCP' or 'UDP'
                        "network_operation": op,              # Captures exact state ('TCP Connect', 'TCP Receive', 'UDP Send', etc.)
                        "direction": direction,
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "bytes_transferred": packet_length,
                        "risk_indicators": risk_indicators,
                        "is_notable": is_notable,
                        "verdict": verdict,
                        "raw_detail": detail                  # Kept for down-stream deeper inspection
                        })

    except Exception as e:
        stream_log("SYSTEM", "ERROR", f"Pass 2 CSV parse failed: {e}")

    # Drop the installed file on desktop in auto-install mode
    if mode == "auto-install" and created_exes:
        installed_path = None
        for f in created_exes:
            f_lower = f.lower()
            if "sample.exe" not in f_lower and "two_phase_agents" not in f_lower and "unified_agents" not in f_lower and "taskkill.exe" not in f_lower:
                installed_path = f
                break
        if installed_path and os.path.exists(installed_path):
            try:
                import shutil
                desktop_dir = f"C:\\Users\\{username}\\Desktop"
                dest_path = os.path.join(desktop_dir, os.path.basename(installed_path))
                shutil.copy2(installed_path, dest_path)
                stream_log("SYSTEM", "INFO", f"Successfully dropped installed file on desktop: {dest_path}")
            except Exception as copy_err:
                stream_log("SYSTEM", "WARNING", f"Failed to drop installed file on desktop: {copy_err}")

    stream_log("SYSTEM", "INFO", "Kernel trace parsing complete.")

def detect_installer_silent_flags(filepath):
    """Detects common installer types (Inno Setup, InstallShield, Wise, Nullsoft, MSI)
    and automatically returns the correct silent flags."""
    try:
        if not os.path.exists(filepath):
            return None, []
        
        ext = os.path.splitext(filepath)[1].lower()
        if ext == ".msi":
            return "MSI", ["/qn", "/norestart"]
            
        with open(filepath, "rb") as f:
            data = f.read(5 * 1024 * 1024) # Read up to 5MB
            
        if b"Inno Setup" in data or b"Inno" in data or b"Inno Setup Setup Instructions" in data:
            return "Inno Setup", ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"]
        elif b"NullsoftInst" in data or b"Nullsoft" in data:
            return "Nullsoft NSIS", ["/S"]
        elif b"InstallShield" in data:
            return "InstallShield", ["/s", "/v/qn"]
        elif b"Wise Installation System" in data or b"Wise Solutions" in data:
            return "Wise", ["/s"]
        elif b"WiX Toolset" in data or b"wixdepca" in data:
            return "WiX", ["/quiet", "/norestart"]
            
    except Exception as e:
        stream_log("SYSTEM", "WARNING", f"Installer detection error: {e}")
        
    return None, []

def get_window_pid(hwnd):
    try:
        import win32process
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        return pid
    except Exception:
        return 0

def click_button(hwnd_btn):
    try:
        import win32gui
        import win32con
        # Send BM_CLICK
        win32gui.SendMessage(hwnd_btn, win32con.BM_CLICK, 0, 0)
        # Fallback mouse events
        win32gui.PostMessage(hwnd_btn, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, 0)
        win32gui.PostMessage(hwnd_btn, win32con.WM_LBUTTONUP, 0, 0)
    except Exception:
        pass

def set_checkbox(hwnd_chk):
    try:
        import win32gui
        import win32con
        win32gui.SendMessage(hwnd_chk, win32con.BM_SETCHECK, win32con.BST_CHECKED, 0)
    except Exception:
        pass

# Background UI automation thread
ui_auto_active = True

def ui_automation_loop():
    global ui_auto_active
    stream_log("SYSTEM", "INFO", "UI Automation Fallback thread started.")
    while ui_auto_active and analysis_active:
        time.sleep(0.5)
        try:
            import win32gui
            win32gui.EnumWindows(enum_windows_callback, None)
        except Exception as e:
            print(f"[-] UI Automation loop error: {e}")

def enum_windows_callback(hwnd, extra):
    try:
        import win32gui
        import win32process
        import win32con
        
        if not win32gui.IsWindowVisible(hwnd) or not win32gui.IsWindowEnabled(hwnd):
            return True
            
        pid = get_window_pid(hwnd)
        if not pid:
            return True
            
        is_tracked = False
        with tracking_lock:
            if str(pid) in tracked_pids:
                is_tracked = True
            else:
                try:
                    p = psutil.Process(pid)
                    ppid = p.ppid()
                    if str(ppid) in tracked_pids:
                        tracked_pids.add(str(pid))
                        is_tracked = True
                except Exception:
                    pass
                    
        if not is_tracked:
            return True
            
        children = []
        def child_callback(ch_hwnd, ch_extra):
            children.append(ch_hwnd)
            return True
            
        try:
            win32gui.EnumChildWindows(hwnd, child_callback, None)
        except Exception:
            return True
            
        for child in children:
            try:
                class_name = win32gui.GetClassName(child).lower()
                length = win32gui.SendMessage(child, win32con.WM_GETTEXTLENGTH, 0, 0)
                buf = ctypes.create_unicode_buffer(length + 1)
                win32gui.SendMessage(child, win32con.WM_GETTEXT, length + 1, buf)
                text = buf.value.lower().strip()
            except Exception:
                continue
                
            if not text:
                continue
                
            if "button" in class_name:
                style = win32gui.GetWindowLong(child, win32con.GWL_STYLE)
                is_checkbox = (style & win32con.BS_CHECKBOX) or (style & win32con.BS_AUTOCHECKBOX)
                
                if is_checkbox:
                    if any(kw in text for kw in ["accept", "agree", "license", "terms", "i accept", "i agree"]):
                        state = win32gui.SendMessage(child, win32con.BM_GETCHECK, 0, 0)
                        if state != win32con.BST_CHECKED:
                            set_checkbox(child)
                            stream_log("UI_AUTO", "CHECKBOX", f"Automatically checked agreement checkbox: '{buf.value}'")
                else:
                    click_keywords = ["next", "install", "i accept", "i agree", "yes", "agree", "accept", "finish", "run", "close", "ok", "forward", "continue"]
                    ignore_keywords = ["cancel", "exit", "abort", "back", "< back"]
                    
                    if any(kw in text for kw in click_keywords) and not any(kw in text for kw in ignore_keywords):
                        click_button(child)
                        stream_log("UI_AUTO", "BUTTON_CLICK", f"Automatically clicked button: '{buf.value}'")
                        
    except Exception as e:
        print(f"[-] Error inside enum callback: {e}")
        
    return True

# ==========================================
# MASTER EXECUTION ORCHESTRATOR
# ==========================================
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Unified Sandbox Agent")
    parser.add_argument(
        "--timeout", type=int, default=ANALYSIS_TIMEOUT,
        help="Analysis monitoring window in seconds (default: %(default)s). "
             "Should be shorter than the host timeout to allow teardown."
    )
    parser.add_argument(
        "--mode", type=str, default="detonate",
        choices=["detonate", "auto-install"],
        help="Execution mode (detonate or auto-install)."
    )
    args = parser.parse_args()
    analysis_timeout = args.timeout
    mode = getattr(args, "mode", "detonate")

    stream_log("SYSTEM", "INIT", "Unified Agent Started. Setting up environment...")
    
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

    # 4. Start Monitoring Threads (all FR-DYN categories)
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

    # 3. Detonate Malware / Installer
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
            tracked_pids.add(str(proc.pid))
        stream_log("FR-DYN-04", "PROCESS_ROOT", f"PID: {proc.pid}")
    except Exception as e:
        stream_log("SYSTEM", "FATAL", f"Failed to execute target {cmd_args}: {e}")
        ui_auto_active = False
        sys.exit(1)

    # 5. Analysis Window
    try:
        stream_log("SYSTEM", "INFO", f"Analysis window open for {analysis_timeout}s...")
        time.sleep(analysis_timeout)
    except Exception as e:
        stream_log("SYSTEM", "ERROR", f"Agent monitoring loop encountered an exception: {e}")
    finally:
        # 6. Teardown & Forensics
        stream_log("SYSTEM", "INFO", "Analysis window closed. Halting active monitors...")
        ui_auto_active = False # Stop UI automation thread
        analysis_active = False # Signal threads to die
        
        # Run memory forensics before killing processes
        try:
            scan_memory()
        except Exception as e:
            stream_log("SYSTEM", "ERROR", f"Teardown: scan_memory failed: {e}")
        
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
        
        # 7. Post-Processing
        try:
            parse_kernel_logs(mode)
        except Exception as e:
            stream_log("SYSTEM", "ERROR", f"Teardown: parse_kernel_logs failed: {e}")
        
        stream_log("SYSTEM", "COMPLETE", "Agent teardown successful. Awaiting host shutdown.")
        if ser:
            try:
                ser.close()
            except Exception:
                pass
        time.sleep(3)