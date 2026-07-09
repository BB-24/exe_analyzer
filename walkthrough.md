# MARS Dual-VM Configuration Walkthrough

**Malware Analysis & Reverse-engineering System**
*VMware Workstation — Controller (VM A) + Sandbox (VM B)*

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  HOST MACHINE (Windows)                                         │
│                                                                 │
│  ┌─────────────────────────┐   ┌─────────────────────────────┐ │
│  │  VM A — Controller      │   │  VM B — Sandbox             │ │
│  │  Windows 10/11          │   │  Windows 10                 │ │
│  │                         │   │                             │ │
│  │  • MARS FastAPI Server  │   │  • Sample detonation        │ │
│  │  • Web Dashboard        │   │  • ProcMon kernel logger    │ │
│  │  • vmrun orchestration  │   │  • unified_agents.py /      │ │
│  │  • Scapy network sniffer│   │    two_phase_agents.py      │ │
│  │                         │   │  • COM1 serial telemetry    │ │
│  │                         │   │                             │ │
│  └──────────┬──────────────┘   └──────────────┬──────────────┘ │
│             │                                  │                │
│    ① VIX API (vmrun.exe)  ←──────────────────→│                │
│    ② Named Pipe  ←── COM1 Serial Telemetry ───→│                │
│    ③ Host-Only Network (vmnet1) ←── Traffic ──→│                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Three Communication Channels

| # | Channel | Direction | Purpose |
|---|---------|-----------|---------|
| ① | VMware VIX API (`vmrun.exe`) | A → B | Revert snapshots, copy files, execute programs |
| ② | Named Pipe / Serial Port | B → A | Out-of-band telemetry stream (filesystem, registry, process, memory events) |
| ③ | Host-Only Network (`vmnet1`) | B → A | Scapy packet sniffing (DNS, HTTP, TLS/SNI) |

---

## Prerequisites

### Host Machine

- VMware Workstation Pro **17+**
- At least **16 GB RAM** (8 GB for each VM)
- At least **150 GB free disk space**

### VM A — Controller

- Windows 10 or 11 (64-bit)
- Python **3.9 – 3.12** installed and on `PATH`
- Git (to clone the MARS repository)
- Administrator privileges

### VM B — Sandbox

- Windows 10 **22H2** (clean, licensed or eval ISO)
- Python **3.9** installed to `C:\Python39\` and on `PATH`
- ProcMon (Sysinternals Process Monitor)
- VMware Tools installed
- Administrator account named **Administrator** (matches `config.yaml`)
- No AV / Defender (will interfere with detonation)

---

## Part 1 — VMware Workstation Setup

### 1.1 Create VM B (Sandbox)

1. Open VMware Workstation → **File → New Virtual Machine**
2. Select **Custom (advanced)**
3. Hardware Compatibility: `Workstation 17.x`
4. Install from: your Windows 10 ISO
5. Set the guest OS to `Microsoft Windows → Windows 10 x64`
6. Name the VM: `Windows10_Sandbox`
7. Save it to: `D:\Virtual Machines\Windows10_Sandbox\` (or your preferred drive — update `vmx_path` in `config.yaml` to match)
8. Processors: `2 cores`, RAM: `4096 MB`, disk: `60 GB`
9. Finish the wizard and install Windows normally.

### 1.2 Install VMware Tools on VM B

Inside VM B → VMware menu bar → **VM → Install VMware Tools**, then run the installer inside the guest. This is required for `vmrun` to copy files and execute programs in the guest.

### 1.3 Configure the Host-Only Network Adapter

> This gives VM A's Scapy sniffer visibility into all traffic leaving VM B.

1. On the **Host**, open VMware Workstation → **Edit → Virtual Network Editor** (run as Administrator)
2. Locate or create a **Host-only** adapter — by default this is `VMnet1`
3. Ensure **"Connect a host virtual adapter to this network"** is checked
4. Note the **Subnet IP** (e.g., `192.168.10.0 / 255.255.255.0`) — you will need this later
5. **Do not** enable "Use local DHCP service" unless you want auto-addressing; a static IP on VM B is more predictable

6. Open **VM B Settings → Add → Network Adapter**
   - Connection type: **Custom: Specific virtual network → VMnet1**
7. Inside VM B (Windows), set a **static IP** on this adapter:
   - IP: `192.168.10.20`
   - Subnet: `255.255.255.0`
   - Gateway: `192.168.10.1` (VM A / host adapter)
   - DNS: `8.8.8.8` (or your preferred resolver)

8. On the **host machine**, the `VMnet1` adapter should automatically have an IP in that subnet (e.g., `192.168.10.1`). Confirm with `ipconfig` in a host terminal.

> **Important:** VM B should have **two** network adapters total:
> - Adapter 1: **NAT** — gives VM B internet access for initial software installs
> - Adapter 2: **Host-only (VMnet1)** — used by Scapy on VM A to capture malware traffic
>
> After setup is complete and before taking the `Clean_State` snapshot, you can disable the NAT adapter so malware cannot reach the real internet during analysis. Leave VMnet1 active so Scapy can still capture traffic.

### 1.4 Configure the Serial Port (Telemetry Channel)

> This creates the pipe that streams telemetry from VM B's `COM1` to VM A in real-time.

1. Open **VM B Settings → Add → Serial Port**
2. Serial port type: **Use named pipe**
3. Named pipe: `\\.\pipe\sandbox_serial`
4. **This end is:** Server
5. **The other end is:** A virtual machine
6. Check **"Yield CPU on poll"**
7. Click OK

This creates a named pipe on the host at `\\.\pipe\sandbox_serial` — exactly what `config.yaml` sets as `serial_pipe`.

---

## Part 2 — VM B (Sandbox) Configuration

Boot VM B and complete all steps below **before** taking the clean snapshot.

### 2.1 Create the Administrator Account

The default account must be named **Administrator** with the password matching `config.yaml` (default: `Password123`). To verify:

```
Settings → Accounts → Your info
```

Or create a new local administrator:

```powershell
net user Administrator Password123 /add
net localgroup administrators Administrator /add
```

### 2.2 Install Python 3.9

Download the official Python 3.9 installer from python.org. Install it to **exactly**:

```
C:\Python39\
```

During installation:
- Check **"Add Python to PATH"**
- Check **"Install for all users"**

Verify in a new Command Prompt:

```cmd
C:\Python39\python.exe --version
# Expected: Python 3.9.x
```

### 2.3 Install Agent Dependencies

Open an **Administrator** Command Prompt:

```cmd
C:\Python39\python.exe -m pip install pyserial psutil pywin32 wmi watchdog
```

These are the only packages the `unified_agents.py` needs inside the sandbox.

### 2.4 Install ProcMon

1. Download **Sysinternals Process Monitor** (`procmon.exe`) from Microsoft:
   https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
2. Place the executable at:

```
C:\Tools\procmon.exe
```

3. Run it once as Administrator, accept the EULA. This registers the EULA registry key so it does not prompt during automated runs.

### 2.5 Create the Analysis Working Directory

```cmd
mkdir C:\Analysis
```

This is where `unified_agents.py` writes the ProcMon trace (`trace.pml`) and CSV export (`trace.csv`).

### 2.6 Disable Windows Defender

Defender will flag and kill both ProcMon and the malware sample. Disable it entirely:

```
Settings → Windows Security → Virus & threat protection
→ Manage settings → Real-time protection: OFF
```

Also disable SmartScreen and Tamper Protection from the same panel.

For a permanent, policy-based disable (survives reboots):

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
```

### 2.7 Configure COM1 for the Serial Pipe

Windows must expose the VMware serial pipe as `COM1`. After adding the serial port in VMware settings (Part 1.4), boot the VM — VMware automatically maps the pipe as `COM1`. Verify in Device Manager:

```
Device Manager → Ports (COM & LPT) → Communications Port (COM1)
```

If it shows as `COM2` or higher, right-click → Properties → Port Settings → Advanced → change the COM port number to `1`.

### 2.8 Take the Clean Snapshot

This is critical — the controller will revert to this snapshot before **every** analysis run.

1. Shut down VM B completely
2. In VMware Workstation, right-click the VM → **Snapshot → Take Snapshot**
3. Name it exactly: `Clean_State`
4. Description: `Baseline — Python, ProcMon, COM1 configured, Defender off`

> **Do not** power VM B on again manually after this point. MARS controls its lifecycle entirely through `vmrun`.

---

## Part 3 — VM A (Controller) Configuration

### 3.1 Clone or Copy the MARS Repository

```cmd
git clone <your-repo-url> C:\MARS
cd C:\MARS
```

Or copy the project folder to `C:\MARS\`.

### 3.2 Install Python Dependencies on VM A

Open an **Administrator** Command Prompt:

```cmd
cd C:\MARS
pip install -r requirements.txt
```

The `requirements.txt` includes:
`fastapi`, `uvicorn`, `python-multipart`, `jinja2`, `sqlalchemy`, `PyYAML`, `pefile`, `yara-python`, `reportlab`, `scapy`, `watchdog`, `PyPubSub`

> **Note:** Scapy on Windows requires **Npcap** for raw packet capture. Download and install it from https://npcap.com — select "Install Npcap in WinPcap API-compatible mode" during setup.

### 3.3 Verify vmrun.exe is Accessible

`vmrun.exe` ships with VMware Workstation and lives at:

```
C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe
```

Test it from a Command Prompt:

```cmd
"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe" list
```

You should see a count of running VMs (possibly `Total running VMs: 0` if none are on). If you get a "not found" error, verify the path and update `config.yaml` accordingly.

---

## Part 4 — MARS Configuration (`config/config.yaml`)

Open `config/config.yaml` and update the `sandbox` section to match your environment:

```yaml
sandbox:
  # How long the malware runs before teardown (seconds)
  timeout_seconds: 300

  # Full path to vmrun.exe on VM A
  vmrun_path: "C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrun.exe"

  # Full path to the sandbox .vmx file on VM A (host filesystem)
  vmx_path: "D:\\Virtual Machines\\Windows10_Sandbox\\Windows10_Sandbox.vmx"

  # Must match the snapshot name created in Part 2.8
  snapshot_name: "Clean_State"

  # Must match the Administrator account name and password in VM B
  guest_user: "Administrator"
  guest_pass: "Password123"

  # The named pipe that maps to VM B's COM1 — do not change unless
  # you used a different pipe name in VMware hardware settings
  serial_pipe: "\\\\.\\pipe\\sandbox_serial"

  # The host-only VMware network adapter name as seen by Scapy on VM A
  # Run `python -c "import scapy.all; print(scapy.all.get_if_list())"` to list adapters
  network_interface: "VMware Network Adapter VMnet1"
```

### 4.1 Finding the Correct Network Interface Name

Scapy uses the Windows adapter display name, not the Linux-style `vmnet1`. Run this on VM A to list all interface names:

```python
python -c "import scapy.all; print(scapy.all.get_if_list())"
```

Look for the entry containing `VMnet1`. It will look like:
```
\Device\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
```

Or with Npcap in WinPcap-compatible mode, the friendly name `VMware Network Adapter VMnet1` may work directly. Update `network_interface` in `config.yaml` with whichever value Scapy recognizes.

### 4.2 Finding the vmx File Path

The `.vmx` file is in the folder you chose when creating VM B. Open VMware Workstation, right-click VM B → **Settings → Options tab** — the `.vmx` path is shown at the top. Copy it exactly (backslashes doubled in YAML, as shown above).

---

## Part 5 — Running MARS

### 5.1 Start the Server (VM A)

Open an **Administrator** Command Prompt (required for Scapy to sniff the network adapter):

```cmd
cd C:\MARS
python main.py
```

Expected startup output:

```
[Backend] Rebuilt analysis_id_map from N report(s) on disk.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

### 5.2 Access the Dashboard

Open a browser on VM A (or any machine on the same network) and navigate to:

```
http://localhost:8000
```

Or from another machine using VM A's IP:

```
http://<VM-A-IP>:8000
```

### 5.3 Upload a Sample for Analysis

1. Click **Upload & Ingest** in the sidebar
2. Drag and drop a `.exe`, `.dll`, `.zip`, `.sys`, or `.msi` file onto the drop zone
3. Select a **Detonation Strategy**:
   - **Static Only** — PE parsing, YARA, strings, entropy. Does not start VM B.
   - **Full Detonation (Static + Dynamic)** — runs both static analysis and dynamic sandbox detonation.
4. Click **Analyze**

The dashboard streams live logs in the **Execution Logs** section as analysis progresses.

---

## Part 6 — What Happens During Full Detonation

When a sample is submitted with "Full Detonation" selected, the pipeline executes the following sequence automatically:

| Step | Controller (VM A) | Sandbox (VM B) |
|------|-------------------|----------------|
| 1 | Reverts VM B to `Clean_State` snapshot | — |
| 2 | Powers on VM B | Windows boots |
| 3 | Waits 15 s for VMware Tools to initialize | Tools handshake |
| 4 | Copies `sample.exe` → `C:\Users\Administrator\Desktop\sample.exe` | — |
| 5 | Copies `unified_agents.py` or `two_phase_agents.py` → `C:\Users\Administrator\Desktop\...agent.py` | — |
| 6 | Starts Scapy sniffer on `vmnet1` | — |
| 7 | Executes the agent (`unified_agents.py` or `two_phase_agents.py`) via Python | Agent starts |
| 8 | Reads telemetry from `\\.\pipe\sandbox_serial` | Streams `COM1` |
| — | — | ProcMon captures kernel events |
| — | — | Malware detonates |
| — | — | Threads monitor: processes, registry, startup, hardware |
| 9 | Waits `timeout_seconds` (default 300 s) | Analysis window |
| 10 | Stops Scapy sniffer, collects network events | Agent terminates ProcMon |
| — | — | ProcMon exports CSV, agent parses and streams |
| 11 | Powers off VM B (hard stop) | Shutdown |
| 12 | Scores all telemetry, generates JSON + PDF report | — |

---

## Part 7 — Verifying Your Setup

Run these checks before submitting a real sample.

### 7.1 Verify vmrun Can Control VM B

```cmd
"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe" -T ws revertToSnapshot "D:\Virtual Machines\Windows10_Sandbox\Windows10_Sandbox.vmx" "Clean_State"
```

Expected: command exits with no output and no error code.

```cmd
"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe" -T ws start "D:\Virtual Machines\Windows10_Sandbox\Windows10_Sandbox.vmx" gui
```

Expected: VM B powers on and you see Windows boot in its VMware window.

```cmd
"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe" -T ws -gu Administrator -gp Password123 stop "D:\Virtual Machines\Windows10_Sandbox\Windows10_Sandbox.vmx" hard
```

Expected: VM B powers off.

### 7.2 Verify the Serial Pipe (Telemetry Channel)

1. Start VM B from VMware Workstation (manually, for this test only)
2. Inside VM B, open a Command Prompt and run:

```cmd
python -c "import serial; s=serial.Serial('COM1',115200); s.write(b'PIPE TEST\r\n'); s.flush(); print('sent')"
```

3. On VM A, in a Python shell:

```python
with open(r'\\.\pipe\sandbox_serial', 'rb') as p:
    print(p.readline())
```

Expected: `b'PIPE TEST\r\n'`

If this works, real-time telemetry from the agent will flow correctly during analysis.

### 7.3 Verify Scapy Can Sniff VMnet1

On VM A (run as Administrator):

```python
import scapy.all as scapy
scapy.sniff(iface="VMware Network Adapter VMnet1", count=5, prn=lambda p: p.summary())
```

Generate some traffic from VM B (ping anything) and confirm packets appear in the output. If you see nothing or a permissions error, ensure:
- Npcap is installed
- The script is running as Administrator
- The interface name in `config.yaml` matches the output of `scapy.get_if_list()`

### 7.4 Verify MARS Downloads

After at least one completed analysis, test the download endpoints:

```
http://localhost:8000/api/artifacts/<sha256>
```

Expected response: `{"json": true, "pdf": true, "pcap": false}` (PCAP is `true` only when network traffic was captured).

---

## Part 8 — YARA Rules

MARS applies YARA signatures at the end of static analysis. The ruleset lives at:

```
rules/rules.yar
```

Add your own rules using standard YARA syntax:

```yara
rule My_Custom_Rule {
    meta:
        description = "Detects something specific"
        author      = "Your Name"
    strings:
        $s1 = "suspicious string" nocase
        $b1 = { 4D 5A 90 00 }
    condition:
        any of them
}
```

No restart is required — rules are loaded fresh for each new analysis.

---

## Part 9 — Directory Structure Reference

```
MARS/
├── config/
│   └── config.yaml          ← Primary configuration (edit this)
├── core/
│   ├── pipeline.py          ← Analysis orchestrator
│   ├── dynamic.py           ← VM lifecycle + serial pipe reader
│   ├── network.py           ← Scapy network interceptor
│   ├── static.py            ← PE parsing, entropy, IAT analysis
│   ├── scoring.py           ← Risk scoring engine
│   ├── report.py            ← JSON + PDF report generator
│   ├── intake.py            ← File ingestion, unpacking, hashing
│   └── package.py           ← Archive handler
├── sandbox_agents/
│   ├── unified_agents.py    ← Runs inside VM B for standard/single-phase detonation
│   └── two_phase_agents.py  ← Runs inside VM B for bifurcated/two-phase detonation
├── rules/
│   └── rules.yar            ← YARA signatures
├── workspace/
│   └── reports/             ← Final JSON + PDF reports (All other analysis workspace folders are now stored in the host system's temporary directory)
├── web/
│   ├── templates/
│   │   ├── index.html       ← Main dashboard SPA
│   │   └── report.html      ← Standalone report viewer
│   └── static/css/
│       └── tailwind.css     ← Dashboard stylesheet
├── api/
│   └── routes.py            ← Upload + history + download endpoints
├── database/
│   └── models.py            ← SQLAlchemy models + DB subscriber
├── main.py                  ← FastAPI app entry point
└── requirements.txt
```

---

## Part 10 — Troubleshooting

### vmrun fails with "The virtual machine is not powered on"

The snapshot revert command and the start command must be separate calls. MARS does this correctly, but if you test manually, always `revertToSnapshot` before `start`.

### Serial pipe never connects / no telemetry appears

- Confirm the serial port hardware is added to VM B in VMware settings (Part 1.4)
- Confirm the pipe name is `\\.\pipe\sandbox_serial` in both VMware and `config.yaml`
- Confirm `COM1` appears in Device Manager inside VM B
- Confirm `pyserial` is installed inside VM B: `C:\Python39\python.exe -m pip show pyserial`

### Scapy shows no packets from VM B

- Ensure Npcap is installed on VM A
- Ensure MARS is started as **Administrator**
- Confirm VM B's network adapter 2 is set to `VMnet1` (not NAT or Bridged)
- Run `scapy.get_if_list()` and update `network_interface` in `config.yaml` to the exact interface name returned

### vmrun guest operations fail (copyFileFromHostToGuest / runProgramInGuest)

- VMware Tools must be installed and running inside VM B. Check Services inside the guest: `VMware Tools` service must be `Running`.
- Confirm `guest_user` and `guest_pass` in `config.yaml` exactly match the Administrator account credentials in VM B.

### ProcMon exits immediately / EULA prompt blocks analysis

- Boot VM B manually, launch `C:\Tools\procmon.exe` as Administrator, accept the EULA, then close it. The EULA key is now stored in the registry and will not prompt again in automated runs.
- Take a **new** `Clean_State` snapshot after accepting the EULA.

### Dashboard shows "PCAP (N/A)" for all analyses

This is expected when no network traffic was captured. PCAP files are saved to `workspace/04_pcaps/{sha256}_traffic.pcap` only when Scapy successfully captures packets during dynamic analysis. Ensure the Scapy sniffer is running and the network interface name is correct.

### Risk score is always 0

Check the **Execution Logs** tab during analysis. If dynamic telemetry shows no events (`Filesystem: 0 event(s), Registry: 0 event(s)` etc.), the agent did not run correctly in the sandbox. Verify Python 3.9 is at `C:\Python39\python.exe` inside VM B and that all agent dependencies are installed.

---

## Quick-Reference Checklist

- [ ] VMware Workstation Pro 17+ installed on host
- [ ] VM B created and Windows 10 installed
- [ ] VMware Tools installed on VM B
- [ ] VM B network adapter 2 set to Host-only (VMnet1)
- [ ] Static IP configured on VM B's VMnet1 adapter
- [ ] Serial port added to VM B → `\\.\pipe\sandbox_serial` → Server end
- [ ] Administrator account exists on VM B with matching password
- [ ] Python 3.9 installed to `C:\Python39\` on VM B
- [ ] `pyserial psutil pywin32 wmi watchdog` installed on VM B
- [ ] ProcMon at `C:\Tools\procmon.exe` with EULA accepted
- [ ] `C:\Analysis\` directory exists on VM B
- [ ] Windows Defender disabled on VM B
- [ ] `Clean_State` snapshot taken with VM B powered off
- [ ] Npcap installed on VM A (host)
- [ ] MARS dependencies installed on VM A via `pip install -r requirements.txt`
- [ ] `config/config.yaml` updated: `vmx_path`, `vmrun_path`, `network_interface`, credentials
- [ ] MARS started as Administrator on VM A
- [ ] Dashboard loads at `http://localhost:8000`
- [ ] `vmrun list` returns without errors
