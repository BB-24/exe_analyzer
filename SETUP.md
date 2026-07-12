# MARS — Setup & Installation Guide

> **Malware Analysis & Reverse-engineering System**
>
> Complete step-by-step guide for installing and configuring MARS on a dual-VM analysis environment.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Hardware & Software Prerequisites](#2-hardware--software-prerequisites)
3. [Host Machine Setup (VM A)](#3-host-machine-setup-vm-a)
4. [Sandbox Guest Setup (VM B)](#4-sandbox-guest-setup-vm-b)
5. [VMware Network & Serial Configuration](#5-vmware-network--serial-configuration)
6. [Configuration Reference (`config.yaml`)](#6-configuration-reference-configyaml)
7. [First Run & Verification](#7-first-run--verification)
8. [Air-Gapped / Offline Installation](#8-air-gapped--offline-installation)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Architecture Overview

MARS uses a **dual-VM architecture**:

```
┌──────────────────────────────────────────────────────┐
│                    HOST MACHINE                      │
│                                                      │
│  ┌──────────────────────┐   ┌─────────────────────┐  │
│  │   VM A (Analyst)     │   │  VM B (Sandbox)     │  │
│  │                      │   │                     │  │
│  │  • MARS Web Server   │◄─►│  • Sandbox Agent    │  │
│  │  • FastAPI Backend   │   │  • ProcMon          │  │
│  │  • Analysis Pipeline │   │  • FakeNet          │  │
│  │  • Report Generator  │   │  • Sample Execution │  │
│  │  • Scapy Sniffer     │   │                     │  │
│  └──────────────────────┘   └─────────────────────┘  │
│         │    ▲                       │    ▲           │
│         │    │ Named Pipe            │    │           │
│         │    │ (Serial Telemetry)    │    │           │
│         │    └───────────────────────┘    │           │
│         │                                │           │
│         └── Host-Only Network (VMnet1) ──┘           │
└──────────────────────────────────────────────────────┘
```

| Component | Role |
|-----------|------|
| **VM A** (Analyst Host) | Runs the MARS web dashboard, orchestrates analysis, receives telemetry, generates reports |
| **VM B** (Sandbox Guest) | Isolated Windows 10 environment where malware is detonated and monitored |
| **Named Pipe** | `\\.\pipe\sandbox_serial` — Serial COM1 telemetry channel between guest agent and host |
| **VMnet1** | Host-only virtual network for Scapy packet capture (no internet for sandbox) |

---

## 2. Hardware & Software Prerequisites

### Minimum Hardware
| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Disk | 60 GB free | 120+ GB SSD |

### Software Requirements

| Software | Version | Purpose |
|----------|---------|---------|
| **VMware Workstation Pro** | 16.x+ | Virtual machine hypervisor |
| **Windows 10/11** | Any | Host OS (VM A) and Sandbox Guest OS (VM B) |
| **Python** | 3.12+ | Runtime for MARS and sandbox agents |
| **Git** | Any | Clone the repository |

> [!IMPORTANT]
> Both VM A and VM B must run **Windows**. The sandbox agents use Windows-specific APIs (`pywin32`, `wmi`, `winreg`, ProcMon).

---

## 3. Host Machine Setup (VM A)

### 3.1 Clone the Repository

```bash
git clone <repository-url> exe_analyzer
cd exe_analyzer/exe_analyzer
```

### 3.2 Create a Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate
```

### 3.3 Install Dependencies

**Online installation:**
```bash
pip install -r requirements.txt
```

**Offline / Air-gapped installation** (using bundled wheels):
```bash
python -m pip install --no-index --find-links=wheels -r requirements.txt
```

> [!NOTE]
> If `yara-python` fails to build on your system, use the fallback requirements file:
> ```bash
> pip install -r reqs_no_yara.txt
> ```
> YARA signature scanning will be disabled, but all other modules remain functional.

### 3.4 Verify Installation

```bash
python -c "import pefile, yara, scapy, psutil, fastapi; print('All dependencies OK')"
```

### 3.5 Directory Structure (Auto-Created on First Run)

MARS automatically creates these workspace directories on startup:

| Directory | Purpose |
|-----------|---------|
| `workspace/reports/` | JSON and PDF analysis reports |
| `%TEMP%/mars_workspace/01_quarantine/` | Uploaded samples held for processing |
| `%TEMP%/mars_workspace/02_extracted/` | Unpacked archive contents |
| `%TEMP%/mars_workspace/03_dossiers/` | Cached dossier JSON copies |
| `%TEMP%/mars_workspace/04_pcaps/` | Network capture PCAP files |
| `%TEMP%/mars_workspace/extracted/` | Pipeline extraction directory |

---

## 4. Sandbox Guest Setup (VM B)

### 4.1 Create a Clean Windows 10 VM

1. Install Windows 10 (any edition) in VMware Workstation.
2. Complete the Windows OOBE (Out-of-Box Experience) setup with any local account.
3. **Disable Windows Defender** and all real-time protection (the sandbox must not interfere with malware execution).

### 4.2 Activate the Built-in Administrator Account

Windows 10 ships with a built-in `Administrator` account that is disabled by default. MARS expects the sandbox to run under this account. Follow **one** of the methods below to activate it:

#### Method A: Using Local Users and Groups (Pro/Enterprise only)

1. Press `Win + R`, type `lusrmgr.msc`, and press Enter.
2. Click **Users** in the left panel.
3. Right-click **Administrator** → **Properties**.
4. **Uncheck** the box labeled *"Account is disabled"*.
5. Click **Apply** → **OK**.
6. Set a password: right-click **Administrator** → **Set Password** → set it to match `guest_pass` in `config.yaml` (default: `Password123`).

#### Method B: Using Command Prompt (All editions including Home)

1. Open **Command Prompt** as Administrator (right-click Start → *Windows Terminal (Admin)* or *Command Prompt (Admin)*).
2. Run the following commands:

```cmd
:: Activate the built-in Administrator account
net user Administrator /active:yes

:: Set the password (must match guest_pass in config.yaml)
net user Administrator Password123
```

3. Verify the account is active:
```cmd
net user Administrator
```
Look for the line `Account active    Yes`.

#### Method C: Using Registry Editor (Home edition fallback)

If both methods above fail (e.g., restricted group policy):

1. Press `Win + R`, type `regedit`, press Enter.
2. Navigate to:
   ```
   HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\000001F4
   ```
   > [!NOTE]
   > You may need to right-click the `SAM` key → **Permissions** → give your current user **Full Control** to access this path.
3. Double-click the `F` binary value.
4. Find offset `0x0038` — change the value from `11` to `10`.
5. Click **OK** and restart the VM.

#### Post-Activation Steps

After activating the Administrator account:

1. **Sign out** of the current user account.
2. On the Windows login screen, select the **Administrator** account and sign in with the password you set.
3. (Optional) Delete or disable the temporary local account created during OOBE to reduce noise.
4. Verify you are logged in as Administrator:
   ```cmd
   whoami
   ```
   Expected output: `<hostname>\administrator`

> [!IMPORTANT]
> The `guest_user` and `guest_pass` values in `config.yaml` **must** match the Administrator account credentials you set here. MARS uses these credentials to authenticate via `vmrun` when copying files and executing the sandbox agent inside the guest.

### 4.3 Install Python in the Guest

Install Python 3.12+ in the Guest VM. Add it to `PATH`.

### 4.3 Install Guest Agent Dependencies

**If the guest has internet:**
```bash
pip install pyserial psutil pywin32 wmi watchdog
```

**If the guest is air-gapped**, copy the `wheels/` directory into the guest and run:
```bash
pip install --no-index --find-links=wheels pyserial psutil pywin32 wmi watchdog
```

The relevant wheels for the guest are:
- `pyserial-3.5-*.whl`
- `psutil-7.2.2-*.whl`
- `pywin32-312-*.whl`
- `WMI-1.5.1-*.whl`
- `watchdog-6.0.0-*.whl`

### 4.4 Deploy Tools & Agent Scripts

Create the following directories in the Guest VM:

```
C:\Tools\
C:\Tools\procmon.exe      ← Copy from sandbox_agents/tools/Procmon.exe
C:\Tools\Fakenet\
C:\Tools\Fakenet\FakeNet.exe  ← Copy from sandbox_agents/tools/FakeNet.exe
C:\Analysis\              ← ProcMon trace output directory (auto-created)
```

Deploy the sandbox agent scripts:
```
C:\Tools\unified_agents.py     ← Copy from sandbox_agents/unified_agents.py
C:\Tools\two_phase_agents.py   ← Copy from sandbox_agents/two_phase_agents.py
```

### 4.5 Create a Clean Snapshot

After completing all setup:

1. Shut down the Guest VM cleanly.
2. In VMware, take a snapshot named **`Clean_State`** (must match `snapshot_name` in `config.yaml`).

> [!CAUTION]
> Every analysis run reverts the VM to this snapshot. If you modify the guest setup later, you must retake this snapshot.

---

## 5. VMware Network & Serial Configuration

### 5.1 Host-Only Network (VMnet1)

1. In VMware Workstation → **Edit** → **Virtual Network Editor**.
2. Ensure **VMnet1** is configured as **Host-Only**.
3. Note the adapter name (e.g., `VMware Virtual Ethernet Adapter for VMnet1`).
4. Update `network_interface` in `config.yaml` to match this exact name.

### 5.2 Serial Port (Named Pipe)

Configure the Guest VM's hardware settings:

1. **Add Hardware** → **Serial Port**.
2. Connection: **Use named pipe**.
3. Pipe name: `\\.\pipe\sandbox_serial`
4. Direction: **This end is the server** → **The other end is an application**.
5. Check **Yield CPU on poll**.

This creates the COM1 serial channel that the sandbox agent uses to stream telemetry back to the host.

### 5.3 vmrun Path

Locate `vmrun.exe` on your host system. The default path is:
```
C:\Program Files\VMware\VMware Workstation\vmrun.exe
```

Update `vmrun_path` in `config.yaml` if your installation path differs.

---

## 6. Configuration Reference (`config.yaml`)

The main configuration file is located at `config/config.yaml`.

```yaml
system:
  max_file_size_gb: 5               # Maximum upload size
  allowed_extensions:                # Accepted file types
    - '.zip'
    - '.exe'
    - '.dll'
    - '.msi'
    - '.sys'
    - '.malz'
  max_unpack_depth: 3               # Zip-bomb protection limit
  workspace_dir: "./workspace"
  extract_dir: "./workspace/extracted"
  reports_dir: "./workspace/reports"

static_analysis:
  yara_rules_path: "rules/rules.yar"
  entropy_threshold: 7.0            # Shannon entropy flagging threshold
  suspicious_imports:               # IAT patterns to flag
    - "CreateRemoteThread"
    - "VirtualAllocEx"
    - "WriteProcessMemory"
    # ... (see full list in config.yaml)

sandbox:
  timeout_seconds: 300              # Default analysis window
  vmrun_path: "C:\\Program Files\\VMware\\VMware Workstation\\vmrun.exe"
  vmx_path: "C:\\Users\\<YOU>\\Documents\\Virtual Machines\\<VM_NAME>\\<VM_NAME>.vmx"
  snapshot_name: "Clean_State"
  guest_user: "Administrator"
  guest_pass: "Password123"         # ⚠ Change this
  fakenet_path: "C:\\Tools\\Fakenet\\FakeNet.exe"
  serial_pipe: "\\\\.\\pipe\\sandbox_serial"
  network_interface: "VMware Virtual Ethernet Adapter for VMnet1"
```

> [!WARNING]
> You **must** update `vmx_path`, `guest_user`, and `guest_pass` to match your actual sandbox VM configuration before first use.

---

## 7. First Run & Verification

### 7.1 Start the MARS Server

```bash
cd exe_analyzer
python main.py
```

The FastAPI server starts on `http://localhost:8000`.

### 7.2 Access the Web Dashboard

Open a browser and navigate to:
```
http://localhost:8000
```

You should see the MARS analysis dashboard with:
- File upload panel
- Analysis type selector (Full Detonation, Static Only, Dynamic Only, Bifurcated)
- Analysis duration slider
- Analysis history table

### 7.3 Run a Test Analysis

1. Upload a benign `.exe` file (e.g., `notepad++` installer).
2. Select **Static Only** as the analysis type.
3. Click **Upload & Analyze**.
4. Verify that the static analysis completes and results appear in the dashboard.

### 7.4 Verify Dynamic Analysis

1. Ensure the sandbox VM snapshot exists and VMware is running.
2. Upload a sample and select **Full Detonation**.
3. The system will:
   - Revert the VM to `Clean_State` snapshot
   - Copy the sample into the guest
   - Deploy and launch the sandbox agent
   - Execute the sample and monitor it
   - Stream telemetry back via the serial pipe
   - Generate reports

---

## 8. Air-Gapped / Offline Installation

MARS ships with a `wheels/` directory containing pre-built Python packages for offline installation. This is critical for secure malware analysis labs that cannot have internet access.

### Host (VM A)
```bash
python -m pip install --no-index --find-links=wheels -r requirements.txt
```

### Guest (VM B)
Copy the `wheels/` folder into the guest VM, then:
```bash
python -m pip install --no-index --find-links=wheels pyserial psutil pywin32 wmi watchdog
```

The wheels directory contains packages for both CPython 3.12 and 3.14 on Windows AMD64.

---

## 9. Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| `yara-python` fails to install | Use `reqs_no_yara.txt` instead; YARA scanning will be disabled |
| `vmrun` not found | Update `vmrun_path` in `config.yaml` to the correct path |
| Serial port connection fails | Ensure the named pipe `\\.\pipe\sandbox_serial` is configured in VMware VM settings |
| VM snapshot not found | Ensure the snapshot is named exactly `Clean_State` (case-sensitive) |
| No telemetry received | Verify COM1 serial port is configured in guest VM hardware and agent script is running |
| `ImportError: No module named 'win32api'` | Run `pip install pywin32` and then `python Scripts/pywin32_postinstall.py -install` |
| ProcMon CSV not generated | Ensure `C:\Tools\procmon.exe` exists in the guest and `C:\Analysis\` directory is writable |
| Network capture empty | Verify `network_interface` in config matches the actual VMnet1 adapter name |
| Host AV quarantines samples | Add `%TEMP%\mars_workspace\` to your antivirus exclusion list |
| Database migration errors | Delete `mars_history.db` and restart; the schema will be recreated |

### Checking Logs

- **Host server logs**: Printed to the terminal running `python main.py`
- **Guest agent logs**: Written to `C:\Users\Administrator\Desktop\agent_err.log` inside the VM
- **ProcMon traces**: `C:\Analysis\trace.csv` inside the guest VM

### Resetting the Environment

To perform a clean reset:
1. Delete `mars_history.db` (the SQLite database will be recreated on restart).
2. Delete the contents of `workspace/reports/`.
3. Delete the `%TEMP%/mars_workspace/` directory.
4. Revert the sandbox VM to the `Clean_State` snapshot.
5. Restart `python main.py`.
