# MARS Air-Gapped Deployment & Run Guide

This document provides a production-grade walkthrough for deploying and executing the Malware Analysis & Reporting System (MARS) in a strictly isolated, **air-gapped** environment. 

A high-security malware sandbox must run with **zero inbound or outbound internet access** to prevent:
1. Active malware from communicating with its live Command and Control (C2) servers.
2. Leakage of analysis metadata, target files, or IP addresses to the external internet.
3. Reliance on third-party CDNs or cloud resources that would fail under strict network boundaries.

---

## 1. Comprehensive Dependency Catalog

To install and run MARS offline, you must gather all dependencies on an internet-connected transit machine first. Below is the catalog of every system utility, interpreter, driver, library, and package required.

### 1.1 Virtualization & Hardware Requirements
* **VMware Workstation Pro (17.x or newer)**: Required on the Host (VM A) to run and control the Guest VM (VM B) via the VIX API.
* **VMware Tools**: Must be installed inside the Guest VM (VM B) to facilitate automated guest operations (file copying, program execution, and status queries).
* **Hardware Resources**:
  * Host Machine: Minimum 16 GB RAM (preferably 32 GB for concurrent detonation workloads), multicore CPU, and 150 GB+ of SSD space.
  * Guest VM: 2 CPU cores, 4 GB RAM, 60 GB disk.

### 1.2 System-Level Utilities & Network Drivers
* **Npcap (or WinPcap)**: Required on the Host (VM A) to enable raw packet capture and interception for the [ScapyInterceptor](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/core/network.py#L8-L22). Download from [npcap.com](https://npcap.com/).
* **Sysinternals Process Monitor (ProcMon)**: Required inside the Guest VM (VM B) to collect kernel-level events. Download from [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon).
* **Virtual COM Port / Named Pipe**: Virtual COM port setup on VM B mapped to the Host named pipe `\\.\pipe\sandbox_serial` for out-of-band telemetry.

### 1.3 Python Interpreters
* **Host Machine (VM A)**: Python **3.10 to 3.12** (64-bit).
* **Guest Sandbox VM (VM B)**: Python **3.9.x** (64-bit) installed to **exactly** `C:\Python39\`. The orchestration code in [core/dynamic.py](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/core/dynamic.py#L1104) strictly relies on this path.

### 1.4 Host Python Libraries (VM A)
These packages are listed in [requirements.txt](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/requirements.txt) and must be installed on VM A:
* `fastapi` (Web application framework core)
* `uvicorn` (ASGI web server)
* `python-multipart` (Multi-part form request parser for file ingestion)
* `jinja2` (Dashboard HTML templating engine)
* `sqlalchemy` (ORM database abstraction)
* `PyYAML` (Configuration parser for YAML files)
* `pefile` (Portable Executable static analyzer)
* `yara-python` (YARA signature compilation engine)
* `reportlab` (PDF Report Generator engine)
* `scapy` (Deep packet inspection and network sniffing library)
* `watchdog` (Directory and file event monitoring library)
* `PyPubSub` (Synchronous event broker for decoupling control threads)
* `psutil` (Resource usage telemetry logger)

### 1.5 Guest Python Libraries (VM B)
These packages are required by the guest agent [unified_agents.py](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/sandbox_agents/unified_agents.py) inside the sandbox VM:
* `pyserial` (Streaming telemetry over the `COM1` named pipe)
* `psutil` (Process enumeration and tracking)
* `watchdog` (Filesystem modification tracking)
* `pywin32` (Windows APIs interaction layer)
* `wmi` (Querying Windows Management Instrumentation for OS details)

### 1.6 Web / Frontend Dependencies (Critical Air-Gap Fixes)
The dashboard frontend references external assets which will fail to load in an air-gapped system. You must resolve these resources offline:
* **Chart.js (v4.x)**: Currently requested from `https://cdn.jsdelivr.net/npm/chart.js` in [index.html](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/web/templates/index.html#L8) and [report.html](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/web/templates/report.html#L8).
* **Google Fonts**: Inter, Outfit, and JetBrains Mono, loaded from `https://fonts.googleapis.com` via `@import` rules in:
  * [index.html](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/web/templates/index.html#L9)
  * [report.html](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/web/templates/report.html#L10)
  * [tailwind.css](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/web/static/css/tailwind.css#L6)

---

## 2. Pre-installation Phase: Asset Gathering (Internet-Facing Host)

On a computer with active internet access, perform the following tasks to bundle all required installers, drivers, and libraries:

### 2.1 Download Offline Python Installers
1. Download Python **3.10.x** Windows Installer (e.g., `python-3.10.11-amd64.exe`) for Host VM A.
2. Download Python **3.9.13** Windows Installer (e.g., `python-3.9.13-amd64.exe`) for Guest VM B.

### 2.2 Download System Utilities & Virtualization Installers
1. Download the latest **Npcap** installer (e.g., `npcap-1.80.exe`) from [npcap.com](https://npcap.com/).
2. Download Sysinternals **Process Monitor** (`ProcessMonitor.zip`) from Microsoft and extract `procmon.exe`.
3. Download the **VMware Workstation Pro 17+** Windows installer.
4. Download a clean **Windows 10 x64 ISO** (for creating VM B).

### 2.3 Download Host Python Wheels (VM A)
On the transit host, download the wheels (pre-compiled binary packages) matching your target Host OS (Windows 64-bit) for all requirements in [requirements.txt](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/requirements.txt):
```cmd
mkdir C:\MARS_Offline_Setup\host_wheels
cd C:\MARS_Offline_Setup\host_wheels
pip download --only-binary=:all: --platform win_amd64 --python-version 310 -r C:\path\to\requirements.txt
```

### 2.4 Download Guest Python Wheels (VM B)
Download Python 3.9 compatible wheels for the guest agent packages:
```cmd
mkdir C:\MARS_Offline_Setup\guest_wheels
cd C:\MARS_Offline_Setup\guest_wheels
pip download --only-binary=:all: --platform win_amd64 --python-version 3.9 pyserial psutil pywin32 wmi watchdog
```

### 2.5 Resolve Frontend CDN Assets Offline
To prevent the web UI from attempting internet connections, fetch the files locally:
1. **Download Chart.js**: Access `https://cdn.jsdelivr.net/npm/chart.js` in a browser, save the file as `chart.js`, and place it in the asset folder.
2. **Download Google Fonts**: 
   * Go to Google Fonts helper pages or download the font families (Inter, Outfit, JetBrains Mono) directly as `.ttf` or `.woff2` files.
   * Place these font files into a dedicated subdirectory.

### 2.6 Package the Offline Assets
Copy all the downloaded setup materials, wheels, installers, and the MARS codebase onto a physical transfer medium (e.g., a verified secure USB drive or an optical disc).

---

## 3. Installation & Local Modifications (Air-Gapped Host VM A)

Mount the physical media on Host VM A and execute the following deployment stages:

### 3.1 Install Core Utilities
1. Install **VMware Workstation Pro**.
2. Install **Python 3.10.x** on Host VM A. Make sure to check **"Add Python to PATH"**.
3. Install **Npcap**:
   > [!IMPORTANT]
   > During Npcap setup, you **MUST** check the checkbox:
   > **"Install Npcap in WinPcap API-compatible mode"**.
   > If you omit this, Scapy will fail to initialize the packet capture driver, throwing win32/packet exceptions upon server start.

### 3.2 Install Host Python Packages Offline
1. Copy the MARS codebase to your preferred directory (e.g., `C:\MARS`).
2. Move the `host_wheels` folder to the host system.
3. Open an Administrator Command Prompt and run:
   ```cmd
   cd C:\MARS
   pip install --no-index --find-links=C:\MARS_Offline_Setup\host_wheels -r requirements.txt
   ```

### 3.3 Apply Local Frontend CDN Mitigations
To eliminate all external HTTP requests when launching the browser dashboard:

1. **Host Chart.js locally**:
   * Create the directory structure: `C:\MARS\web\static\js\`
   * Place the downloaded `chart.js` file inside `C:\MARS\web\static\js\chart.js`
   * Update [index.html](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/web/templates/index.html#L8):
     ```diff
     - <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
     + <script src="/static/js/chart.js"></script>
     ```
   * Update [report.html](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/web/templates/report.html#L8):
     ```diff
     - <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
     + <script src="/static/js/chart.js"></script>
     ```

2. **Host Fonts locally**:
   * Create the directory structure: `C:\MARS\web\static\fonts\`
   * Place your font files (e.g., `Inter.ttf`, `Outfit.ttf`, `JetBrainsMono.ttf`) in `C:\MARS\web\static\fonts\`.
   * Add `@font-face` definitions to the top of [tailwind.css](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/web/static/css/tailwind.css):
     ```css
     @font-face {
       font-family: 'Inter';
       src: url('/static/fonts/Inter.ttf') format('truetype');
       font-weight: 100 900;
     }
     @font-face {
       font-family: 'Outfit';
       src: url('/static/fonts/Outfit.ttf') format('truetype');
       font-weight: 100 900;
     }
     @font-face {
       font-family: 'JetBrains Mono';
       src: url('/static/fonts/JetBrainsMono.ttf') format('truetype');
       font-weight: 100 900;
     }
     ```
   * Delete or comment out the external `@import` links in:
     * [index.html](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/web/templates/index.html#L9)
     * [report.html](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/web/templates/report.html#L10)
     * [tailwind.css](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/web/static/css/tailwind.css#L6)

---

## 4. Setup & Baseline Snapshot Configuration (Guest VM B)

The guest VM performs the actual malware execution. Follow these instructions precisely to set up the baseline snapshot:

### 4.1 Create VM B (Sandbox Windows 10)
1. In VMware Workstation, create a new VM using your Windows 10 ISO. Name it `Windows10_Sandbox`.
2. Install Windows 10, choosing a standard Local Account.
3. Install **VMware Tools** from the Workstation menu → **VM -> Install VMware Tools**. Run the setup and reboot VM B.
4. Create the required credentials. The default guest account must be named `Administrator` and configured with a password:
   ```cmd
   net user Administrator Password123 /add
   net localgroup administrators Administrator /add
   ```

### 4.2 Offline Installation of Python 3.9 and Dependencies
1. Run the Python 3.9 installer inside VM B.
2. Select **"Customize installation"**, and ensure it is installed to **exactly**:
   ```
   C:\Python39\
   ```
3. Transfer the `guest_wheels` folder to VM B's Desktop (using drag-and-drop or a temporary network share).
4. Open an Administrator Command Prompt in VM B and install the packages offline:
   ```cmd
   C:\Python39\python.exe -m pip install --no-index --find-links=C:\Users\Administrator\Desktop\guest_wheels pyserial psutil pywin32 wmi watchdog
   ```

### 4.3 Configure Guest System Utilities
1. Inside VM B, create the tool directory: `mkdir C:\Tools`
2. Place the `procmon.exe` executable inside `C:\Tools\procmon.exe`.
3. **Accept the ProcMon EULA**:
   > [!IMPORTANT]
   > Launch `C:\Tools\procmon.exe` manually once. Click **Agree** on the license prompt, then close ProcMon. 
   > This action generates a local Registry key (`HKCU\Software\Sysinternals\Process Monitor\EulaAccepted = 1`) which prevents blocking UI prompts during automated sandbox runs.

4. Create the sandbox working directory:
   ```cmd
   mkdir C:\Analysis
   ```

### 4.4 Sandbox Security Hardening (Disable Security Windows Features)
Malware analysis requires removing all active security features to ensure execution is not halted prematurely:
1. Disable **Windows Defender / Security**:
   * Open *Windows Security* → *Virus & threat protection settings* → *Manage settings*.
   * Toggle **Real-time protection**, **Cloud-delivered protection**, and **Tamper Protection** to **OFF**.
2. For a persistent policy-level shutdown that survives reboots, run this in an Administrator PowerShell window:
   ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $true
   Set-MpPreference -DisableBehaviorMonitoring $true
   Set-MpPreference -DisableBlockAtFirstSeen $true
   Set-MpPreference -DisableIOAVProtection $true
   ```

### 4.5 VM Hardware Settings & Snapshot Capturing
1. Shut down VM B.
2. Right-click the VM inside VMware Workstation → **Settings**.
3. **Network Configuration**:
   * Add a new network adapter and map it to **Host-Only (VMnet1)**.
   * If there is a NAT adapter configured for the setup phase, select it and **Uncheck** "Connect at power on" to guarantee VM B cannot communicate with the outside network during execution.
4. **Serial Telemetry Pipe Setup**:
   * Add a new **Serial Port** hardware.
   * Set connection type to **Use named pipe**.
   * Name: `\\.\pipe\sandbox_serial`
   * Select: **This end is Server** / **The other end is a virtual machine**.
   * Check **"Yield CPU on poll"**.
5. Power VM B on once to verify that the virtual serial port maps to `COM1` inside Device Manager. Turn VM B off.
6. With VM B completely shut down:
   * Right-click VM B → **Snapshot -> Take Snapshot**.
   * Name it **exactly**: `Clean_State` (matches `snapshot_name` config key).

---

## 5. Network & Configuration Matching (Host VM A)

Now, customize [config.yaml](file:///c:/BHAVYA/Internship/zip-repl%20%282%29/zip-repl/config/config.yaml) on VM A to route telemetry, control VM B, and parse network packets offline.

1. Open `C:\MARS\config\config.yaml`
2. Update the `sandbox` section keys:
   ```yaml
   sandbox:
     # Timeout window in seconds
     timeout_seconds: 300

     # Path to vmrun on the Host filesystem
     vmrun_path: "C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrun.exe"

     # Absolute path to the VM configuration file
     vmx_path: "C:\\Users\\Acer\\Documents\\Virtual Machines\\Windows10_Sandbox\\Windows10_Sandbox.vmx"

     # Match snapshot and VM credentials
     snapshot_name: "Clean_State"
     guest_user: "Administrator"
     guest_pass: "Password123"

     # Local Named Pipe
     serial_pipe: "\\\\.\\pipe\\sandbox_serial"

     # Host-only network interface Display Name mapped on VM A
     network_interface: "VMware Network Adapter VMnet1"
   ```
3. Locate the host adapter friendly name:
   * Run this in your host CLI:
     ```cmd
     python -c "import scapy.all; print(scapy.all.get_if_list())"
     ```
   * Find the adapter entry representing the Host-Only `VMnet1` virtual card (e.g. `\Device\NPF_{GUID}` or `VMware Network Adapter VMnet1`) and set it as the value of `network_interface` in `config.yaml`.

---

## 6. Execution & Offline Verification

### 6.1 Launching the Sandbox Controls
On VM A, launch the application server using an Administrator terminal:
```cmd
cd C:\MARS
python main.py
```
> [!NOTE]
> Administrator privileges are required to bind to raw sockets via Npcap for network sniffing.

Access the dashboard in your local browser at `http://127.0.0.1:8000`.

### 6.2 Baseline Pipeline Tests
Before analyzing unknown malware, execute a baseline validation check:
1. Create a harmless test text file and change its extension to `.exe`.
2. Upload the file to the dashboard with **Full Detonation** selected.
3. Monitor the live log feed inside the browser.
4. **Successful pipeline validation matches this sequence**:
   * Host reverts VM B to `Clean_State` snapshot.
   * Host starts VM B and waits for VMware Tools initialization.
   * Host copies the sample and `unified_agents.py` into VM B.
   * Host initiates the Scapy sniffer on `VMnet1` and connects to the named pipe `\\.\pipe\sandbox_serial`.
   * Guest agent starts executing `sample.exe`.
   * Telemetry streams over COM1, populating dashboard logs.
   * Analysis duration concludes; Host terminates VM B.
   * PDF report and dossier are generated successfully inside the `workspace/reports/` folder.
