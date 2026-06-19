import os
import re
import math
import datetime
import xml.etree.ElementTree as ET
import pefile
import yara
from pubsub import pub

class StaticModule:
    def __init__(self, config):
        self.config = config
        self.entropy_threshold = self.config.get('static_analysis', {}).get('entropy_threshold', 7.0)
        default_imports = [
            'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
            'ShellExecuteA', 'ShellExecuteW', 'WinExec', 'InternetOpenA', 'InternetOpenW'
        ]
        raw_imports = self.config.get('static_analysis', {}).get('suspicious_imports', default_imports)
        # YAML config supplies str names; pefile import names are bytes — keep str for matching
        self.target_imports = [
            name.decode('utf-8') if isinstance(name, bytes) else str(name)
            for name in raw_imports
        ]
        
        # Load YARA rules (FR-STA-07)
        yara_path = self.config.get('static_analysis', {}).get('yara_rules_path', 'rules/rules.yar')
        try:
            self.yara_rules = yara.compile(filepath=yara_path)
            pub.sendMessage("gui.log", msg=f"[*] Successfully compiled YARA ruleset from {yara_path}")
        except Exception as e:
            self.yara_rules = None
            pub.sendMessage("gui.log", msg=f"[!] Failed to load YARA rules: {str(e)}")

        # FR-STA-06: Pre-compile Regex patterns for high performance
        self.regex_patterns = {
            "IPv4": re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            "IPv6": re.compile(rb'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b'),
            "URL": re.compile(rb'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'),
            "Registry": re.compile(rb'(?i)(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[A-Za-z0-9_\\-]+'),
            "Email": re.compile(rb'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'),
            "Password-Like": re.compile(rb'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{12,}$')
        }

    def process_file(self, filepath):
        pub.sendMessage("gui.log", msg="\n[+] --- Starting Static Analysis Module ---")
        
        try:
            pe = pefile.PE(filepath)
            results = {}
            
            self._analyze_pe_headers(pe, results)        # FR-STA-02
            self._analyze_mitigations(pe, results)       # FR-STA-03
            self._analyze_sections(pe, results)          # FR-STA-04 & 08
            self._analyze_imports(pe, results)           # FR-STA-05
            self._extract_manifest(pe, results)          # FR-STA-01
            self._extract_strings(filepath, results)     # FR-STA-06
            self._run_yara(filepath, results)            # FR-STA-07 & 08
            
            # Format results for GUI Treeview
            for category, data in results.items():
                if isinstance(data, dict):
                    display_data = {
                        key: ", ".join(value) if isinstance(value, list) else value
                        for key, value in data.items()
                    }
                    pub.sendMessage("gui.update_table", module=f"Static: {category}", data=display_data)
                
            return results
                    
        except pefile.PEFormatError:
            pub.sendMessage("gui.log", msg=f"[!] {os.path.basename(filepath)} is not a valid PE file. Skipping Static Analysis.")
            return None
        except Exception as e:
            pub.sendMessage("gui.log", msg=f"[!] Critical Error in Static Module: {str(e)}")
            return None

    # ==========================================
    # FR-STA-02: PE Header Parsing
    # ==========================================
    def _analyze_pe_headers(self, pe, results):
        pub.sendMessage("gui.log", msg="[*] Parsing PE Structures and Headers...")
        
        timestamp = pe.FILE_HEADER.TimeDateStamp
        compile_time = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        results["PE Headers"] = {
            "Machine Architecture": hex(pe.FILE_HEADER.Machine),
            "Compile Timestamp": compile_time,
            "DOS Header Offset (e_lfanew)": hex(pe.DOS_HEADER.e_lfanew),
            "Address of Entry Point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "Image Base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "Number of Sections": pe.FILE_HEADER.NumberOfSections
        }

    # ==========================================
    # FR-STA-03: Security Mitigation Enumeration
    # ==========================================
    def _analyze_mitigations(self, pe, results):
        pub.sendMessage("gui.log", msg="[*] Enumerating Security Mitigations...")
        
        # Standard DLL Characteristics Flags
        dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
        
        dep_enabled = bool(dll_chars & 0x0100)        # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        aslr_enabled = bool(dll_chars & 0x0040)       # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        cfg_enabled = bool(dll_chars & 0x4000)        # IMAGE_DLLCHARACTERISTICS_GUARD_CF
        no_seh = bool(dll_chars & 0x0400)             # IMAGE_DLLCHARACTERISTICS_NO_SEH
        force_integ = bool(dll_chars & 0x0080)        # IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
        app_container = bool(dll_chars & 0x1000)      # IMAGE_DLLCHARACTERISTICS_APPCONTAINER
        
        # Advanced Flags from Load Configuration Directory
        stack_canary = False
        safeseh = False
        rfg_enabled = False
        cet_enabled = False

        if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
            load_config = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
            
            # Stack Canary (/GS) -> Indicated by a non-zero Security Cookie
            if hasattr(load_config, 'SecurityCookie') and load_config.SecurityCookie != 0:
                stack_canary = True
                
            # SafeSEH -> Indicated if SEHandlerTable exists and NO_SEH is not set
            if no_seh:
                safeseh = True # Technically safe from SEH exploits because it doesn't use it
            elif hasattr(load_config, 'SEHandlerTable') and load_config.SEHandlerTable != 0:
                safeseh = True
                
            # Guard Flags (For CFG, RFG, CET)
            if hasattr(load_config, 'GuardFlags'):
                guard_flags = load_config.GuardFlags
                rfg_enabled = bool(guard_flags & 0x00020000) # IMAGE_GUARD_RF_INSTRUMENTED
                
                # CET (Shadow Stack) checking (if CET compatible flag bit is flipped)
                # CET bits differ slightly by version, checking standard extended features
                cet_enabled = bool(guard_flags & 0x10000000) # Typical CET compatible bit

        # Compile Results
        results["Mitigations"] = {
            "DEP / NX Bit": "Enabled" if dep_enabled else "Disabled",
            "ASLR": "Enabled" if aslr_enabled else "Disabled",
            "CFG (Control Flow Guard)": "Enabled" if cfg_enabled else "Disabled",
            "RFG (Return Flow Guard)": "Enabled" if rfg_enabled else "Disabled",
            "SafeSEH": "Enabled/N/A" if (safeseh or no_seh) else "Disabled",
            "Stack Canaries (/GS)": "Enabled" if stack_canary else "Disabled",
            "Hardware Protection (CET/Shadow Stack)": "Enabled" if cet_enabled else "Disabled",
            "Force Integrity": "Enabled" if force_integ else "Disabled",
            "Isolation / AppContainer": "Enabled" if app_container else "Disabled"
        }

    # ==========================================
    # FR-STA-04 & 08: Section Entropy, Packing & Permissions
    # ==========================================
    def _analyze_sections(self, pe, results):

        pub.sendMessage("gui.log", msg="[*] Calculating Section Entropy and Permissions...")
        section_data = {}
        
        # PE Section Characteristic Masks
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        IMAGE_SCN_MEM_READ = 0x40000000
        IMAGE_SCN_MEM_WRITE = 0x80000000

        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            entropy = self._calculate_entropy(section.get_data())
            chars = section.Characteristics
            
            # Determine R/W/E Permissions
            readable = "R" if chars & IMAGE_SCN_MEM_READ else "-"
            writable = "W" if chars & IMAGE_SCN_MEM_WRITE else "-"
            executable = "E" if chars & IMAGE_SCN_MEM_EXECUTE else "-"
            permissions = f"{readable}{writable}{executable}"
            
            flags = []
            
            # Flag high entropy (Packing/Encryption)
            if entropy >= self.entropy_threshold:
                flags.append("[PACKED/HIGH ENTROPY]")
                
            # Flag RWE permissions (Suspicious memory allocation)
            if permissions == "RWE":
                flags.append("[SUSPICIOUS RWE]")
                pub.sendMessage("gui.log", msg=f"  [CRITICAL] Section {name} is Writeable and Executable (RWE)!")

            flag_str = " ".join(flags)
            if flag_str:
                pub.sendMessage("gui.log", msg=f"  -> Section {name} | Perms: {permissions} | Entropy: {entropy:.2f} {flag_str}")
            
            # Format output for the GUI Result Table
            section_data[f"Section: {name}"] = f"Perms: {permissions} | Entropy: {entropy:.2f} {flag_str}"
            
        results["Sections"] = section_data
    
    def _calculate_entropy(self, data):
        """Calculates Shannon Entropy for a byte sequence (FR-STA-04)."""
        if not data: 
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
                
        return entropy

    # ==========================================
    # FR-STA-05: Suspicious Import Tracking
    # ==========================================
    def _analyze_imports(self, pe, results):
        found_suspicious = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if not imp.name:
                        continue
                    imp_name = imp.name.decode('utf-8', errors='replace') if isinstance(imp.name, bytes) else str(imp.name)
                    if any(target in imp_name for target in self.target_imports):
                        found_suspicious.append(imp_name)
        
        if found_suspicious:
            pub.sendMessage("gui.log", msg=f"  [WARNING] Suspicious APIs detected: {', '.join(found_suspicious)}")
            
        results["Suspicious Imports"] = {
            "Tracked APIs Found": len(found_suspicious),
            "APIs": ", ".join(found_suspicious) if found_suspicious else "None detected"
        }

    # ==========================================
    # FR-STA-01: Manifest Analysis
    # ==========================================
    def _extract_manifest(self, pe, results):
        manifest_data = "Not Found"
        privilege_level = "Unknown"
        
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.id == pefile.RESOURCE_TYPE['RT_MANIFEST']: # ID 24 is Manifest
                    for resource_id in resource_type.directory.entries:
                        for resource_lang in resource_id.directory.entries:
                            offset = resource_lang.data.struct.OffsetToData
                            size = resource_lang.data.struct.Size
                            data = pe.get_memory_mapped_image()[offset:offset+size]
                            
                            try:
                                root = ET.fromstring(data)
                                namespace = {'ns': 'urn:schemas-microsoft-com:asm.v3'}
                                exe_level = root.find('.//ns:requestedExecutionLevel', namespace)
                                if exe_level is not None:
                                    privilege_level = exe_level.get('level', 'Unknown')
                                manifest_data = "Parsed Successfully"
                            except Exception:
                                manifest_data = "Malformed XML"

        results["Manifest Data"] = {
            "Manifest Status": manifest_data,
            "Requested Execution Level": privilege_level
        }

    # ==========================================
    # FR-STA-06: Automated String Extraction
    # ==========================================
    def _extract_strings(self, filepath, results):
        pub.sendMessage("gui.log", msg="[*] Executing regex string extraction loops...")
        extracted_counts = {k: 0 for k in self.regex_patterns.keys()}
        extracted_artifacts = {k: [] for k in self.regex_patterns.keys()}

        with open(filepath, 'rb') as f:
            data = f.read()
            for key, pattern in self.regex_patterns.items():
                matches = set(pattern.findall(data))
                decoded = sorted(m.decode('utf-8', errors='replace') for m in matches)
                extracted_counts[key] = len(decoded)
                extracted_artifacts[key] = decoded
                if decoded:
                    pub.sendMessage("gui.log", msg=f"  -> Found {len(decoded)} {key}(s): {', '.join(decoded[:3])}{' ...' if len(decoded) > 3 else ''}")

        results["Strings Analytics"] = extracted_counts
        results["Extracted Artifacts"] = extracted_artifacts

    # ==========================================
    # FR-STA-07 & 08: Local YARA Processing
    # ==========================================
    def _run_yara(self, filepath, results):
        if not self.yara_rules:
            results["YARA"] = {"Status": "Engine not initialized"}
            return
            
        pub.sendMessage("gui.log", msg="[*] Running YARA Rulesets...")
        matches = self.yara_rules.match(filepath)
        
        match_names = []
        if matches:
            for match in matches:
                pub.sendMessage("gui.log", msg=f"  [!!!] YARA Signature Hit: {match.rule}")
                match_names.append(match.rule)
                
        results["YARA Signatures"] = {
            "Hits": len(matches),
            "Matched Rules": ", ".join(match_names) if match_names else "Clean"
        }