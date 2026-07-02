
/*
   MARS - Comprehensive Static Analysis YARA Ruleset
   Author: MARS System Architect
   Description: Consolidated ruleset targeting known malware signatures, 
   tactical tradecraft, evasion, obfuscation, modern frameworks, and LotL abuse.
*/

import "pe"

// ============================================================================
// 1. Known Malware & Infrastructure Signatures
// ============================================================================

rule Suspicious_PDB_Paths {
    meta:
        description = "Detects suspicious hardcoded PDB compilation paths"
        category = "1. Known Malware"
    strings:
        $pdb1 = "\\mimikatz\\" ascii nocase
        $pdb2 = "\\cobaltstrike\\" ascii nocase
        $pdb3 = "\\Release\\payload.pdb" ascii nocase
        $pdb4 = "\\Release\\beacon.pdb" ascii nocase
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule Malicious_C2_Indicators {
    meta:
        description = "Detects hardcoded C2 framework User-Agents and domains"
        category = "1. Known Malware"
    strings:
        $ua1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36" // Common default CS UA
        $ua2 = "Meterpreter" ascii wide nocase
        $http_ind1 = "/dpixel" ascii wide
        $http_ind2 = "/submit.php?id=" ascii wide
    condition:
        uint16(0) == 0x5a4d and any of them
}

// ============================================================================
// 2. Tactical Execution & Tradecraft
// ============================================================================

rule Tactical_Process_Injection {
    meta:
        description = "Detects combination of APIs used for Process Injection/Hollowing"
        category = "2. Tactical Execution"
    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "QueueUserAPC" ascii wide
        $api5 = "SetThreadContext" ascii wide
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule Tactical_Anti_Analysis {
    meta:
        description = "Detects anti-debugging and anti-VM strings/imports"
        category = "2. Tactical Execution"
    strings:
        $api1 = "IsDebuggerPresent" ascii wide
        $api2 = "CheckRemoteDebuggerPresent" ascii wide
        $vm1 = "VMware" ascii wide nocase
        $vm2 = "VBox" ascii wide nocase
        $vm3 = "VirtualBox" ascii wide nocase
        $vm4 = "QEMU" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and (2 of ($api*) or any of ($vm*))
}

rule Tactical_Credential_Dumping {
    meta:
        description = "Detects interactions with LSASS or MiniDump APIs"
        category = "2. Tactical Execution"
    strings:
        $s1 = "lsass.exe" ascii wide nocase
        $s2 = "samlib.dll" ascii wide nocase
        $api1 = "MiniDumpWriteDump" ascii wide
        $api2 = "LogonUserA" ascii wide
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or any of ($api*))
}

rule Tactical_Keylogging {
    meta:
        description = "Detects user input hooking APIs"
        category = "2. Tactical Execution"
    strings:
        $api1 = "SetWindowsHookEx" ascii wide
        $api2 = "GetAsyncKeyState" ascii wide
        $api3 = "GetKeyboardState" ascii wide
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

// ============================================================================
// 3. Defense Evasion & Bypassing
// ============================================================================

rule Evasion_AMSI_ETW_Patching {
    meta:
        description = "Detects indicators of AMSI or ETW telemetry patching"
        category = "3. Defense Evasion"
    strings:
        $amsi1 = "amsi.dll" ascii wide nocase
        $amsi2 = "AmsiScanBuffer" ascii wide
        $etw1 = "EtwEventWrite" ascii wide
        $etw2 = "nttrace" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and (all of ($amsi*) or all of ($etw*))
}

rule Evasion_Direct_Syscalls {
    meta:
        description = "Detects assembly stubs matching direct system calls (x64)"
        category = "3. Defense Evasion"
    strings:
        // mov r10, rcx; mov eax, <syscall_num>; syscall
        $syscall_stub = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 }
    condition:
        uint16(0) == 0x5a4d and $syscall_stub
}

rule Evasion_PEB_Walking {
    meta:
        description = "Detects assembly patterns for PEB walking to manually resolve APIs"
        category = "3. Defense Evasion"
    strings:
        // mov eax, fs:[0x30] (x86)
        $peb32 = { 64 A1 30 00 00 00 }
        // mov rax, gs:[0x60] (x64)
        $peb64 = { 65 48 8B 04 25 60 00 00 00 }
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule Evasion_API_Hashing_Constants {
    meta:
        description = "Detects constants commonly used in API hashing (e.g., CRC32, Murmur)"
        category = "3. Defense Evasion"
    strings:
        // CRC32 Polynomial
        $crc32 = { 20 83 B8 ED } 
        // MurmurHash3 constants
        $murmur1 = { 2B 65 EB 85 }
        $murmur2 = { 32 16 EB C6 }
    condition:
        uint16(0) == 0x5a4d and any of them
}

// ============================================================================
// 4. Obfuscation, Packing & Encryption
// ============================================================================

rule Obfuscation_Packer_Signatures {
    meta:
        description = "Detects known software packers"
        category = "4. Obfuscation"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx_magic = { 55 50 58 21 } // UPX!
        $vmp = ".vmp0" ascii
        $themida1 = "Themida" ascii wide nocase
        $themida2 = "WinLicense" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and ( (2 of ($upx*) and $upx_magic) or $vmp or any of ($themida*) )
}

rule Obfuscation_Crypto_Constants {
    meta:
        description = "Detects cryptographic constants for AES, ChaCha20, or RSA"
        category = "4. Obfuscation"
    strings:
        $aes_te0 = { C6 63 63 A5 } // Common AES S-Box initialization marker
        $chacha = "expand 32-byte k" ascii // ChaCha20 initial matrix constant
        $str_aes = "AES-256" ascii wide nocase
        $str_rsa = "RSA-2048" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and any of them
}

// ============================================================================
// 5. File Structure Anomalies & Droppers
// ============================================================================

rule Dropper_Embedded_Executable {
    meta:
        description = "Detects multiple MZ headers indicating an embedded PE file"
        category = "5. File Structure"
    strings:
        $mz = "MZ"
    condition:
        uint16(0) == 0x5a4d and #mz > 1
}

// ============================================================================
// 6. Modern Languages & Frameworks
// ============================================================================

rule Framework_Golang_Binary {
    meta:
        description = "Identifies Golang compiled binaries"
        category = "6. Modern Languages"
    strings:
        $go1 = "Go build ID" ascii
        $go2 = "runtime.goexit" ascii
        $go3 = "go.buildid" ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule Framework_Rust_Binary {
    meta:
        description = "Identifies Rust compiled binaries"
        category = "6. Modern Languages"
    strings:
        $rust1 = "rustc" ascii
        $rust2 = "cargo" ascii
        $rust3 = "core::panicking" ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule Framework_AutoIt_Dropper {
    meta:
        description = "Detects embedded AutoIt/AutoHotkey scripts"
        category = "6. Modern Languages"
    strings:
        $autoit_magic = "AU3!EA06" ascii
        $autoit_str = "AutoIt v3" ascii wide
        $ahk_str = "AutoHotkey" ascii wide
    condition:
        uint16(0) == 0x5a4d and any of them
}

// ============================================================================
// 7. Living Off the Land (LotL) & Third-Party Abuse
// ============================================================================

rule LotL_PowerShell_Abuse {
    meta:
        description = "Detects hardcoded PowerShell bypass and execution flags"
        category = "7. LotL"
    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "-ep bypass" ascii wide nocase
        $ps3 = "-ExecutionPolicy Bypass" ascii wide nocase
        $ps4 = "-enc" ascii wide nocase
        $ps5 = "-WindowStyle Hidden" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and ($ps1 and any of ($ps2, $ps3, $ps4, $ps5))
}

rule LotL_Native_Tool_Abuse {
    meta:
        description = "Detects hardcoded commands for vssadmin, certutil, or reg.exe"
        category = "7. LotL"
    strings:
        $vss = "vssadmin delete shadows" ascii wide nocase
        $cert = "certutil.exe -urlcache -split -f" ascii wide nocase
        $reg = "reg add HKLM\\Software\\Policies\\Microsoft\\Windows Defender" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule Abuse_Webhooks_And_Tokens {
    meta:
        description = "Detects hardcoded Discord/Telegram/Slack webhook URLs"
        category = "7. LotL"
    strings:
        $discord = "discord.com/api/webhooks/" ascii wide nocase
        $telegram = "api.telegram.org/bot" ascii wide nocase
        $slack = "hooks.slack.com/services/" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule Abuse_Bundled_RMM_Tools {
    meta:
        description = "Detects strings related to legitimate RMM software often abused by actors"
        category = "7. LotL"
    strings:
        $rmm1 = "AnyDesk" ascii wide nocase
        $rmm2 = "ScreenConnect" ascii wide nocase
        $rmm3 = "TeamViewer" ascii wide nocase
        $rmm4 = "Atera" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and any of them
}