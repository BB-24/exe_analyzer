"""
MARS — Threat Scoring Engine
=============================
Produces a per-target ScoringResult from static and/or dynamic artefacts.

Architecture
------------
  MARSScorer.score_target(target, static_res, dyn_res)  →  ScoringResult
  MARSScorer.score_all(static_data, dyn_data, pkg_data) →  dict[str, ScoringResult]

Scoring is additive across six weighted categories that total a maximum of
100 raw points.  The raw sum is normalised to 0.0–10.0 and mapped to one of
four verdict labels:

  0.0 – 2.9   CLEAN
  3.0 – 4.9   SUSPICIOUS
  5.0 – 7.4   HIGH RISK
  7.5 – 10.0  MALICIOUS

Confidence tracks how much evidence was available:
  LOW      only one analysis phase ran, or fewer than 3 scoring signals fired
  MEDIUM   both phases present, 3–7 signals
  HIGH     both phases present, 8+ signals
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field
from pubsub import pub


# ══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class ScoreCategory:
    """One scoring dimension with its raw contribution and human-readable findings."""
    name:       str
    score:      float          # points awarded in this category
    max_score:  float          # maximum possible points
    weight_pct: float          # percentage of total score this category represents
    findings:   list[str] = field(default_factory=list)

    @property
    def normalised(self) -> float:
        """Category score as 0.0–10.0."""
        if self.max_score == 0:
            return 0.0
        return min((self.score / self.max_score) * 10.0, 10.0)

    def to_dict(self) -> dict:
        return {
            "name":        self.name,
            "score":       round(self.score, 2),
            "max_score":   self.max_score,
            "weight_pct":  self.weight_pct,
            "normalised":  round(self.normalised, 2),
            "findings":    self.findings,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScoreCategory":
        return cls(
            name=d.get("name", ""),
            score=float(d.get("score", 0)),
            max_score=float(d.get("max_score", 10)),
            weight_pct=float(d.get("weight_pct", 0)),
            findings=list(d.get("findings", [])),
        )


@dataclass
class ScoringResult:
    """Complete scoring result for a single analysed executable."""
    target:      str
    verdict:     str           # CLEAN / SUSPICIOUS / HIGH RISK / MALICIOUS
    total_score: float         # 0.0 – 10.0
    confidence:  str           # LOW / MEDIUM / HIGH
    categories:  list[ScoreCategory] = field(default_factory=list)
    timestamp:   str = field(default_factory=lambda: datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))

    # Convenience accessors
    @property
    def verdict_color_hex(self) -> str:
        return {
            "MALICIOUS": "#BE1414",
            "HIGH RISK": "#B45309",
            "SUSPICIOUS":"#D97706",
            "CLEAN":     "#047857",
        }.get(self.verdict, "#263056")

    @property
    def verdict_bg_hex(self) -> str:
        return {
            "MALICIOUS": "#FEF2F2",
            "HIGH RISK": "#FFFBEB",
            "SUSPICIOUS":"#FFFBEB",
            "CLEAN":     "#ECFDF5",
        }.get(self.verdict, "#F0F4FF")

    def top_findings(self, n: int = 5) -> list[str]:
        """Return the most significant findings across all categories."""
        all_findings = []
        for cat in self.categories:
            all_findings.extend(cat.findings)
        return all_findings[:n]

    def to_dict(self) -> dict:
        return {
            "target":      self.target,
            "verdict":     self.verdict,
            "total_score": round(self.total_score, 2),
            "confidence":  self.confidence,
            "timestamp":   self.timestamp,
            "categories":  [c.to_dict() for c in self.categories],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScoringResult":
        return cls(
            target=d.get("target", ""),
            verdict=d.get("verdict", "CLEAN"),
            total_score=float(d.get("total_score", 0)),
            confidence=d.get("confidence", "LOW"),
            categories=[ScoreCategory.from_dict(c) for c in d.get("categories", [])],
            timestamp=d.get("timestamp", ""),
        )


# ══════════════════════════════════════════════════════════════════════════
# SCORING RULES  (keyword → points)
# ══════════════════════════════════════════════════════════════════════════

# Dynamic event patterns: (regex_pattern, points, label)
_DYN_EVENT_RULES: list[tuple[str, float, str]] = [
    (r"PROCESS_HOLLOW|NtUnmapViewOfSection|ZwUnmapViewOfSection",
     9.0,  "Process hollowing detected"),
    (r"INJECT|WriteProcessMemory|CreateRemoteThread|SetThreadContext",
     8.0,  "Process injection technique observed"),
    (r"RANSOM|CryptEncrypt|CryptGenKey|\.locked|\.crypt",
     9.5,  "Ransomware / encryption activity"),
    (r"REG_RUN_KEY|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
     5.0,  "Registry persistence (Run key) established"),
    (r"SCHTASK|schtasks|TaskScheduler|TASK_CREATE",
     4.5,  "Scheduled task persistence mechanism"),
    (r"OpenSCManager|CreateService|SERVICE_AUTO_START",
     5.0,  "Windows service installed for persistence"),
    (r"AdjustTokenPrivileges|SeDebugPrivilege|PRIVILEGE_ESCALAT",
     5.5,  "Privilege escalation attempt"),
    (r"FILE_DROP.*\.(exe|dll|sys|bat|ps1|vbs)",
     4.0,  "Executable payload dropped to disk"),
    (r"MEMORY_INJECT|VirtualAllocEx.*EXECUTE|PAGE_EXECUTE_READWRITE",
     6.0,  "Suspicious executable memory allocation"),
    (r"DNS.*evil|evil.*DNS|C2|beaconing|GET /payload|POST.*[0-9]{1,3}\.[0-9]{1,3}",
     5.0,  "Command-and-control network communication"),
    (r"NETWORK.*CONNECT|HttpSendRequest|InternetOpen.*http",
     2.5,  "Outbound network connection observed"),
    (r"UAC_BYPASS|ComSpec|fodhelper|eventvwr",
     6.0,  "UAC bypass technique detected"),
    (r"WMIC|powershell.*-enc|-encodedcommand|-nop.*bypass",
     4.0,  "Living-off-the-land binary abuse (LOLBIN)"),
    (r"KILL_PROCESS|TerminateProcess.*antivirus|taskkill.*defender",
     7.0,  "Security tool termination attempt"),
    (r"DeleteShadowCopy|vssadmin.*delete|bcdedit.*recoveryenabled no",
     8.5,  "Shadow copy deletion (anti-forensics / ransomware)"),
]

# Static import rules: (api_substring, points, label)
_IMPORT_RULES: list[tuple[str, float, str]] = [
    ("VirtualAllocEx",       3.5, "VirtualAllocEx — remote memory allocation"),
    ("WriteProcessMemory",   3.5, "WriteProcessMemory — process injection vector"),
    ("CreateRemoteThread",   4.0, "CreateRemoteThread — remote code execution"),
    ("SetThreadContext",     3.5, "SetThreadContext — thread hijacking"),
    ("NtWriteVirtualMemory", 3.5, "NtWriteVirtualMemory — low-level injection"),
    ("ZwUnmapViewOfSection", 4.0, "ZwUnmapViewOfSection — process hollowing"),
    ("NtUnmapViewOfSection", 4.0, "NtUnmapViewOfSection — process hollowing"),
    ("OpenSCManager",        3.0, "OpenSCManager — service manipulation"),
    ("CreateService",        3.0, "CreateService — service persistence"),
    ("RegSetValueEx",        2.0, "RegSetValueEx — registry modification"),
    ("AdjustTokenPrivileges",3.0, "AdjustTokenPrivileges — privilege escalation"),
    ("IsDebuggerPresent",    2.0, "IsDebuggerPresent — anti-analysis"),
    ("CheckRemoteDebugger",  2.0, "CheckRemoteDebuggerPresent — anti-analysis"),
    ("CryptEncrypt",         3.5, "CryptEncrypt — encryption capability"),
    ("CryptGenKey",          3.0, "CryptGenKey — encryption key generation"),
    ("SetWindowsHookEx",     2.5, "SetWindowsHookEx — keylogging / hook"),
    ("InternetOpenUrl",      2.0, "InternetOpenUrl — HTTP client"),
    ("HttpSendRequest",      2.0, "HttpSendRequest — HTTP C2 capability"),
    ("WinHttpOpen",          2.0, "WinHttpOpen — HTTP client"),
    ("ShellExecuteA",        1.5, "ShellExecuteA — shell command execution"),
    ("ShellExecuteW",        1.5, "ShellExecuteW — shell command execution"),
    ("WinExec",              2.0, "WinExec — command execution"),
]

# Mitigation penalties (each disabled mitigation adds risk)
_MITIGATION_PENALTIES: dict[str, float] = {
    "DEP / NX Bit":                      1.5,
    "ASLR":                              1.5,
    "CFG (Control Flow Guard)":          1.0,
    "Stack Canaries (/GS)":              1.0,
    "RFG (Return Flow Guard)":           0.5,
    "SafeSEH":                           0.5,
    "Hardware Protection (CET/Shadow Stack)": 0.5,
    "Force Integrity":                   0.5,
}


# ══════════════════════════════════════════════════════════════════════════
# SCORER
# ══════════════════════════════════════════════════════════════════════════

class MARSScorer:
    """
    Stateless scoring engine.  Call score_target() per executable or
    score_all() to process every target from the pipeline data dictionaries.
    """

    # Maximum raw points per category (used for normalisation)
    _MAX_YARA       = 20.0
    _MAX_IMPORTS    = 18.0
    _MAX_SECTIONS   = 14.0
    _MAX_MITIGATIONS= 8.0
    _MAX_STRINGS    = 8.0
    _MAX_DYNAMIC    = 40.0

    # Category weight percentages (informational, displayed in report)
    _WEIGHTS = {
        "YARA Signatures":    "20%",
        "Suspicious Imports": "18%",
        "Section Analysis":   "14%",
        "Mitigations":        "8%",
        "String Artefacts":   "8%",
        "Dynamic Behaviour":  "32%",
    }

    # ── Public API ─────────────────────────────────────────────────────

    def score_all(
        self,
        static_data: dict,
        dynamic_data: dict,
        pkg_data: list | None = None,
    ) -> dict[str, ScoringResult]:
        """
        Score every target present in static_data and/or dynamic_data.
        Returns a dict keyed by target filename.
        """
        targets = set(static_data.keys()) | set(dynamic_data.keys())
        results: dict[str, ScoringResult] = {}
        for target in sorted(targets):
            sr = self.score_target(
                target,
                static_data.get(target),
                dynamic_data.get(target),
                pkg_data=pkg_data,
            )
            results[target] = sr
            pub.sendMessage(
                "gui.log",
                msg=(
                    f"  [SCORE] {target}: {sr.verdict} "
                    f"({sr.total_score:.1f}/10.0) — {sr.confidence} confidence"
                ),
            )
            pub.sendMessage("scoring.result", result=sr)
        return results

    def score_target(
        self,
        target: str,
        static_res: dict | None,
        dyn_res:    dict | None,
        *,
        pkg_data: list | None = None,
    ) -> ScoringResult:
        """Score a single executable target and return a ScoringResult."""
        categories: list[ScoreCategory] = []
        signal_count = 0

        if static_res and isinstance(static_res, dict):
            yara_cat = self._score_yara(static_res)
            imp_cat  = self._score_imports(static_res)
            sec_cat  = self._score_sections(static_res)
            mit_cat  = self._score_mitigations(static_res)
            str_cat  = self._score_strings(static_res)
            categories += [yara_cat, imp_cat, sec_cat, mit_cat, str_cat]
            signal_count += sum(
                1 for c in [yara_cat, imp_cat, sec_cat, mit_cat, str_cat]
                if c.findings
            )

        if dyn_res and isinstance(dyn_res, dict) and "Error" not in dyn_res:
            dyn_cat = self._score_dynamic(dyn_res)
            categories.append(dyn_cat)
            signal_count += bool(dyn_cat.findings)

        # Aggregate raw score
        raw_total = sum(c.score for c in categories)
        raw_max   = sum(c.max_score for c in categories) or 1.0
        total_score = round(min((raw_total / raw_max) * 10.0, 10.0), 2)

        verdict    = self._verdict(total_score)
        confidence = self._confidence(
            has_static=bool(static_res),
            has_dynamic=bool(dyn_res and "Error" not in dyn_res),
            signal_count=signal_count,
        )

        return ScoringResult(
            target=target,
            verdict=verdict,
            total_score=total_score,
            confidence=confidence,
            categories=categories,
        )

    # ── Category scorers ───────────────────────────────────────────────

    def _score_yara(self, static: dict) -> ScoreCategory:
        yara_data = static.get("YARA Signatures", {})
        hits      = 0
        findings  = []

        if isinstance(yara_data, dict):
            raw_hits = yara_data.get("Hits", 0)
            try:
                hits = int(raw_hits)
            except (TypeError, ValueError):
                hits = 0
            rules = str(yara_data.get("Matched Rules", ""))
            if hits > 0 and rules and rules.lower() != "clean":
                for rule in rules.split(","):
                    rule = rule.strip()
                    if rule:
                        findings.append(f"YARA rule matched: {rule}")

        pts = min(hits * 5.0, self._MAX_YARA)
        return ScoreCategory(
            name="YARA Signatures",
            score=pts,
            max_score=self._MAX_YARA,
            weight_pct=20.0,
            findings=findings,
        )

    def _score_imports(self, static: dict) -> ScoreCategory:
        imp_data = static.get("Suspicious Imports", {})
        findings = []
        pts      = 0.0

        if isinstance(imp_data, dict):
            api_str = str(imp_data.get("APIs", ""))
            apis    = [a.strip() for a in api_str.split(",") if a.strip() and a.strip() != "None detected"]
            for api in apis:
                for keyword, weight, label in _IMPORT_RULES:
                    if keyword.lower() in api.lower():
                        pts += weight
                        findings.append(label)
                        break  # one rule per import

        pts = min(pts, self._MAX_IMPORTS)
        return ScoreCategory(
            name="Suspicious Imports",
            score=pts,
            max_score=self._MAX_IMPORTS,
            weight_pct=18.0,
            findings=findings,
        )

    def _score_sections(self, static: dict) -> ScoreCategory:
        sec_data = static.get("Sections", {})
        findings = []
        pts      = 0.0

        if isinstance(sec_data, dict):
            for sec_name, sec_info in sec_data.items():
                info_str = str(sec_info).upper()
                if "PACKED" in info_str or "HIGH ENTROPY" in info_str:
                    pts += 3.5
                    findings.append(f"{sec_name}: high entropy / packed section")
                if "RWE" in info_str or "SUSPICIOUS RWE" in info_str:
                    pts += 4.0
                    findings.append(f"{sec_name}: RWE memory permissions (write + execute)")

        pts = min(pts, self._MAX_SECTIONS)
        return ScoreCategory(
            name="Section Analysis",
            score=pts,
            max_score=self._MAX_SECTIONS,
            weight_pct=14.0,
            findings=findings,
        )

    def _score_mitigations(self, static: dict) -> ScoreCategory:
        mit_data = static.get("Mitigations", {})
        findings = []
        pts      = 0.0

        if isinstance(mit_data, dict):
            for mit_name, penalty in _MITIGATION_PENALTIES.items():
                val = str(mit_data.get(mit_name, "")).lower()
                if val == "disabled":
                    pts += penalty
                    findings.append(f"{mit_name}: disabled (mitigation absent)")

        # Extra: requireAdministrator manifest = privilege escalation risk
        manifest = static.get("Manifest Data", {})
        if isinstance(manifest, dict):
            level = str(manifest.get("Requested Execution Level", "")).lower()
            if "administrator" in level:
                pts += 1.0
                findings.append("Manifest requests Administrator elevation")

        pts = min(pts, self._MAX_MITIGATIONS)
        return ScoreCategory(
            name="Mitigations",
            score=pts,
            max_score=self._MAX_MITIGATIONS,
            weight_pct=8.0,
            findings=findings,
        )

    def _score_strings(self, static: dict) -> ScoreCategory:
        str_counts   = static.get("Strings Analytics", {})
        str_artefacts = static.get("Extracted Artifacts", {})
        findings = []
        pts      = 0.0

        if isinstance(str_counts, dict):
            ip_count  = int(str_counts.get("IPv4", 0) or 0)
            url_count = int(str_counts.get("URL",  0) or 0)
            reg_count = int(str_counts.get("Registry", 0) or 0)
            email_cnt = int(str_counts.get("Email", 0) or 0)

            if ip_count:
                award = min(ip_count * 1.0, 3.0)
                pts  += award
                ips = str_artefacts.get("IPv4", [])[:3]
                findings.append(
                    f"{ip_count} embedded IP address(es): {', '.join(ips)}"
                    if ips else f"{ip_count} embedded IP address(es)"
                )
            if url_count:
                award = min(url_count * 1.0, 2.5)
                pts  += award
                urls = str_artefacts.get("URL", [])[:2]
                findings.append(
                    f"{url_count} embedded URL(s): {', '.join(urls)}"
                    if urls else f"{url_count} embedded URL(s)"
                )
            if reg_count:
                award = min(reg_count * 0.8, 2.0)
                pts  += award
                findings.append(f"{reg_count} embedded registry path(s)")
            if email_cnt:
                pts += min(email_cnt * 0.5, 1.0)
                findings.append(f"{email_cnt} email address(es) embedded in binary")

        pts = min(pts, self._MAX_STRINGS)
        return ScoreCategory(
            name="String Artefacts",
            score=pts,
            max_score=self._MAX_STRINGS,
            weight_pct=8.0,
            findings=findings,
        )

    def _score_dynamic(self, dyn_res: dict) -> ScoreCategory:
        findings: list[str] = []
        pts = 0.0

        # Collect all event strings from every telemetry category
        all_events: list[str] = []
        for cat_events in dyn_res.values():
            if isinstance(cat_events, list):
                all_events.extend(str(e) for e in cat_events)
            elif isinstance(cat_events, str):
                all_events.append(cat_events)

        fired: set[str] = set()   # prevent double-counting same rule

        for event_text in all_events:
            for pattern, weight, label in _DYN_EVENT_RULES:
                if label in fired:
                    continue
                if re.search(pattern, event_text, re.IGNORECASE):
                    pts += weight
                    findings.append(label)
                    fired.add(label)

        pts = min(pts, self._MAX_DYNAMIC)
        return ScoreCategory(
            name="Dynamic Behaviour",
            score=pts,
            max_score=self._MAX_DYNAMIC,
            weight_pct=32.0,
            findings=findings,
        )

    # ── Verdict / confidence helpers ───────────────────────────────────

    @staticmethod
    def _verdict(score: float) -> str:
        if score >= 7.5:
            return "MALICIOUS"
        if score >= 5.0:
            return "HIGH RISK"
        if score >= 3.0:
            return "SUSPICIOUS"
        return "CLEAN"

    @staticmethod
    def _confidence(has_static: bool, has_dynamic: bool, signal_count: int) -> str:
        if has_static and has_dynamic and signal_count >= 8:
            return "HIGH"
        if (has_static or has_dynamic) and signal_count >= 3:
            return "MEDIUM"
        return "LOW"
