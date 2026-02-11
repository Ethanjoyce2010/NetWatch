"""
DLL Inspector — detects suspicious DLL injection in running processes.

Enumerates loaded modules for each process and flags DLLs that:
  1. Are loaded from temp / user-writable / download directories
  2. Don't match the process's own install directory or system dirs
  3. Have known-malicious names
  4. Have random-looking filenames (entropy check)
  5. Are unsigned or have no version info (placeholder for future)
  6. Are loaded into processes that shouldn't have them
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import math
import os
import re
import string
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import psutil

from .models import Alert, Severity
from .threat_intel import ThreatIntelManager, get_threat_intel

logger = logging.getLogger("netwatch.dll_inspector")

# ======================================================================
# Windows API bindings for module enumeration
# ======================================================================

try:
    _psapi = ctypes.WinDLL("psapi", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _EnumProcessModulesEx = _psapi.EnumProcessModulesEx
    _EnumProcessModulesEx.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.POINTER(ctypes.wintypes.HMODULE),
        ctypes.wintypes.DWORD,
        ctypes.POINTER(ctypes.wintypes.DWORD),
        ctypes.wintypes.DWORD,
    ]
    _EnumProcessModulesEx.restype = ctypes.wintypes.BOOL

    _GetModuleFileNameExW = _psapi.GetModuleFileNameExW
    _GetModuleFileNameExW.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.wintypes.HMODULE,
        ctypes.wintypes.LPWSTR,
        ctypes.wintypes.DWORD,
    ]
    _GetModuleFileNameExW.restype = ctypes.wintypes.DWORD

    _OpenProcess = _kernel32.OpenProcess
    _OpenProcess.argtypes = [
        ctypes.wintypes.DWORD,
        ctypes.wintypes.BOOL,
        ctypes.wintypes.DWORD,
    ]
    _OpenProcess.restype = ctypes.wintypes.HANDLE

    _CloseHandle = _kernel32.CloseHandle

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    LIST_MODULES_ALL = 0x03

    _WINAPI_AVAILABLE = True
except (OSError, AttributeError):
    _WINAPI_AVAILABLE = False
    logger.info("Windows API not available — DLL inspection disabled on this platform.")


# ======================================================================
# Suspicious indicators
# ======================================================================

# Directories where legitimate DLLs almost never live
SUSPICIOUS_DIRS: list[str] = [
    os.path.expandvars(r"%TEMP%").lower(),
    os.path.expandvars(r"%TMP%").lower(),
    os.path.expandvars(r"%USERPROFILE%\Downloads").lower(),
    os.path.expandvars(r"%USERPROFILE%\Desktop").lower(),
    os.path.expandvars(r"%USERPROFILE%\Documents").lower(),
    os.path.expandvars(r"%APPDATA%\Local\Temp").lower(),
    os.path.expandvars(r"%LOCALAPPDATA%\Temp").lower(),
    r"c:\users\public",
    r"c:\perflogs",
]

# System directories where DLLs are expected
SYSTEM_DIRS: set[str] = {
    os.environ.get("SYSTEMROOT", r"C:\Windows").lower(),
    os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32").lower(),
    os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "SysWOW64").lower(),
    os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "WinSxS").lower(),
    os.environ.get("PROGRAMFILES", r"C:\Program Files").lower(),
    os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)").lower(),
    os.environ.get("COMMONPROGRAMFILES", r"C:\Program Files\Common Files").lower(),
}

# DLL names commonly associated with injection / hooking / malware
KNOWN_SUSPICIOUS_DLLS: set[str] = {
    # Credential stealers / keyloggers
    "mimilib.dll", "mimidrv.sys", "sekurlsa.dll",
    # Common injected DLLs
    "inject.dll", "payload.dll", "hook.dll", "hooker.dll",
    "evil.dll", "malware.dll", "backdoor.dll", "shell.dll",
    "reverse.dll", "beacon.dll", "stage.dll", "loader.dll",
    # Cobalt Strike indicators
    "beacon.dll", "pivot.dll",
    # Reflective loader stubs
    "reflective.dll", "reflectiveloader.dll",
    # Process hollowing tools
    "hollow.dll", "runpe.dll",
    # Proxy / tunnel DLLs
    "proxydll.dll", "tunnel.dll",
    # Generic persistence
    "persistence.dll", "startup.dll",
    # DLL side-loading common names
    "version.dll", "userenv.dll", "winhttp.dll", "dbghelp.dll",
    "crypt32.dll", "msimg32.dll", "cryptsp.dll",
}

# DLLs often abused for side-loading — suspicious ONLY when loaded from
# a non-system directory (attackers drop a rogue copy next to an exe)
SIDELOAD_CANDIDATES: set[str] = {
    "version.dll", "userenv.dll", "winhttp.dll", "dbghelp.dll",
    "msimg32.dll", "cryptsp.dll", "dwmapi.dll", "uxtheme.dll",
    "comctl32.dll", "propsys.dll", "profapi.dll", "ntmarta.dll",
    "secur32.dll", "netapi32.dll", "samcli.dll", "dnsapi.dll",
}

# Processes that should have a very small / well-known DLL footprint
# If these load unusual DLLs it's a strong injection indicator
TIGHT_PROCESSES: dict[str, set[str]] = {
    "notepad.exe": {"kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
                     "comctl32.dll", "msvcrt.dll", "advapi32.dll", "shell32.dll",
                     "comdlg32.dll", "imm32.dll", "oleaut32.dll", "ole32.dll",
                     "uxtheme.dll", "shcore.dll", "kernelbase.dll", "rpcrt4.dll",
                     "sechost.dll", "shlwapi.dll", "combase.dll", "bcryptprimitives.dll",
                     "ucrtbase.dll", "msvcp_win.dll", "win32u.dll", "clbcatq.dll",},
    "calc.exe": set(),
    "mspaint.exe": set(),
}


# ======================================================================
# Data structures
# ======================================================================

@dataclass
class LoadedModule:
    """A single DLL / module loaded in a process."""
    path: str
    name: str
    directory: str
    exists_on_disk: bool = True


@dataclass
class DLLScanResult:
    """Results of scanning one process for injected DLLs."""
    pid: int
    process_name: str
    exe_path: Optional[str] = None
    total_modules: int = 0
    suspicious_modules: list[dict] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return len(self.suspicious_modules) > 0


# ======================================================================
# Inspector
# ======================================================================

class DLLInspector:
    """Enumerates and analyses loaded DLLs across processes."""

    def __init__(self, threat_intel: Optional[ThreatIntelManager] = None):
        if not _WINAPI_AVAILABLE:
            logger.warning("DLL inspection requires Windows — feature disabled.")
        self.threat_intel = threat_intel or get_threat_intel()
        # Merge extended definitions from threat intel
        self._all_suspicious_dlls = KNOWN_SUSPICIOUS_DLLS | self.threat_intel.get_suspicious_dlls()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_process(self, pid: int) -> Optional[DLLScanResult]:
        """Scan a single process for suspicious loaded DLLs."""
        if not _WINAPI_AVAILABLE:
            return None

        try:
            proc = psutil.Process(pid)
            pname = proc.name().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

        exe_path = None
        try:
            exe_path = proc.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            pass

        modules = self._enum_modules(pid)
        if modules is None:
            return None

        result = DLLScanResult(
            pid=pid,
            process_name=proc.name(),
            exe_path=exe_path,
            total_modules=len(modules),
        )

        proc_dir = os.path.dirname(exe_path).lower() if exe_path else ""

        for mod in modules:
            reasons = self._check_module(mod, pname, proc_dir)
            if reasons:
                entry = {
                    "path": mod.path,
                    "name": mod.name,
                    "exists_on_disk": mod.exists_on_disk,
                    "reasons": reasons,
                }
                result.suspicious_modules.append(entry)

                # Determine severity from reasons
                severity = self._severity_from_reasons(reasons)
                alert = Alert(
                    rule_name="Suspicious DLL",
                    severity=severity,
                    description=f"'{mod.name}' loaded in {proc.name()} — {', '.join(reasons)}",
                    pid=pid,
                    process_name=proc.name(),
                    details=entry,
                )
                result.alerts.append(alert)

        return result

    def scan_all(self, pids: Optional[list[int]] = None) -> list[DLLScanResult]:
        """Scan multiple (or all) processes. Returns only those with findings."""
        if not _WINAPI_AVAILABLE:
            return []

        targets = pids or [p.pid for p in psutil.process_iter(["pid"])]
        results: list[DLLScanResult] = []

        for pid in targets:
            if pid in (0, 4):  # Skip System / Idle
                continue
            result = self.scan_process(pid)
            if result and result.is_suspicious:
                results.append(result)

        results.sort(key=lambda r: len(r.suspicious_modules), reverse=True)
        return results

    # ------------------------------------------------------------------
    # Module enumeration via Win32 API
    # ------------------------------------------------------------------

    def _enum_modules(self, pid: int) -> Optional[list[LoadedModule]]:
        """Use EnumProcessModulesEx to list all loaded modules."""
        handle = _OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not handle:
            return None

        try:
            modules: list[LoadedModule] = []
            h_modules = (ctypes.wintypes.HMODULE * 1024)()
            cb_needed = ctypes.wintypes.DWORD()

            ok = _EnumProcessModulesEx(
                handle,
                h_modules,
                ctypes.sizeof(h_modules),
                ctypes.byref(cb_needed),
                LIST_MODULES_ALL,
            )
            if not ok:
                return None

            count = cb_needed.value // ctypes.sizeof(ctypes.wintypes.HMODULE)
            buf = ctypes.create_unicode_buffer(512)

            for i in range(count):
                length = _GetModuleFileNameExW(handle, h_modules[i], buf, 512)
                if length:
                    path = buf.value
                    name = os.path.basename(path).lower()
                    directory = os.path.dirname(path).lower()
                    exists = os.path.isfile(path)
                    modules.append(LoadedModule(
                        path=path,
                        name=name,
                        directory=directory,
                        exists_on_disk=exists,
                    ))

            return modules
        finally:
            _CloseHandle(handle)

    # ------------------------------------------------------------------
    # Heuristic checks
    # ------------------------------------------------------------------

    def _check_module(
        self, mod: LoadedModule, process_name: str, process_dir: str
    ) -> list[str]:
        """Return a list of reasons this module is suspicious (empty = clean)."""
        reasons: list[str] = []

        name = mod.name.lower()
        directory = mod.directory.lower()

        # Skip the process's own exe
        if name == process_name:
            return []

        # 1. Known malicious DLL name (includes threat intel extended list)
        if name in self._all_suspicious_dlls and not self._is_system_dir(directory):
            # Check if threat intel has more details
            ti_match = self.threat_intel.is_known_malicious_dll(name)
            if ti_match:
                reasons.append(f"known malicious DLL name '{name}' ({ti_match.source})")
            else:
                reasons.append(f"known suspicious DLL name '{name}'")

        # 2. Loaded from temp / downloads / user-writable directory
        for sus_dir in SUSPICIOUS_DIRS:
            if directory.startswith(sus_dir):
                reasons.append(f"loaded from suspicious directory: {mod.directory}")
                break

        # 3. DLL side-loading: known sideload candidate from non-system dir
        if name in SIDELOAD_CANDIDATES:
            if not self._is_system_dir(directory):
                reasons.append(f"potential DLL side-load — '{name}' loaded from non-system path")

        # 4. Module doesn't exist on disk (reflective / memory-only injection)
        # Skip this check for .NET managed assemblies — the CLR maps them
        # in memory and the on-disk path reported by the OS may not resolve.
        if not mod.exists_on_disk and not self._is_managed_assembly(directory, name):
            # Also skip dotnet host/fxr directories
            if "dotnet" not in directory:
                reasons.append("module file not found on disk (possible reflective injection)")

        # 5. High-entropy / random-looking filename (threshold 4.1 to avoid legit long names)
        stem = Path(name).stem
        if len(stem) >= 6 and self._filename_entropy(stem) > 4.1:
            if not self._is_system_dir(directory) and not directory.startswith(process_dir):
                if not self._is_app_module_dir(directory, process_dir):
                    reasons.append(f"random-looking filename (entropy={self._filename_entropy(stem):.2f})")

        # 6. Loaded into a "tight" process that shouldn't have extra DLLs
        if process_name in TIGHT_PROCESSES:
            allowed = TIGHT_PROCESSES[process_name]
            if allowed and name not in allowed and not self._is_system_dir(directory):
                reasons.append(f"unexpected DLL in {process_name}")

        # 7. DLL in a completely unrelated directory (not system, not process dir)
        if (
            not self._is_system_dir(directory)
            and process_dir
            and not directory.startswith(process_dir)
            and not reasons  # don't double-flag
        ):
            # Only flag if it's also not a well-known runtime or app-module dir
            if not self._is_runtime_dir(directory) and not self._is_app_module_dir(directory, process_dir):
                # Soft signal — only include if the name is also unusual
                if name not in self._COMMON_RUNTIME_DLLS:
                    reasons.append(f"loaded from unrelated directory: {mod.directory}")

        # 8. SHA256 hash check against threat intel (for DLLs in suspicious locations)
        if reasons and mod.exists_on_disk:
            hash_match = self.threat_intel.check_file_hash(mod.path)
            if hash_match:
                reasons.insert(0,
                    f"HASH MATCH: {hash_match.malware_family or 'malware'} "
                    f"({hash_match.source})"
                )

        return reasons

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_system_dir(directory: str) -> bool:
        """Check whether directory is under a known system location."""
        d = directory.lower()
        return any(d.startswith(sd) for sd in SYSTEM_DIRS)

    @staticmethod
    def _severity_from_reasons(reasons: list[str]) -> Severity:
        """Pick the highest severity based on the reason strings."""
        text = " ".join(reasons).lower()
        if "hash match" in text:
            return Severity.CRITICAL
        if "not found on disk" in text or "reflective" in text:
            return Severity.CRITICAL
        if "known suspicious" in text or "known malicious" in text or "unexpected dll" in text:
            return Severity.HIGH
        if "side-load" in text or "suspicious directory" in text:
            return Severity.HIGH
        if "random-looking" in text or "unrelated directory" in text:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _is_runtime_dir(directory: str) -> bool:
        """Directories for common runtimes (.NET, VC++, Java, etc.)."""
        patterns = [
            "microsoft.net", "dotnet", "assembly",
            "microsoft visual studio", "vc\\redist",
            "java", "jre", "jdk",
            "python", "node_modules",
            "nvidia", "amd", "intel",
            "microsoft\\edgewebview",
            "microsoft shared", "windows kits",
            "common files", "windowsapps",
            "microsoft sdks",
            ".vscode", "vscode", "vs code",
            "site-packages", "lib\\site",
            "powertoys", "steam",
        ]
        d = directory.lower()
        return any(p in d for p in patterns)

    @staticmethod
    def _is_app_module_dir(directory: str, process_dir: str) -> bool:
        """Check if the directory is a sub-module / plugin dir of the app.

        Many apps (Discord, VS Code, Chrome, etc.) load DLLs from
        sub-directories like `modules/`, `extensions/`, `plugins/`
        that share a common ancestor with the process directory.
        """
        d = directory.lower().lstrip("\\\\?\\").rstrip("\\")
        pd = process_dir.lower().lstrip("\\\\?\\").rstrip("\\")

        # Check if they share a common root (at least 3 path components deep)
        d_parts = d.replace("/", "\\").split("\\")
        pd_parts = pd.replace("/", "\\").split("\\")
        common = 0
        for a, b in zip(d_parts, pd_parts):
            if a == b:
                common += 1
            else:
                break
        if common >= 3:
            return True

        # Known app module sub-dir patterns
        module_markers = [
            "\\modules\\", "\\extensions\\", "\\plugins\\",
            "\\resources\\", "\\addons\\", "\\components\\",
            "\\bin\\", "\\lib\\",
        ]
        return any(m in d for m in module_markers) and common >= 2

    @staticmethod
    def _is_managed_assembly(directory: str, name: str) -> bool:
        """Return True if the module looks like a .NET managed assembly."""
        d = directory.lower()
        n = name.lower()
        # .NET runtime / shared framework directories
        dotnet_markers = [
            "dotnet\\shared", "microsoft.netcore.app",
            "microsoft.windowsdesktop.app", "microsoft.aspnetcore.app",
            "microsoft.net\\framework", "microsoft.net\\assembly",
            "dotnet\\packs", ".nuget",
        ]
        if any(m in d for m in dotnet_markers):
            return True
        # Common .NET system assembly prefixes
        if n.startswith(("system.", "microsoft.", "presentat", "windowsbase", "directwrite")):
            if "dotnet" in d or "microsoft.net" in d:
                return True
        return False

    @staticmethod
    def _filename_entropy(name: str) -> float:
        """Shannon entropy of a string — high entropy ≈ random name."""
        if not name:
            return 0.0
        freq: dict[str, int] = defaultdict(int)
        for ch in name.lower():
            freq[ch] += 1
        length = len(name)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    # DLLs that commonly appear from runtime / framework dirs
    _COMMON_RUNTIME_DLLS: set[str] = {
        "mscorlib.ni.dll", "clr.dll", "clrjit.dll", "coreclr.dll",
        "hostfxr.dll", "hostpolicy.dll", "vcruntime140.dll",
        "vcruntime140_1.dll", "msvcp140.dll", "ucrtbase.dll",
        "python3.dll", "python311.dll", "python312.dll", "python310.dll",
        "libcrypto-3-x64.dll", "libssl-3-x64.dll",
        "nvinit.dll", "nvoglv64.dll",
    }
