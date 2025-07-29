#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integrated Security Monitor
Combines Sysmon log monitoring with periodic DLL scanning/removal.
"""
import os
import sys
import time
import json
import hashlib
import logging
import subprocess
import threading
from datetime import datetime, timedelta
from pathlib import Path
import re
import winreg
import xml.etree.ElementTree as ET
import traceback
import ctypes
from ctypes import windll, wintypes, byref, create_unicode_buffer
import base64
# At the top of your file with other imports
from ctypes import windll, wintypes, byref, create_unicode_buffer

# Then define the Windows Event Log API functions properly
wevtapi = windll.wevtapi

# Define the function prototypes
EvtQuery = wevtapi.EvtQuery
EvtQuery.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
EvtQuery.restype = wintypes.HANDLE

EvtNext = wevtapi.EvtNext
EvtNext.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
                    wintypes.DWORD, wintypes.DWORD, wintypes.PDWORD]
EvtNext.restype = wintypes.BOOL

EvtRender = wevtapi.EvtRender
EvtRender.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD,
                      wintypes.DWORD, wintypes.LPWSTR, wintypes.PDWORD,
                      wintypes.PDWORD]
EvtRender.restype = wintypes.BOOL

EvtClose = wevtapi.EvtClose
EvtClose.argtypes = [wintypes.HANDLE]
EvtClose.restype = wintypes.BOOL
# --- Dependency Check ---
try:
    import psutil
except ImportError:
    print("Missing required module: psutil")
    print("Install with: pip install psutil")
    sys.exit(1)

# --- Constants ---
# Winevt API
EVT_QUERY_CHANNEL_PATH = 0x1
EVT_RENDER_EVENT_XML = 1
ERROR_NO_MORE_ITEMS = 259

# Sysmon Detection
SMB_PORTS = {445, 139}
LATERAL_TOOLS = {
    "powershell.exe", "cmd.exe", "psexec.exe", "wmic.exe", "wmiprvse.exe",
    "sc.exe", "reg.exe", "rundll32.exe", "at.exe", "schtasks.exe",
    "python.exe", "pythonw.exe", "python3.exe", "python3.11.exe"
}

# --- Global Variables ---
WINDOWS_AVAILABLE = (os.name == 'nt')
MAIN_LOG_FILE = "security_monitor.log"
DLL_LOG_FILE = "dll_scan.log"

# --- Configuration ---
PROCESSUS_LEGITIMES = {
    "services.exe", "svchost.exe", "explorer.exe", "wininit.exe",
    "lsass.exe", "csrss.exe", "smss.exe", "winlogon.exe", "taskhostw.exe",
    "spoolsv.exe"
}
UTILISATEURS_SYSTEME = {
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service",
    "trustedinstaller"
}

# --- Logging ---
class SecurityLogger:
    """Unified logger for security events."""
    def __init__(self, log_file):
        self.logger = logging.getLogger(f"SecurityMonitor_{log_file}")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.FileHandler(log_file, encoding='utf-8')
            handler.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            # Console output for main monitor
            if log_file == MAIN_LOG_FILE:
                console_handler = logging.StreamHandler()
                console_handler.setLevel(logging.INFO)
                console_handler.setFormatter(formatter)
                self.logger.addHandler(console_handler)

    def log_action(self, action_type, details):
        serializable_details = self._make_serializable(details)
        action_data = {
            "timestamp": datetime.now().isoformat(),
            "action_type": action_type,
            "details": serializable_details
        }
        self.logger.info(f"{action_type.upper()}: {json.dumps(action_data, ensure_ascii=False)}")
        return action_data

    def _make_serializable(self, obj):
        if isinstance(obj, dict):
            return {key: self._make_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, datetime):
            return obj.isoformat()
        return obj

# Initialize loggers
MAIN_LOGGER = SecurityLogger(MAIN_LOG_FILE)
DLL_LOGGER = SecurityLogger(DLL_LOG_FILE)

# Example corrected logic (conceptual)
def est_legitime(proc: psutil.Process) -> bool:
    try:
        with proc.oneshot():
            name = proc.name().lower()
            exe = (proc.exe() or "").lower()
            user = (proc.username() or "").lower()
    except psutil.Error:
        MAIN_LOGGER.logger.warning(f"[WARN] Cannot access process {proc.pid}. Assuming legitimate.")
        return True

    # Critical: Always protect explorer.exe (this part is correct)
    if name == "explorer.exe":
        MAIN_LOGGER.logger.info(f"[INFO] 'explorer.exe' (PID {proc.pid}) protected.")
        return True

    # Check against known legitimate combinations
    if name in PROCESSUS_LEGITIMES:
        # Check user
        is_system_user = user in UTILISATEURS_SYSTEME
        # Check path
        from pathlib import Path
        exe_path = Path(exe)
        is_system_path = False
        try:
            # Check if the executable is in a system directory
            for sys_dir in [Path(r"c:\windows\system32"), Path(r"c:\windows\syswow64")]:
                if exe_path.is_relative_to(sys_dir):
                     is_system_path = True
                     break
        except ValueError:
             is_system_path = False # Not relative, so not in system dir

        # ONLY consider legitimate if BOTH user and path are correct
        if is_system_user and is_system_path:
            MAIN_LOGGER.logger.debug(f"[DEBUG] Legitimate system process: {name} (PID {proc.pid})")
            return True
        else:
            # This specific process name is in the list, but running in wrong context
            MAIN_LOGGER.logger.warning(f"[WARN] Suspicious {name} (PID {proc.pid}): User={user}, Path={exe}. Not killed due to name, but flagged.")
            # Decide policy: Kill or just log? Current logic protects by name.
            # Consider refining: return False if NOT system context?
            # For now, keep protection by name, but log the anomaly.
            # If you want to be stricter: return False if not system context.
            # Let's assume the name protection is absolute for these specific names:
            return True # Keep existing behavior for named processes

    # For all other processes
    MAIN_LOGGER.logger.debug(f"[DEBUG] Non-listed process: {name} (PID {proc.pid})")
    return False

def kill_process_tree(pid: int, kill_parent: bool = True):
    """Kill a process tree using psutil."""
    try:
        parent = psutil.Process(pid)
        MAIN_LOGGER.logger.info(f"[INFO] Killing process tree for PID {pid} ({parent.name()})")
    except psutil.NoSuchProcess:
        MAIN_LOGGER.logger.warning(f"[WARN] Process PID {pid} not found.")
        return
    except psutil.AccessDenied:
        MAIN_LOGGER.logger.error(f"[ERROR] Access denied to process PID {pid}. Cannot kill tree.")
        return # Cannot proceed if we can't access the parent

    current_pid = os.getpid()
    # Collect processes to kill
    to_kill = []
    try:
        # Get children recursively
        children = parent.children(recursive=True)
        to_kill.extend([p for p in children if p.pid != current_pid])
    except psutil.Error as e:
        MAIN_LOGGER.logger.error(f"[ERROR] Failed to get children of PID {pid}: {e}")

    # Optionally add the parent itself
    if kill_parent and parent.pid != current_pid:
        to_kill.append(parent)

    # Kill collected processes
    killed_pids = []
    MAIN_LOGGER.logger.debug(f"[DEBUG] kill_process_tree called for PID {pid}, kill_parent={kill_parent}")
    for proc_to_kill in to_kill:
        try:
            # Try graceful termination first (optional, might alert malware)
            # proc_to_kill.terminate()
            # gone, alive = psutil.wait_procs([proc_to_kill], timeout=3) # Wait 3s
            # for p in alive:
            #     p.kill() # Force kill if it didn't terminate

            MAIN_LOGGER.logger.info(f"[INFO] Attempting to kill process in tree: {proc_to_kill.name()} (PID {proc_to_kill.pid})")

            proc_to_kill.kill() # This sends SIGKILL on Unix, terminates on Windows
            killed_pids.append(proc_to_kill.pid)
            MAIN_LOGGER.logger.info(f"[🔪] Killed {proc_to_kill.name()} (PID {proc_to_kill.pid})")
        except psutil.NoSuchProcess:
             # Process might have died already
            MAIN_LOGGER.logger.debug(f"[DEBUG] Process {proc_to_kill.pid} seems to have died already.")
        except psutil.AccessDenied:
            MAIN_LOGGER.logger.warning(
                f"[⚠️] Access denied killing {proc_to_kill.name()} (PID {proc_to_kill.pid})."
            )
        except Exception as e:
            MAIN_LOGGER.logger.error(f"[ERROR] Exception killing {proc_to_kill.pid}: {e}")

# --- Sysmon Monitoring ---
def decode_powershell_base64(commandline: str) -> str:
    """Decode Base64 encoded PowerShell commands."""
    try:
        match = re.search(r"(?:-enc\s+|-encodedcommand\s+)([a-z0-9+/=]+)", commandline, re.I)
        if match:
            encoded_str = match.group(1)
            decoded_bytes = base64.b64decode(encoded_str)
            try:
                return decoded_bytes.decode('utf-16le')
            except UnicodeDecodeError:
                return decoded_bytes.decode('utf-8', errors='ignore')
    except Exception as e:
        MAIN_LOGGER.logger.warning(f"[!] Error decoding PowerShell command: {e}")
    return ""

def est_commande_suspecte(commandline: str) -> bool:
    """Check if a command line is suspicious."""
    if not commandline:
        return False
    cl = commandline.lower()
    decoded_cmd = decode_powershell_base64(commandline)
    full_cmd = cl + " " + decoded_cmd.lower()

    motifs_suspects = [
        r"encodedcommand", r"-enc", r"base64", r"invoke-expression", r"\biex\b",
        r"downloadstring", r"invoke-webrequest", r"start-bitstransfer", r"new-object",
        r"start-process", r"bypass", r"-nop", r"hidden", r"certutil", r"curl", r"wget",
        r"bitsadmin", r"\.js\b", r"\.vbs\b", r"\.bat\b", r"\.ps1\b", r"schtasks",
        r"reg add", r"regsvr32", r"rundll32"
    ]
    return any(re.search(motif, full_cmd) for motif in motifs_suspects)

def detect_processus_suspect(event_data):
    """Detect suspicious processes (Sysmon Event ID 1)."""
    nom_processus = os.path.basename(event_data.get("Image", "")).lower()
    ligne_commande = event_data.get("CommandLine") or ""
    pid_str = event_data.get("ProcessId")
    parent_image = os.path.basename(event_data.get("ParentImage", "")).lower()
    processus_suspects = [
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "regsvr32.exe", "rundll32.exe", "schtasks.exe", "certutil.exe", "curl.exe",
        "python.exe", "pythonw.exe", "python3.exe", "python3.11.exe"
    ]
    ransomware_keywords = [".vbs", "ransomware", ".locked", "encoder.py"]
    if (nom_processus in processus_suspects or
        any(kw in ligne_commande.lower() for kw in ransomware_keywords) or
        est_commande_suspecte(ligne_commande) or
        ("wscript.exe" == nom_processus and "python" in parent_image)):
        MAIN_LOGGER.logger.warning(f"[⚠️] Suspicious process detected (ID 1): {nom_processus}")
        MAIN_LOGGER.logger.info(f"      CommandLine: {ligne_commande}")
        if pid_str and pid_str.isdigit():
            try:
                proc = psutil.Process(int(pid_str))
                if not est_legitime(proc):
                    kill_process_tree(int(pid_str), kill_parent=True) # Kill parent and children
                else:
                    MAIN_LOGGER.logger.info(f"[INFO] Process {pid_str} is legitimate.")
            except psutil.NoSuchProcess:
                 MAIN_LOGGER.logger.warning(f"[WARN] Process {pid_str} disappeared before action.")
            except psutil.AccessDenied:
                 MAIN_LOGGER.logger.error(f"[ERROR] Access denied checking process {pid_str}.")
            except Exception as e:
                MAIN_LOGGER.logger.error(f"[!] Error handling process {pid_str}: {e}")
                
def _open_reg_key(hive, path, rights):
    """Open a registry key, trying WOW64 variations."""
    for flag in (0, winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        try:
            return winreg.OpenKey(hive, path, 0, rights | flag)
        except OSError:
            continue
    raise
def detect_event_id_11(event_data):
    """Detect suspicious file creations (Sysmon Event ID 11)."""
    fichier = (event_data.get("TargetFilename") or "").lower().strip()
    pid_str = event_data.get("ProcessId")
    if fichier.endswith((".locked", ".enc", ".crypt", ".encrypted")):
        MAIN_LOGGER.logger.critical(f"[🧨] Encrypted file detected: {fichier}")
        if pid_str and pid_str.isdigit():
            try:
                proc = psutil.Process(int(pid_str))
                # No need to check legitimacy here, creating .locked files is highly suspicious
                kill_process_tree(int(pid_str), kill_parent=True)
            except psutil.NoSuchProcess:
                 MAIN_LOGGER.logger.warning(f"[WARN] Process {pid_str} (file creator) disappeared.")
            except psutil.AccessDenied:
                 MAIN_LOGGER.logger.error(f"[ERROR] Access denied killing process {pid_str} (file creator).")
            except Exception as e:
                MAIN_LOGGER.logger.error(f"[!] Error handling PID {pid_str} (file creator): {e}")
        else:
            MAIN_LOGGER.logger.warning("[WARN] Invalid or missing ProcessId for encrypted file creation")
        return True
    if re.match(r"^\\\\[^\\]+\\(admin\$|c\$|ipc\$)\\", fichier):
        MAIN_LOGGER.logger.warning(f"[🚨] File creation on admin share: {fichier} (PID={pid_str})")
        if pid_str and pid_str.isdigit():
            try:
                proc = psutil.Process(int(pid_str))
                if not est_legitime(proc):
                    kill_process_tree(int(pid_str), kill_parent=True)
                # Consider if we should kill even if legitimate? Depends on policy.
                # For now, stick to legitimacy check.
            except psutil.NoSuchProcess:
                 MAIN_LOGGER.logger.warning(f"[WARN] Process {pid_str} (admin share creator) disappeared.")
            except psutil.AccessDenied:
                 MAIN_LOGGER.logger.error(f"[ERROR] Access denied checking process {pid_str} (admin share creator).")
            except Exception as e:
                MAIN_LOGGER.logger.error(f"[!] Error handling PID {pid_str} (admin share creator): {e}")
        return True
    return False
def detect_registre(event_data):
    """Detect suspicious registry modifications (Sysmon Event ID 12/13/14)."""
    cle = (event_data.get("TargetObject") or "").lower()
    valeur = (event_data.get("Details") or "").lower()
    event_type = (event_data.get("EventType") or "").lower()
    pid_str = event_data.get("ProcessId")
    cles_suspectes = [
        r"\\run", r"\\runonce", r"\\image file execution options",
        r"\\winlogon", r"\\shell", r"\\services"
    ]
    commandes_suspectes = [
        "powershell", "cmd.exe", "wscript", "regsvr32", ".vbs", ".js", ".bat",
        ".ps1", "frombase64string", "-enc", "iex"
    ]
    if any(re.search(cle_suspecte, cle) for cle_suspecte in cles_suspectes) and \
       any(cmd in valeur for cmd in commandes_suspectes):
        MAIN_LOGGER.logger.warning(f"[⚠️] Suspicious registry modification: {cle}")
        # Attempt to undo the registry change (existing logic)
        try:
            parts = cle.split("\\")
            hive_name = parts[0].upper()
            sous_cle = "\\".join(parts[1:-1])
            nom_valeur = parts[-1]
            hive_map = {
                "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
                "HKLM": winreg.HKEY_LOCAL_MACHINE,
                "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
                "HKCU": winreg.HKEY_CURRENT_USER,
            }
            hive = hive_map.get(hive_name)
            if hive:
                if event_type == "setvalue":
                    with _open_reg_key(hive, sous_cle, winreg.KEY_SET_VALUE) as key:
                        winreg.DeleteValue(key, nom_valeur)
                        MAIN_LOGGER.logger.info(f"[✔] Registry value deleted: {nom_valeur}")
                elif event_type == "createkey":
                    parent_path = "\\".join(parts[1:-1])
                    with _open_reg_key(hive, parent_path, winreg.KEY_ALL_ACCESS) as parent_key:
                        winreg.DeleteKey(parent_key, nom_valeur)
                        MAIN_LOGGER.logger.info(f"[✔] Registry key deleted: {cle}")
            else:
                MAIN_LOGGER.logger.error(f"[!] Unknown registry hive: {hive_name}")
        except Exception as e:
            MAIN_LOGGER.logger.error(f"[!] Error modifying registry: {e}")
        # Kill the associated process if not legitimate
        if pid_str and pid_str.isdigit():
            try:
                proc = psutil.Process(int(pid_str))
                if not est_legitime(proc):
                    # Use the unified kill function
                    kill_process_tree(int(pid_str), kill_parent=True)
                    # Removed the direct proc.kill() call
                else:
                     MAIN_LOGGER.logger.info(f"[INFO] Registry modifier process {pid_str} is legitimate.")
            except psutil.NoSuchProcess:
                 MAIN_LOGGER.logger.warning(f"[WARN] Registry modifier process {pid_str} disappeared.")
            except psutil.AccessDenied:
                 MAIN_LOGGER.logger.error(f"[ERROR] Access denied checking registry modifier process {pid_str}.")
            except Exception as e:
                MAIN_LOGGER.logger.error(f"[!] Error accessing process {pid_str}: {e}")

def detect_smb_propagation(event_data: dict) -> bool:
    """Detect SMB propagation attempts (Sysmon Event ID 3)."""
    try:
        image = os.path.basename(event_data.get("Image", "")).lower()
        cmd = event_data.get("CommandLine") or ""
        dport = int(event_data.get("DestinationPort", 0))
        dip = event_data.get("DestinationIp", "")
        pid = event_data.get("ProcessId")
    except (ValueError, TypeError):
        return False

    if dport in SMB_PORTS and (image in LATERAL_TOOLS or est_commande_suspecte(cmd)):
        MAIN_LOGGER.logger.warning(f"[🚨] Suspicious SMB connection: {image} PID={pid} to {dip}:{dport}")
        if pid and pid.isdigit():
            try:
                proc = psutil.Process(int(pid))
                if not est_legitime(proc):
                    kill_process_tree(int(pid), kill_parent=True)
            except Exception as e:
                MAIN_LOGGER.logger.error(f"[!] Error handling PID {pid}: {e}")
        return True
    return False

def detect_pipe_lateral(event_data: dict) -> bool:
    """Detect lateral movement via named pipes (Sysmon Event ID 17/18)."""
    pipe = (event_data.get("PipeName") or "").lower()
    pid = event_data.get("ProcessId")

    SUSPICIOUS_PIPES = (r"\psexesvc", r"\remcom_communic", r"\paexec", r"\atsvc")
    if any(p in pipe for p in SUSPICIOUS_PIPES):
        MAIN_LOGGER.logger.warning(f"[🚨] Suspicious named pipe: {pipe} (PID={pid})")
        if pid and pid.isdigit():
            try:
                proc = psutil.Process(int(pid))
                if not est_legitime(proc):
                    kill_process_tree(int(pid), kill_parent=True)
            except Exception as e:
                MAIN_LOGGER.logger.error(f"[!] Error handling PID {pid}: {e}")
        return True
    return False

def analyser_event_xml(event_xml: str):
    """Parse Sysmon XML event."""
    try:
        root = ET.fromstring(event_xml)
        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        event_id_el = root.find('./e:System/e:EventID', ns)
        if event_id_el is None or not event_id_el.text:
            return None, None
        event_id = int(event_id_el.text)
        data_elements = root.findall('.//e:EventData/e:Data', ns)
        event_data = {elem.attrib.get('Name'): (elem.text or "") for elem in data_elements}
        return event_id, event_data
    except Exception as e:
        MAIN_LOGGER.logger.error(f"[!] XML parsing error: {e}")
        return None, None

def get_event_record_id(xml_event):
    """Extract EventRecordID from XML."""
    try:
        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        root = ET.fromstring(xml_event)
        erid_elem = root.find('./e:System/e:EventRecordID', ns)
        if erid_elem is not None:
            return int(erid_elem.text)
    except:
        pass
    return 0

def render_event(event_handle):
    """Render event to XML string."""
    buffer_size = wintypes.DWORD(0)
    buffer_used = wintypes.DWORD(0)
    property_count = wintypes.DWORD(0)
    
    # First call to get required buffer size
    if not EvtRender(None, event_handle, EVT_RENDER_EVENT_XML, 0, None, byref(buffer_used), byref(property_count)):
        error = ctypes.GetLastError()
        if error != 122:  # ERROR_INSUFFICIENT_BUFFER
            MAIN_LOGGER.logger.error(f"EvtRender failed with error: {error}")
            return None
    
    # Create buffer and render the event
    buf = create_unicode_buffer(buffer_used.value)
    if not EvtRender(None, event_handle, EVT_RENDER_EVENT_XML, buffer_used, buf, byref(buffer_used), byref(property_count)):
        MAIN_LOGGER.logger.error(f"EvtRender failed with error: {ctypes.GetLastError()}")
        return None
    
    return buf.value



def monitor_sysmon_log():
    """Main Sysmon monitoring loop."""
    channel = "Microsoft-Windows-Sysmon/Operational"
    last_event_id = 0
    MAIN_LOGGER.logger.info("[*] Starting Sysmon monitoring (Winevt API)...")

    event_id_query = "*[System[(EventID=3 or EventID=11 or EventID=12 or EventID=13 or EventID=14 or EventID=17 or EventID=18)]]"

    try:
        while True:
            query_string = f"{event_id_query} and *[System[EventRecordID > {last_event_id}]]"
            query_handle = EvtQuery(None, channel, query_string, EVT_QUERY_CHANNEL_PATH)

            if not query_handle:
                error_code = ctypes.GetLastError()
                MAIN_LOGGER.logger.error(f"[!] Cannot open Sysmon log '{channel}' with query '{query_string}' (code {error_code}), retrying in 2s")
                time.sleep(2)
                continue # Retry the loop

            event_handles = (wintypes.HANDLE * 100)() # Use wintypes.HANDLE as EVT_HANDLE
            returned = wintypes.DWORD() # Use wintypes.DWORD for the count

            try:
                while True:
                    success = EvtNext(query_handle, 100, event_handles, 1000, 0, byref(returned))
                    if not success:
                        error_code = ctypes.GetLastError()
                        if error_code == ERROR_NO_MORE_ITEMS:
                            break 
                        else:
                            MAIN_LOGGER.logger.error(f"[!] EvtNext failed with error code: {error_code}")
                            break

                    for i in range(returned.value):
                        try:
                            xml_event = render_event(event_handles[i])
                            if not xml_event:
                                continue

                            event_id, event_data = analyser_event_xml(xml_event)
                            if not event_id:
                                continue

                            event_record_id = get_event_record_id(xml_event)
                            if event_record_id and event_record_id > last_event_id:
                                last_event_id = event_record_id
                                if event_id == 1:
                                    detect_processus_suspect(event_data)
                                # Keep Event ID 11 for .locked files
                                if event_id == 11:
                                    detect_event_id_11(event_data)
                                elif event_id == 3:
                                    detect_smb_propagation(event_data)
                                elif event_id in (17, 18):
                                    detect_pipe_lateral(event_data)
                                elif event_id in (12, 13, 14):
                                    detect_registre(event_data)
                                # Add more elif blocks for other event IDs as needed
                            else:
                                # Optional: Log skipped old events if debugging
                                # MAIN_LOGGER.logger.debug(f"[DEBUG] Skipping old event ID {event_id}, Record ID {event_record_id} (Last: {last_event_id})")
                                pass

                        except Exception as e:
                            MAIN_LOGGER.logger.error(f"[!] Error processing individual event: {e}")
                            MAIN_LOGGER.logger.error(traceback.format_exc())
                        finally:
                            # Always close the individual event handle
                            if event_handles[i]: # Check if handle seems valid
                                EvtClose(event_handles[i])

            finally:
                if query_handle:
                    EvtClose(query_handle)

            time.sleep(1)

    except KeyboardInterrupt:
        MAIN_LOGGER.logger.info("Sysmon monitoring loop interrupted by user.")
    except Exception as e:
        MAIN_LOGGER.logger.critical(f"[CRITICAL] Sysmon monitoring loop crashed unexpectedly: {e}")
        MAIN_LOGGER.logger.critical(traceback.format_exc())

# --- DLL Scanner ---
class DLLSecurityScanner:
    """Scanner for suspicious DLLs in user directories."""
    def __init__(self, logger):
        self.logger = logger
        self.scan_paths = [
    str(Path.home() / 'Desktop'),
    str(Path.home() / 'Downloads')
]

        self.suspicious_content_patterns = [
            'encrypt', 'decrypt', 'ransom', 'bitcoin', 'wallet', 'payment', '.onion',
            'createremotethread', 'virtualallocex', 'writeprocessmemory',
            'setwindowshookex', 'loadlibrary', 'getprocaddress',
            'urldownloadtofile', 'internetopen', 'httpopen',
            'deletefile', 'movefile', 'copyfile',
        ]
        self.scan_cycle_counter = 0

    def is_digitally_signed(self, file_path):
        """Check if a DLL is digitally signed."""
        if not WINDOWS_AVAILABLE:
            return None
        try:
            cmd = f'powershell -Command "(Get-AuthenticodeSignature \'{file_path}\').Status -eq \'Valid\'"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=30)
            if result.returncode == 0:
                if "True" in result.stdout:
                    return True
                elif "False" in result.stdout:
                    return False
            return None
        except subprocess.TimeoutExpired:
            self.logger.logger.warning(f"Timeout checking signature for {file_path}")
            return None
        except Exception as e:
            self.logger.logger.warning(f"Could not verify signature for {file_path}: {e}")
            return None

    def get_file_metadata(self, file_path):
        """Get file metadata and hash."""
        try:
            stat = os.stat(file_path)
            path_obj = Path(file_path)
            metadata = {
                'path': str(file_path),
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'is_signed': self.is_digitally_signed(file_path),
                'extension': path_obj.suffix.lower(),
                'filename': path_obj.name
            }
            hash_sha256 = hashlib.sha256()
            try:
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_sha256.update(chunk)
                metadata['sha256'] = hash_sha256.hexdigest()
            except IOError:
                metadata['sha256'] = "Error"
            return metadata
        except Exception as e:
            self.logger.logger.error(f"Error getting metadata for {file_path}: {e}")
            return None

    def is_suspicious_location(self, dll_path):
        """Check if DLL is in a suspicious location."""
        path_str = str(dll_path).lower()
        suspicious_indicators = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
            '\\users\\public\\', '\\programdata\\temp\\',
            '\\windows\\temp\\', '\\$recycle.bin\\',
            '\\downloads\\', '\\desktop\\'
        ]
        return any(indicator in path_str for indicator in suspicious_indicators)

    def analyze_dll_content(self, dll_path):
        """Analyze DLL content for suspicious strings."""
        suspicious_patterns = []
        try:
            with open(dll_path, 'rb') as f:
                content = f.read(16384)
                content_str = content.decode('latin-1', errors='ignore').lower()
                for indicator in self.suspicious_content_patterns:
                    if indicator in content_str:
                        suspicious_patterns.append(indicator)
        except Exception:
            pass
        return suspicious_patterns

    def calculate_risk_score(self, metadata, content_patterns, location_suspicious):
        """Calculate risk score with breakdown."""
        risk_score = 0
        score_details = []

        if metadata['is_signed'] is False:
            risk_score += 40
            score_details.append("Not signed (+40)")
        elif metadata['is_signed'] is None:
            risk_score += 20
            score_details.append("Signature check failed (+20)")

        if location_suspicious:
            risk_score += 30
            score_details.append("Suspicious location (+30)")

        pattern_count = len(content_patterns)
        pattern_score = pattern_count * 10
        risk_score += pattern_score
        if pattern_count > 0:
            score_details.append(f"Contains {pattern_count} patterns (+{pattern_score})")

        try:
            modified_dt = datetime.fromisoformat(metadata['modified'])
            file_age = datetime.now() - modified_dt
            if file_age < timedelta(hours=1):
                risk_score += 25
                score_details.append("Very recent (<1h) (+25)")
            elif file_age < timedelta(days=1):
                risk_score += 15
                score_details.append("Recent (<1d) (+15)")
        except Exception:
            pass

        size = metadata['size']
        if size < 10000 or size > 50000000:
            risk_score += 10
            score_details.append("Unusual size (+10)")

        return risk_score, score_details

    def delete_dll(self, dll_path, metadata, risk_score, risk_factors, score_details):
        """Delete a suspicious DLL."""
        try:
            deletion_log = {
                'cycle_id': self.scan_cycle_counter,
                'deleted_path': str(dll_path),
                'timestamp': datetime.now().isoformat(),
                'risk_score': risk_score,
                'risk_factors': risk_factors,
                'score_breakdown': score_details,
                'metadata': metadata
            }
            Path(dll_path).unlink()
            self.logger.log_action("DLL_DELETED", deletion_log)
            print(f"[DLL_SCAN] Deleted: {dll_path}") # Immediate console feedback
            return True
        except PermissionError as e:
            error_log = {'cycle_id': self.scan_cycle_counter, 'path': str(dll_path), 'error': f"Permission denied: {e}", 'risk_score': risk_score, 'risk_factors': risk_factors, 'metadata': metadata}
            self.logger.logger.error(f"Permission denied deleting {dll_path}: {e}")
            self.logger.log_action("DLL_DELETE_FAILED", error_log)
            return False
        except Exception as e:
            error_log = {'cycle_id': self.scan_cycle_counter, 'path': str(dll_path), 'error': f"Error: {e}", 'risk_score': risk_score, 'risk_factors': risk_factors, 'metadata': metadata}
            self.logger.logger.error(f"Failed to delete {dll_path}: {e}")
            self.logger.log_action("DLL_DELETE_FAILED", error_log)
            return False

    def scan_and_delete_suspicious_dlls(self, risk_threshold=50):
        """Scan and delete suspicious DLLs."""
        self.scan_cycle_counter += 1
        cycle_start_time = datetime.now()
        self.logger.logger.info(f"--- Starting DLL Scan Cycle {self.scan_cycle_counter} ---")
        scan_results = {'cycle_id': self.scan_cycle_counter, 'start_time': cycle_start_time.isoformat(), 'scanned': 0, 'deleted': 0, 'suspicious': 0, 'errors': 0}

        for scan_path in self.scan_paths:
            if not os.path.exists(scan_path):
                self.logger.logger.warning(f"Scan path inaccessible: {scan_path}")
                scan_results['errors'] += 1
                continue
            self.logger.logger.info(f"Scanning directory: {scan_path}")

            try:
                for root, dirs, files in os.walk(scan_path):
                    root_lower = root.lower()
                    if any(sys_dir in root_lower for sys_dir in ['\\windows\\system32\\', '\\windows\\syswow64\\', '\\windows\\winsxs\\']):
                        continue

                    for file in files:
                        if file.lower().endswith('.dll'):
                            dll_path = os.path.join(root, file)
                            try:
                                scan_results['scanned'] += 1
                                metadata = self.get_file_metadata(dll_path)
                                if not metadata:
                                    scan_results['errors'] += 1
                                    continue

                                location_suspicious = self.is_suspicious_location(dll_path)
                                content_patterns = self.analyze_dll_content(dll_path)
                                any_suspicion = location_suspicious or content_patterns or metadata['is_signed'] is False

                                risk_score, score_details = self.calculate_risk_score(metadata, content_patterns, location_suspicious)

                                if risk_score >= risk_threshold:
                                    scan_results['suspicious'] += 1
                                    risk_factors = []
                                    if metadata['is_signed'] is False: risk_factors.append("unsigned")
                                    if location_suspicious: risk_factors.append("suspicious_location")
                                    if content_patterns: risk_factors.extend([f"pattern_{p}" for p in content_patterns[:5]])

                                    log_details = {'cycle_id': self.scan_cycle_counter, 'path': dll_path, 'risk_score': risk_score, 'risk_factors': risk_factors, 'score_breakdown': score_details, 'metadata': metadata}
                                    self.logger.log_action("DLL_SUSPICIOUS", log_details)

                                    if self.delete_dll(dll_path, metadata, risk_score, risk_factors, score_details):
                                        scan_results['deleted'] += 1

                            except Exception as e:
                                scan_results['errors'] += 1
                                self.logger.logger.error(f"Error processing {dll_path}: {e}", exc_info=True)

            except Exception as e:
                self.logger.logger.error(f"Error scanning directory {scan_path}: {e}", exc_info=True)
                scan_results['errors'] += 1

        cycle_end_time = datetime.now()
        scan_results['end_time'] = cycle_end_time.isoformat()
        scan_results['duration_seconds'] = (cycle_end_time - cycle_start_time).total_seconds()
        self.logger.logger.info(f"--- DLL Scan Cycle {self.scan_cycle_counter} Completed ---")
        self.logger.logger.info(f"Results: {scan_results}")
        return scan_results

def run_dll_scanner_periodically(logger_instance, interval_seconds=60):
    """Run DLL scanner periodically."""
    scanner = DLLSecurityScanner(logger_instance)
    try:
        while True:
            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] --- Initiating DLL Scan Cycle ---")
            results = scanner.scan_and_delete_suspicious_dlls(risk_threshold=50)
            print(f"--- Scan Cycle Summary ---")
            print(f"  Cycle ID: {results.get('cycle_id', 'N/A')}")
            print(f"  Scanned: {results['scanned']} DLLs")
            print(f"  Suspicious: {results['suspicious']} DLLs")
            print(f"  Deleted: {results['deleted']} DLLs")
            print(f"  Errors: {results['errors']}")
            print(f"  Duration: {results.get('duration_seconds', 'N/A'):.2f} seconds")
            print(f"--- Waiting {interval_seconds} seconds ---\n")
            time.sleep(interval_seconds)
    except Exception as e:
        logger_instance.logger.critical(f"DLL Scanner crashed: {e}")
        logger_instance.logger.critical(traceback.format_exc())

# --- System Integration ---
def add_task_scheduler(task_name="SecurityMonitor", script_path=None):
    """Add script to Windows Task Scheduler."""
    try:
        if script_path is None:
            script_path = os.path.abspath(__file__)
        result = subprocess.run(["schtasks", "/Query", "/TN", task_name], capture_output=True, text=True)
        if result.returncode == 0:
            MAIN_LOGGER.logger.info(f"[✔] Scheduled task '{task_name}' already exists.")
            return
        cmd = [
            "schtasks", "/Create", "/SC", "ONSTART", "/RL", "HIGHEST",
            "/TN", task_name,
            "/TR", f'"{sys.executable} {script_path}"',
            "/F"
        ]
        result = subprocess.run(" ".join(cmd), capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            MAIN_LOGGER.logger.info(f"[✔] Scheduled task '{task_name}' added.")
        else:
            MAIN_LOGGER.logger.error(f"[!] Error adding task: {result.stderr.strip()}")
    except Exception as e:
        MAIN_LOGGER.logger.error(f"[ERROR] Cannot create scheduled task: {e}")

def run_as_admin():
    """Relaunch script with admin privileges."""
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False
    if not is_admin:
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        except Exception as e:
            MAIN_LOGGER.logger.error(f"[!] Cannot request admin rights: {e}")
        sys.exit(0)

# - Main Execution -
def main():
    """Main entry point."""
    print("=" * 60)
    print("Integrated Security Monitor")
    print("Sysmon Monitoring + DLL Scanner")
    print("=" * 60)
    print("Press Ctrl+C to stop.")

    run_as_admin()
    add_task_scheduler()

    dll_scan_thread = threading.Thread(target=run_dll_scanner_periodically, args=(DLL_LOGGER,1), daemon=True)
    dll_scan_thread.start()
    MAIN_LOGGER.logger.info("DLL Scanner thread started.")

   
    try:
        monitor_sysmon_log() 
    except KeyboardInterrupt:
        print("\nReceived interrupt signal. Shutting down...")
        MAIN_LOGGER.logger.info("Monitor stopped by user.")
    except Exception as e:
        MAIN_LOGGER.logger.critical(f"Monitor crashed unexpectedly: {e}")
        MAIN_LOGGER.logger.critical(traceback.format_exc())
      

if __name__ == "__main__":
    main()
