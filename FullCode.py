#!/usr/bin/env python3
"""
Real-Time DLL Scanner & Remover
Combines continuous file system scanning with Sysmon event log monitoring.
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
import psutil
import ctypes
from ctypes import windll, wintypes, byref, create_unicode_buffer
import xml.etree.ElementTree as ET
import re
import traceback

# Required imports
try:
    import psutil
except ImportError as e:
    print(f"Missing required module: {e}")
    print("Install with: pip install psutil")
    sys.exit(1)

WINDOWS_AVAILABLE = (os.name == 'nt')

# --- Winevt API Constants and Setup (For Sysmon Monitoring) ---
if WINDOWS_AVAILABLE:
    try:
        # Constantes Winevt
        EVT_QUERY_CHANNEL_PATH = 0x1
        EVT_RENDER_EVENT_XML = 1
        ERROR_NO_MORE_ITEMS = 259
        # Chargement de l'API Winevt.dll
        wevtapi = windll.wevtapi
        # Définition des fonctions
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
        WINEVT_AVAILABLE = True
    except Exception as e:
        print(f"Winevt API setup failed (Sysmon monitoring will be disabled): {e}")
        WINEVT_AVAILABLE = False
else:
    WINEVT_AVAILABLE = False


# --- Configuration for Sysmon Monitoring ---
PROCESSUS_LEGITIMES = {
    "services.exe", "svchost.exe", "explorer.exe", "wininit.exe",
    "lsass.exe", "csrss.exe", "smss.exe", "winlogon.exe", "taskhostw.exe",
    "spoolsv.exe", "system"
}
UTILISATEURS_SYSTEME = {
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service",
    "trustedinstaller",
    "system"
}

# --- Core Security Logger ---
class SecurityLogger:
    """Simple logging for security events"""
    def __init__(self, log_file="dll_scan.log"):
        self.logger = logging.getLogger("DLLScanner")
        # Prevent adding multiple handlers if logger already exists
        if not self.logger.handlers:
            self.logger.setLevel(logging.INFO)

            # File handler
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.INFO)

            # Console handler
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)

            # Formatter
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            fh.setFormatter(formatter)
            ch.setFormatter(formatter)

            self.logger.addHandler(fh)
            self.logger.addHandler(ch)

    def log_action(self, action_type, details):
            """Log an action with structured data"""
            # Ensure all datetime objects are serialized
            serializable_details = self._make_serializable(details)
            action_data = {
                "timestamp": datetime.now().isoformat(),  # Already a string
                "action_type": action_type,
                "details": serializable_details
            }
            try:
                self.logger.info(f"{action_type.upper()}: {json.dumps(action_data)}")
                return action_data
            except TypeError as e:
                self.logger.error(f"Failed to serialize log data: {e}")
                return None
            
    def _make_serializable(self, obj):
        """Recursively convert non-serializable objects (like datetime) to strings."""
        if isinstance(obj, dict):
            return {key: self._make_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, datetime):
            return obj.isoformat()
        # Add other non-serializable types if needed
        return obj

# --- Core DLL Security Scanner ---
class DLLSecurityScanner:
    """DLL scanner focused on user directories with deletion capability"""
    def __init__(self, logger):
        self.logger = logger
        self.suspicious_dll_cache = set() # Cache reset each scan cycle in continuous mode

        # Focus on user directories
        self.scan_paths = [
            'C:\\Users',
            str(Path.home() / 'Desktop')
        ]

        # Suspicious patterns indicating potential malware
        self.suspicious_content_patterns = [
            # Crypto/Ransomware indicators
            'encrypt', 'decrypt', 'ransom', 'bitcoin', 'wallet',
            'payment', '.onion',
            # Process injection indicators
            'createremotethread', 'virtualallocex', 'writeprocessmemory',
            'setwindowshookex', 'loadlibrary', 'getprocaddress',
            # Network indicators
            'urldownloadtofile', 'internetopen', 'httpopen',
            # File operations
            'deletefile', 'movefile', 'copyfile',
        ]

    def is_digitally_signed(self, file_path):
        """Check if a file is digitally signed using Windows tools"""
        if not WINDOWS_AVAILABLE:
            return None
        try:
            # Use PowerShell to check digital signature
            cmd = f'powershell -Command "(Get-AuthenticodeSignature \'{file_path}\').Status -eq \'Valid\'"'
            # Increased timeout and catch TimeoutExpired
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=30)
            if result.returncode == 0 and "True" in result.stdout:
                return True
            return False
        except subprocess.TimeoutExpired:
            self.logger.logger.warning(f"Timeout checking signature for {file_path}")
            return None
        except Exception as e:
            self.logger.logger.warning(f"Could not verify signature for {file_path}: {e}")
            return None

    def get_file_metadata(self, file_path):
        """Extract file metadata and hash"""
        try:
            stat = os.stat(file_path)
            path_obj = Path(file_path)

            metadata = {
                'path': str(file_path),
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime), # Keep as datetime object internally
                'is_signed': self.is_digitally_signed(file_path),
                'extension': path_obj.suffix.lower(),
                'filename': path_obj.name
            }

            # Calculate file hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()
                for chunk in iter(lambda: f.read(4096), b""):
                    file_hash.update(chunk)
                metadata['sha256'] = file_hash.hexdigest()

            return metadata
        except Exception as e:
            self.logger.logger.error(f"Error getting metadata for {file_path}: {e}")
            return None

    def is_suspicious_location(self, dll_path):
        """Check if DLL is in a suspicious user location"""
        path_str = str(dll_path).lower()

        # Suspicious user locations
        suspicious_indicators = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
            '\\users\\public\\', '\\programdata\\temp\\',
            '\\windows\\temp\\', '\\$recycle.bin\\',
            '\\downloads\\', '\\desktop\\'
        ]

        return any(indicator in path_str for indicator in suspicious_indicators)

    def analyze_dll_content(self, dll_path):
        """Analyze DLL content for suspicious patterns"""
        suspicious_patterns = []
        try:
            with open(dll_path, 'rb') as f:
                content = f.read(8192)  # Read first 8KB
                content_str = content.decode('latin-1', errors='ignore').lower()

                for indicator in self.suspicious_content_patterns:
                    if indicator in content_str:
                        suspicious_patterns.append(indicator)
        except Exception as e:
             self.logger.logger.warning(f"Could not analyze content for {dll_path}: {e}")
        return suspicious_patterns

    def calculate_risk_score(self, metadata, content_patterns, location_suspicious):
        """Calculate risk score for a DLL"""
        risk_score = 0

        # Unsigned file increases risk
        if metadata['is_signed'] is False:
            risk_score += 40
        elif metadata['is_signed'] is None:
            risk_score += 20

        # Location check
        if location_suspicious:
            risk_score += 30

        # Content patterns
        risk_score += len(content_patterns) * 10

        # File age (newer files are more suspicious)
        # metadata['modified'] is a datetime object
        file_age = datetime.now() - metadata['modified']
        if file_age < timedelta(hours=1):
            risk_score += 25
        elif file_age < timedelta(days=1):
            risk_score += 15

        # Unusual file size
        size = metadata['size']
        if size < 10000 or size > 50000000:  # < 10KB or > 50MB
            risk_score += 10

        return risk_score

    def delete_dll(self, dll_path, metadata=None, risk_score="N/A", risk_factors=None):
        """Permanently delete a suspicious DLL"""
        if risk_factors is None:
            risk_factors = ["real_time_detection"]
        if metadata is None:
            metadata = {"reason": "Real-time detection, metadata not available"}
        try:
            dll_path_obj = Path(dll_path)
            # Log deletion details (ensure metadata is serializable for logging)
            log_metadata = self.logger._make_serializable(metadata.copy())
            deletion_log = {
                'deleted_path': str(dll_path),
                'timestamp': datetime.now().isoformat(),
                'risk_score': risk_score,
                'risk_factors': risk_factors,
                'metadata': log_metadata
            }
            # Delete the file
            dll_path_obj.unlink()
            self.logger.log_action("DLL_DELETED", deletion_log)
            print(f"  [DELETED] {dll_path}") # Print to console immediately
            return True
        except PermissionError as e:
            self.logger.logger.error(f"Permission denied deleting {dll_path}: {e}")
            print(f"  [FAILED - Permission] {dll_path}")
            return False
        except Exception as e:
            self.logger.logger.error(f"Failed to delete {dll_path}: {e}")
            print(f"  [FAILED - Error] {dll_path}")
            return False

    def scan_and_delete_suspicious_dlls(self, risk_threshold=50):
        """Scan user directories and delete suspicious DLLs"""
        self.logger.logger.info(f"Starting DLL scan in user directories with risk threshold: {risk_threshold}")

        scan_results = {
            'scanned': 0,
            'deleted': 0,
            'suspicious': 0,
            'errors': 0
        }

        for scan_path in self.scan_paths:
            if not os.path.exists(scan_path):
                self.logger.logger.warning(f"Scan path does not exist: {scan_path}")
                continue

            self.logger.logger.info(f"Scanning directory: {scan_path}")

            try:
                # Walk through the directory tree
                for root, dirs, files in os.walk(scan_path):
                    # Skip Windows system directories
                    if any(sys_dir in root.lower() for sys_dir in ['\\windows\\system32\\', '\\windows\\syswow64\\']):
                        continue

                    for file in files:
                        if file.lower().endswith('.dll'):
                            dll_path = os.path.join(root, file)

                            try:
                                scan_results['scanned'] += 1

                                # Get metadata
                                metadata = self.get_file_metadata(dll_path)
                                if not metadata:
                                    scan_results['errors'] += 1
                                    continue

                                # Check location and content
                                location_suspicious = self.is_suspicious_location(dll_path)
                                content_patterns = self.analyze_dll_content(dll_path)

                                # Calculate risk
                                risk_score = self.calculate_risk_score(
                                    metadata, content_patterns, location_suspicious
                                )

                                if risk_score >= risk_threshold:
                                    scan_results['suspicious'] += 1
                                    risk_factors = []

                                    if metadata['is_signed'] is False:
                                        risk_factors.append("unsigned")
                                    if location_suspicious:
                                        risk_factors.append("suspicious_location")
                                    if content_patterns:
                                        risk_factors.extend([f"pattern_{p}" for p in content_patterns[:3]])

                                    # Delete the suspicious DLL
                                    if self.delete_dll(dll_path, metadata, risk_score, risk_factors):
                                        scan_results['deleted'] += 1
                                        # Note: Cache not used in continuous mode per cycle

                                # Progress update (more frequent for continuous mode feedback)
                                if scan_results['scanned'] % 50 == 0:
                                    self.logger.logger.info(f"Scanned {scan_results['scanned']} DLLs so far...")

                            except Exception as e:
                                scan_results['errors'] += 1
                                self.logger.logger.error(f"Error scanning {dll_path}: {e}")

            except Exception as e:
                self.logger.logger.error(f"Error scanning directory {scan_path}: {e}")

        self.logger.logger.info(f"DLL scan cycle completed: {scan_results}")
        return scan_results

# --- Sysmon Event Monitoring --- Test ur code cuz i don't have the right config for sysmon 
class SysmonMonitor:
    """Monitors Sysmon event logs for suspicious activities related to DLLs."""
    def __init__(self, logger, dll_scanner):
        self.logger = logger
        self.dll_scanner = dll_scanner
        self.running = False

    def est_legitime(self, proc: psutil.Process) -> bool:
        """Check if a process is considered legitimate."""
        try:
            name = proc.name().lower()
            user = proc.username().lower()
            exe  = (proc.exe() or "").lower()
        except psutil.Error:
            return True # Assume legitimate if we can't check
        if name in PROCESSUS_LEGITIMES and \
           (exe.startswith(r"c:\windows\system32") or exe.startswith(r"c:\windows\syswow64")) and \
           user in UTILISATEURS_SYSTEME:
            return True
        return False

    def kill_process_tree(self, pid: int, kill_parent: bool = True):
        """Kill a process tree with better error handling"""
        try:
            parent = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return

        try:
            children = parent.children(recursive=True)
            for child in children:
                try:
                    if not self.est_legitime(child):
                        child.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    self.logger.logger.warning(f"[Sysmon] Could not kill child {child.pid}: {e}")
        except psutil.Error as e:
            self.logger.logger.warning(f"[Sysmon] Error getting children of {pid}: {e}")

        if kill_parent:
            try:
                if not self.est_legitime(parent):
                    parent.kill()
                    self.logger.logger.info(f"[Sysmon] Killed process {pid} ({parent.name()})")
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                self.logger.logger.warning(f"[Sysmon] Could not kill process {pid}: {e}")

    def est_commande_suspecte(self, commandline: str) -> bool:
        if not commandline:
            return False
        cl = commandline.lower()
        motifs_suspects = [
            r"encodedcommand", r"-enc", r"base64",
            r"invoke-expression", r"\biex\b",
            r"downloadstring", r"invoke-webrequest", r"start-bitstransfer",
            r"new-object", r"start-process",
            r"bypass", r"-nop", r"hidden",
            r"certutil", r"curl", r"wget", r"bitsadmin",
            r"\.js\b", r"\.vbs\b", r"\.bat\b", r"\.ps1\b",
            r"schtasks", r"reg add", r"regsvr32", r"rundll32"
        ]
        for motif in motifs_suspects:
            if re.search(motif, cl):
                return True
        return False

    def detect_suspicious_dll_via_process(self, event_data):
        """
        Analyse a Sysmon ProcessCreate event (EventID 1) for suspicious DLL activity.
        """
        nom_processus = (event_data.get("Image") or "").lower()
        ligne_commande = (event_data.get("CommandLine") or "")
        pid_str = event_data.get("ProcessId")

        # Focus on processes that load DLLs or can execute code
        processus_suspects = [
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "regsvr32.exe", "rundll32.exe", "schtasks.exe", "certutil.exe"
        ]

        # Check if the process itself is suspicious
        if not any(p in nom_processus for p in processus_suspects):
            # Even if the process isn't inherently suspicious, check its command line
            # for loading suspicious DLLs or executing from suspicious locations
            if not self.est_commande_suspecte(ligne_commande):
                 return False # Not suspicious enough

        # If we get here, the process or its command line is suspicious
        # Check if it loads a DLL from a suspicious location in its command line
        # This is a simplified check. A more robust check would involve monitoring DLL loads (Event ID 7)
        # or checking the DLLs loaded by the process after it starts.
        cl_lower = ligne_commande.lower()
        suspicious_paths = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
            '\\users\\public\\', '\\programdata\\', '\\downloads\\'
        ]
         # Check for rundll32/regsvr32 loading from suspicious path
        if "rundll32.exe" in nom_processus or "regsvr32.exe" in nom_processus:
            for sus_path in suspicious_paths:
                if sus_path in cl_lower:
                    self.logger.log_action("SYSMON_SUSPICIOUS_DLL_LOAD_CMD", {
                        "process": nom_processus,
                        "command_line": ligne_commande,
                        "suspicious_path": sus_path,
                        "source": "Sysmon_Event_1"
                    })
                    print(f"  [SYSMON ALERT - Suspicious Load Cmd] {nom_processus} loading from {sus_path}")
                    # Attempt to kill the process
                    if pid_str and pid_str.isdigit():
                        self.kill_process_tree(int(pid_str), kill_parent=True)
                    return True

        # Check for general suspicious command lines
        if self.est_commande_suspecte(ligne_commande):
            self.logger.log_action("SYSMON_SUSPICIOUS_CMDLINE", {
                "process": nom_processus,
                "command_line": ligne_commande,
                "source": "Sysmon_Event_1"
            })
            print(f"  [SYSMON ALERT - Suspicious Cmdline] {nom_processus}")
            if pid_str and pid_str.isdigit():
                self.kill_process_tree(int(pid_str), kill_parent=True)
            return True

        return False 

    def detect_suspicious_dll_via_file_creation(self, event_data):
        """
        Analyse a Sysmon FileCreate event (EventID 11) for suspicious DLL creation.
        """
        fichier = (event_data.get("TargetFilename") or "")
        # Check if the created file is a DLL
        if not fichier.lower().endswith('.dll'):
            return False

        # Check if the DLL was created in a suspicious location
        if self.dll_scanner.is_suspicious_location(fichier):
            # Get basic metadata (file exists at this point)
            metadata = self.dll_scanner.get_file_metadata(fichier)
            # Perform quick content analysis
            content_patterns = self.dll_scanner.analyze_dll_content(fichier)
            # Quick risk check (simplified for real-time)
            location_suspicious = True # We already know this
            risk_score = self.dll_scanner.calculate_risk_score(metadata if metadata else {}, content_patterns, location_suspicious) if metadata else 60 # Assume high risk if metadata fails

            if risk_score >= 50: # Use a threshold, maybe make configurable
                 self.logger.log_action("SYSMON_SUSPICIOUS_DLL_CREATED", {
                    "file_path": fichier,
                    "risk_score": risk_score,
                    "location_suspicious": location_suspicious,
                    "content_patterns": content_patterns,
                    "source": "Sysmon_Event_11"
                })
                 print(f"  [SYSMON ALERT - Suspicious DLL Created] {fichier} (Risk: {risk_score})")
                 # Delete the suspicious DLL immediately
                 self.dll_scanner.delete_dll(fichier, metadata, risk_score, ["sysmon_file_creation", "suspicious_location"] + [f"pattern_{p}" for p in content_patterns[:2]])
                 # Kill the creating process
                 pid_str = event_data.get("ProcessId")
                 if pid_str and pid_str.isdigit():
                    self.kill_process_tree(int(pid_str), kill_parent=True)
                 return True
        return False

    def analyser_event_xml(self, event_xml: str):
        """Parse Sysmon event XML with better error handling"""
        try:
            if not event_xml or "<Event" not in event_xml:
                return None, None
                
            root = ET.fromstring(event_xml)
            ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            # Get EventID
            event_id_el = root.find('./e:System/e:EventID', ns)
            if event_id_el is None or not event_id_el.text:
                return None, None
                
            try:
                event_id = int(event_id_el.text)
            except ValueError:
                return None, None
                
            event_data = {}
            data_elements = root.findall('.//e:EventData/e:Data', ns)
            for elem in data_elements:
                name = elem.attrib.get('Name')
                if name:
                    event_data[name] = elem.text or ""
                    
            return event_id, event_data
            
        except ET.ParseError as e:
            self.logger.logger.error(f"[Sysmon] XML parse error: {e}")
            return None, None
        except Exception as e:
            self.logger.logger.error(f"[Sysmon] Unexpected XML parsing error: {e}")
            return None, None

    def render_event(self, event_handle):
        """Render an event handle to XML string."""
        buffer_size = wintypes.DWORD(0)
        buffer_used = wintypes.DWORD(0)
        property_count = wintypes.DWORD(0)
        # Premier appel pour obtenir la taille nécessaire
        EvtRender(None, event_handle, EVT_RENDER_EVENT_XML,
                  0, None, byref(buffer_used), byref(property_count))
        buf = create_unicode_buffer(buffer_used.value)
        if not EvtRender(None, event_handle, EVT_RENDER_EVENT_XML,
                         buffer_used, buf, byref(buffer_used), byref(property_count)):
            err_code = ctypes.GetLastError()
            self.logger.logger.error(f"[Sysmon] EvtRender failed: {err_code}")
            return None
        return buf.value

    def monitor_sysmon_events(self):
        """Main loop for monitoring Sysmon events."""
        if not WINEVT_AVAILABLE:
            self.logger.logger.error("[Sysmon] Winevt API not available. Sysmon monitoring disabled.")
            return

        channel = "Microsoft-Windows-Sysmon/Operational"
        query = "*"
        query_handle = EvtQuery(None, channel, query, EVT_QUERY_CHANNEL_PATH)
        if not query_handle:
            err = ctypes.GetLastError()
            self.logger.logger.error(f"[Sysmon] Unable to open Sysmon log (code {err}). Is Sysmon running and configured?")
            return

        self.logger.logger.info("[Sysmon] Starting real-time monitoring of Sysmon events...")
        print("  [Sysmon Monitor] Active")
        event_handles = (wintypes.HANDLE * 10)()
        returned = wintypes.DWORD()

        while self.running:
            try:
                success = EvtNext(query_handle, 10, event_handles, 1000, 0, byref(returned))
                if not success:
                    err_code = ctypes.GetLastError()
                    if err_code == ERROR_NO_MORE_ITEMS:
                        time.sleep(0.5) # Brief pause before retrying
                        continue
                    else:
                        self.logger.logger.error(f"[Sysmon] EvtNext error: {err_code}")
                        time.sleep(2)
                        continue

                for i in range(returned.value):
                    try:
                        xml_event = self.render_event(event_handles[i])
                        if not xml_event or "<Event" not in xml_event:
                            continue
                        event_id, event_data = self.analyser_event_xml(xml_event)
                        if not event_id:
                            continue

                        if event_id == 11: # File created
                            self.detect_suspicious_dll_via_file_creation(event_data)
                        elif event_id == 1: # Process created
                            self.detect_suspicious_dll_via_process(event_data)

                    except Exception as e:
                        self.logger.logger.error(f"[Sysmon] Exception processing event: {e}")
                        self.logger.logger.debug(traceback.format_exc())
                    finally:
                        EvtClose(event_handles[i])

                time.sleep(0.1) 

            except Exception as e:
                self.logger.logger.error(f"[Sysmon] Critical error in monitoring loop: {e}")
                self.logger.logger.debug(traceback.format_exc())
                time.sleep(5) # Longer pause on critical error

        # Cleanup on stop
        try:
            EvtClose(query_handle)
        except:
            pass
        self.logger.logger.info("[Sysmon] Stopped monitoring Sysmon events.")

    def start_monitoring(self):
        """Start the Sysmon monitoring in a background thread."""
        if not WINEVT_AVAILABLE:
             print("  [Sysmon Monitor] Disabled (Winevt API unavailable)")
             return
        self.running = True
        self.thread = threading.Thread(target=self.monitor_sysmon_events, daemon=True)
        self.thread.start()

    def stop_monitoring(self):
        """Signal the monitoring thread to stop."""
        self.running = False
        if hasattr(self, 'thread'):
            self.thread.join(timeout=5) 


# --- Main Application ---
def main():
    print("Real-Time DLL Scanner & Remover")
    print("=" * 40)
    print("Press Ctrl+C to stop the scanner.")

    # Setup
    logger = SecurityLogger()
    scanner = DLLSecurityScanner(logger)
    sysmon_monitor = SysmonMonitor(logger, scanner)

    scan_interval_seconds = 60
    sysmon_monitor.start_monitoring()

    try:
        while True:
            try:
                print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting file system scan cycle...")
                results = scanner.scan_and_delete_suspicious_dlls(risk_threshold=50)

                print(f"File System Scan Cycle Results:")
                print(f"  Scanned: {results['scanned']} DLLs")
                print(f"  Suspicious: {results['suspicious']} DLLs")
                print(f"  Deleted: {results['deleted']} DLLs")
                print(f"  Errors: {results['errors']}")
                
            except Exception as e:
                logger.logger.error(f"Error during scan cycle: {e}")
                print(f"  [SCAN ERROR] {str(e)}")
                
            print(f"Waiting {scan_interval_seconds} seconds before next scan...")
            time.sleep(scan_interval_seconds)

    except KeyboardInterrupt:
        print("\nReceived interrupt signal. Shutting down...")
    except Exception as e:
        logger.logger.critical(f"Scanner crashed: {e}")
        print(f"\nFatal error: {e}")
    finally:
        sysmon_monitor.stop_monitoring()
        logger.logger.info("Scanner stopped.")


if __name__ == "__main__":
    if WINDOWS_AVAILABLE:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Warning: This script requires Administrator privileges for full functionality (Sysmon log access, file deletion).")
            # run ur code as admin please 
            # ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            # sys.exit()

    main()