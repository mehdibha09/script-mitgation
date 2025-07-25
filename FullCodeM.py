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
import winreg
import time

# Required imports
try:
    import psutil
except ImportError as e:
    print(f"Missing required module: {e}")
    print("Install with: pip install psutil")
    sys.exit(1)

WINDOWS_AVAILABLE = (os.name == 'nt')

SMB_PORTS = {445, 139}
LATERAL_TOOLS = {
    "powershell.exe", "cmd.exe", "psexec.exe", "wmic.exe", "wmiprvse.exe",
    "sc.exe", "reg.exe", "rundll32.exe", "at.exe", "schtasks.exe",
    "python.exe", "pythonw.exe", "python3.exe", "python3.11.exe"
}
LOG_FILE = "registre_suspect.log"


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

    def log(self,msg):
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"
        line = f"{ts} {msg}"
        print(line)
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass
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
        """
        Tuer un processus et tous ses enfants (amélioré).
        - Utilise psutil.kill() par défaut, avec fallback taskkill si échec.
        - Exclut le PID actuel (processus Python).
        - Vérifie est_legitime() avant de tuer.
        """
        pid_exclu = os.getpid()

        try:
            parent = psutil.Process(pid)
            self.logger.logger.info(f"[Sysmon] Tentative de kill PID={pid} ({parent.name()})")
        except psutil.NoSuchProcess:
            self.logger.logger.warning(f"[Sysmon] Processus {pid} introuvable")
            return

        # --- Kill enfants ---
        try:
            for child in parent.children(recursive=True):
                if child.pid == pid_exclu:
                    self.logger.logger.info(f"[Sysmon] PID {child.pid} exclu (processus actuel)")
                    continue
                try:
                    if not self.est_legitime(child):
                        child.kill()
                        self.logger.logger.info(f"[Sysmon] Enfant tué: {child.pid} ({child.name()})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Fallback avec taskkill
                    subprocess.run(["taskkill", "/PID", str(child.pid), "/F", "/T"], capture_output=True)
                    self.logger.logger.warning(f"[Sysmon] Taskkill forcé enfant {child.pid}")
        except psutil.Error as e:
            self.logger.logger.warning(f"[Sysmon] Erreur récupération enfants PID {pid}: {e}")

        # --- Kill parent ---
        if kill_parent:
            try:
                if not self.est_legitime(parent):
                    parent.kill()
                    self.logger.logger.info(f"[Sysmon] Processus {pid} ({parent.name()}) tué")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"], capture_output=True)
                self.logger.logger.warning(f"[Sysmon] Taskkill forcé parent {pid}")


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

    def detect_event_id_1(self, event_data):
        """
        Analyse Sysmon EventID 1 (ProcessCreate) pour détecter :
        - Processus suspects (cmd.exe, powershell.exe, etc.)
        - Commandes suspectes (obfuscation, encodage, ransomware keywords)
        - Chargement de DLLs depuis des chemins suspects (rundll32/regsvr32)
        """
        try:
            nom_processus = os.path.basename(event_data.get("Image", "")).lower()
            ligne_commande = (event_data.get("CommandLine") or "").lower()
            pid_str = event_data.get("ProcessId")

            parent_image = os.path.basename(event_data.get("ParentImage", "")).lower()
            parent_cmd = (event_data.get("ParentCommandLine") or "").lower()
            parent_user = (event_data.get("ParentUser", "")).lower()
        except Exception:
            return False

        # --- [1] Listes de référence ---
        processus_suspects = [
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "regsvr32.exe", "rundll32.exe",
            "schtasks.exe", "taskschd.msc", "certutil.exe", "curl.exe",
            "python.exe", "pythonw.exe", "python3.exe", "python3.11.exe"
        ]

        ransomware_keywords = [
            "watchdog.vbs", ".vbs", "themes", "ransomware",
            ".locked", "encoder.py", "script-mitgation"
        ]

        suspicious_paths = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
            '\\users\\public\\', '\\programdata\\', '\\downloads\\'
        ]

        suspicious = False

        # --- [2] Détection par nom de processus ---
        if nom_processus in processus_suspects:
            suspicious = True

        # --- [3] Détection par mots-clés dans la commande ---
        if any(keyword in ligne_commande for keyword in ransomware_keywords):
            suspicious = True
        if any(keyword in parent_cmd for keyword in ransomware_keywords):
            suspicious = True

        # --- [4] Détection de commandes suspectes ---
        if self.est_commande_suspecte(ligne_commande):
            suspicious = True

        # --- [5] Cas spécifique : wscript lancé par python ---
        if nom_processus == "wscript.exe" and "python" in parent_image:
            suspicious = True

        # --- [6] Vérification DLL via rundll32/regsvr32 ---
        if "rundll32.exe" in nom_processus or "regsvr32.exe" in nom_processus:
            for sus_path in suspicious_paths:
                if sus_path in ligne_commande:
                    self.logger.log_action("SYSMON_SUSPICIOUS_DLL_LOAD_CMD", {
                        "process": nom_processus,
                        "command_line": ligne_commande,
                        "suspicious_path": sus_path,
                        "source": "Sysmon_Event_1"
                    })
                    print(f"[🚨] Chargement DLL suspect depuis {sus_path} par {nom_processus}")
                    suspicious = True
                    break

        # --- [7] Si rien de suspect ---
        if not suspicious:
            print("DEBUG Pas suspect (EventID 1)")
            return False

        # --- [8] Logging de l'alerte ---
        print(f"[⚠️] Processus suspect détecté (EventID 1) : {nom_processus}")
        print(f"      CommandLine : {ligne_commande}")
        print(f"      Parent : {parent_image} ({parent_user}) -> {parent_cmd}")

        self.logger.log_action("SYSMON_SUSPICIOUS_PROCESS", {
            "process": nom_processus,
            "command_line": ligne_commande,
            "parent_image": parent_image,
            "parent_command_line": parent_cmd,
            "source": "Sysmon_Event_1"
        })

        # --- [9] Tentative de kill ---
        if pid_str and pid_str.isdigit():
            pid = int(pid_str)
            try:
                proc = psutil.Process(pid)
                if not est_legitime(proc):
                    print(f"[🔪] Kill tree PID={pid}")
                    self.kill_process_tree(pid, kill_parent=True)
                else:
                    print(f"[INFO] Processus {pid} ({proc.name()}) légitime - non tué.")
            except Exception as e:
                print(f"[!] Échec du kill du processus {pid} : {e}")

        return True

        
    def detect_smb_propagation(self, event_data):
    
    #Détection propagation SMB (Sysmon EventID 3 - NetworkConnect).
    #Détecte des connexions SMB (ports 445/139) initiées par des processus suspects 
    #ou des commandes malveillantes (latéralisation).
        try:
            image = os.path.basename((event_data.get("Image") or "")).lower()
            cmd   = (event_data.get("CommandLine") or "").lower()
            dport = int(event_data.get("DestinationPort") or 0)
            dip   = (event_data.get("DestinationIp") or "")
            pid   = event_data.get("ProcessId")
        except Exception:
            return False

        # Vérification du port (SMB)
        if dport not in SMB_PORTS:
            return False

        # Vérifie si le processus ou la commande est suspecte
        is_suspect = (image in LATERAL_TOOLS) or self.est_commande_suspecte(cmd)
        if not is_suspect:
            return False

        # Log de l'activité suspecte
        self.log(f"[🚨] Connexion SMB suspecte → {image} PID={pid} vers {dip}:{dport}")
        self.log(f"     CMD: {cmd}")

        # Tentative de neutralisation du processus
        if pid and str(pid).isdigit():
            try:
                proc = psutil.Process(int(pid))
                if not self.est_legitime(proc):
                    self.kill_process_tree(int(pid), kill_parent=True)
                    self.log(f"[✔] Processus {pid} terminé (propagation SMB).")
            except Exception as e:
                self.log(f"[!] Impossible de tuer PID {pid}: {e}")

        return True
    def detect_pipe_lateral(self, event_data):
        """
        Sysmon EventID 17 (Pipe Created) / 18 (Pipe Connected)
        Détecte PsExec et autres outils via les noms de pipes.
        """
        pipe = (event_data.get("PipeName") or "").lower()
        pid  = event_data.get("ProcessId")

        # Pipes typiques PsExec / RemCom / SMB lateralisation
        SUSPICIOUS_PIPES = (r"\psexesvc", r"\remcom_communic", r"\paexec", r"\atsvc")

        if any(p in pipe for p in SUSPICIOUS_PIPES):
            self.log(f"[🚨] Pipe latérale suspecte : {pipe} (PID={pid})")
            if pid and pid.isdigit():
                try:
                    proc = psutil.Process(int(pid))
                    if not self.est_legitime(proc):
                        self.kill_process_tree(int(pid), kill_parent=True)
                except Exception as e:
                    self.log(f"[!] Impossible de tuer PID {pid}: {e}")
            return True

        return False
    
    def detect_registre(self.event_data):
        cle = (event_data.get("TargetObject") or "").lower()
        valeur = (event_data.get("Details") or "").lower()
        event_type = (event_data.get("EventType") or "").lower()
        pid_str = event_data.get("ProcessId")

        cles_suspectes = [
            r"\\run", r"\\runonce", r"\\image file execution options",
            r"\\winlogon", r"\\shell", r"\\services", r"\\appinit_dlls", r"\\policies\\system"
        ]

        commandes_suspectes = [
            "powershell", "cmd.exe", "wscript", "regsvr32",
            ".vbs", ".js", ".bat", ".ps1", "frombase64string", "-enc", "iex"
        ]

        if not any(re.search(cle_suspecte, cle) for cle_suspecte in cles_suspectes):
            return

        self.log(f"Clé registre critique modifiée : {cle}")

        if not any(cmd in valeur for cmd in commandes_suspectes):
            return

        self.log(f"[⚠️] Valeur suspecte détectée : {valeur}")

        try:
            parts = cle.split("\\")
            hive_name = parts[0].upper()
            sous_cle = "\\".join(parts[1:-1])
            nom_valeur = parts[-1]

            hive = {
                "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
                "HKLM": winreg.HKEY_LOCAL_MACHINE,
                "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
                "HKCU": winreg.HKEY_CURRENT_USER,
                "HKEY_USERS": winreg.HKEY_USERS,
                "HKU": winreg.HKEY_USERS
            }.get(hive_name, None)
            if hive:
                if event_type == "setvalue":
                    with _open_reg_key(hive, sous_cle, winreg.KEY_SET_VALUE) as key:
                        winreg.DeleteValue(key, nom_valeur)
                        self.log(f"[✔] Valeur supprimée du registre : {nom_valeur}")
                elif event_type == "createkey":
                    parent_path = "\\".join(parts[1:-1])
                    with _open_reg_key(hive, parent_path, winreg.KEY_ALL_ACCESS) as parent_key:
                        winreg.DeleteKey(parent_key, nom_valeur)
                        self.log(f"[✔] Clé supprimée : {cle}")
            else:
                self.log(f"[!] Hive non reconnu : {hive_name}")

        except Exception as e:
            self.log(f"[!] Erreur suppression registre : {e}")

        if pid_str and pid_str.isdigit():
            pid = int(pid_str)
            try:
                proc = psutil.Process(pid)
                if not self.est_legitime(proc):
                    self.log(f"[🔪] Processus suspect tué : {proc.name()} (PID: {pid})")
                    proc.kill()
            except Exception as e:
                self.log(f"[!] Impossible d'accéder au processus {pid} : {e}")


    def detect_event_id_11(self, event_data):
        """
        Détection Sysmon EventID 11 (FileCreate) :
        - Suspicious DLL creation (DLL dans des emplacements suspects, contenu suspect).
        - Fichiers chiffrés détectés (.locked, .enc, .crypt, .encrypted).
        - Création de fichiers sur des partages ADMIN$, C$, IPC$.
        """
        fichier = (event_data.get("TargetFilename") or "").strip()
        pid_str = event_data.get("ProcessId")

        # Normalisation en minuscule pour certaines vérifications
        fichier_lower = fichier.lower()

        # --- [1] Analyse DLL suspecte ---
        if fichier_lower.endswith('.dll'):
            if self.dll_scanner.is_suspicious_location(fichier):
                try:
                    metadata = self.dll_scanner.get_file_metadata(fichier)
                    content_patterns = self.dll_scanner.analyze_dll_content(fichier)

                    # Calcul du score de risque (ou valeur par défaut haute)
                    risk_score = self.dll_scanner.calculate_risk_score(
                        metadata if metadata else {},
                        content_patterns,
                        location_suspicious=True
                    ) if metadata else 60  # Si pas de metadata, on assume un risque élevé.

                    if risk_score >= 50:
                        self.logger.log_action("SYSMON_SUSPICIOUS_DLL_CREATED", {
                            "file_path": fichier,
                            "risk_score": risk_score,
                            "location_suspicious": True,
                            "content_patterns": content_patterns,
                            "source": "Sysmon_Event_11"
                        })
                        print(f"[SYSMON ALERT - Suspicious DLL Created] {fichier} (Risk: {risk_score})")

                        # Suppression immédiate de la DLL
                        self.dll_scanner.delete_dll(
                            fichier,
                            metadata,
                            risk_score,
                            ["sysmon_file_creation", "suspicious_location"] + [f"pattern_{p}" for p in content_patterns[:2]]
                        )

                        # Kill le processus créateur
                        if pid_str and pid_str.isdigit():
                            self.kill_process_tree(int(pid_str), kill_parent=True)
                        return True
                except Exception as e:
                    print(f"[!] Erreur analyse DLL : {e}")

        # --- [2] Détection fichier chiffré (extensions ransomwares) ---
        if fichier_lower.endswith((".locked", ".enc", ".crypt", ".encrypted")):
            log(f"[🧨] Fichier chiffré détecté : {fichier_lower}")
            log(f"[DEBUG] ProcessId détecté : {pid_str}")
            if pid_str and pid_str.isdigit():
                kill_process_tree(int(pid_str), kill_parent=True)
            else:
                log("[WARN] ProcessId invalide ou manquant")
            return True

        # --- [3] Détection création fichier sur partage admin$ ---
        if re.match(r"^\\\\[^\\]+\\(admin\$|c\$|ipc\$)\\", fichier_lower):
            log(f"[🚨] Création sur partage admin : {fichier_lower} (PID={pid_str})")
            if pid_str and pid_str.isdigit():
                try:
                    proc = psutil.Process(int(pid_str))
                    if not est_legitime(proc):
                        kill_process_tree(int(pid_str), kill_parent=True)
                except Exception as e:
                    log(f"[!] Impossible de tuer PID {pid_str}: {e}")
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
                        if not event_id or event_id == 255:
                            continue

                        if event_id == 11: # File created
                            self.detect_event_id_11(event_data)
                        elif event_id == 1: # Process created
                            self.detect_event_id_1(event_data)
                        elif event_id == 3:
                            self.detect_smb_propagation(event_data)
                        elif event_id in (17, 18):
                            self.detect_pipe_lateral(event_data)
                        elif event_id in (12, 13, 14):
                            self.detect_registre(event_data)
                            

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


def add_to_registry(app_name="SysmonMonitor", script_path=None):
    """
    Ajoute une clé de registre pour lancer le script au démarrage de Windows.
    - Utilise HKCU (Current User).
    - Si script_path n'est pas un .exe, il ajoute 'python.exe <script.py>'
    """
    try:
        if script_path is None:
            script_path = os.path.abspath(__file__)

        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Le script '{script_path}' n'existe pas.")

        # Si ce n'est pas un .exe, on utilise python.exe
        if not script_path.lower().endswith(".exe"):
            exe_cmd = f'"{sys.executable}" "{script_path}"'
        else:
            exe_cmd = f'"{script_path}"'

        # Clé registre Run (Current User)
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, exe_cmd)
        winreg.CloseKey(key)

        print(f"[✔] '{app_name}' ajouté au registre (démarrage automatique).")

    except Exception as e:
        print(f"[ERROR] Impossible d'ajouter au registre : {e}")


def run_as_admin():
    """Relance le script avec droits administrateur si nécessaire."""
    try:
        # Vérifie si le script est déjà en admin
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False

    if not is_admin:
        # Relance en admin
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
        except Exception as e:
            print(f"[!] Impossible de demander les droits admin: {e}")
        sys.exit(0)  # Quitte le script courant

# --- Main Application ---
def main():
    run_as_admin()
    add_to_registry()
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