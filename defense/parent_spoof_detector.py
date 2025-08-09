# parent spoof detector.py
import psutil
import logging
import os
import hashlib
import time
from collections import defaultdict
import subprocess
import requests
from utils.constants import (
    MAX_REQUESTS,
    SUSPICIOUS_PARENT_CHILD,
    SUSPICIOUS_PROCESS_NAMES,
    SUSPICIOUS_CMDLINE_PATTERNS,
    SUSPICIOUS_PATHS,
    TARGET_FOR_INJECTION,
    SIGCHECK_PATH,
    TIME_LIMIT,
    VIRUSTOTAL_API_KEY,
    VIRUSTOTAL_URL
  )
import collections
import threading
"""
explanation :
This module provides functionality to detect suspicious parent-child process relationships,
it defines lists of rules for suspicious parent-child pairs, process names, command line(like an explorrer.exe with powershell.exe),
also it defines suspicious file paths like temp , %appdata% and so on 
The detection logic scans running processes, checking for suspicious activity based on the defined rules.
"""


request_times = collections.deque()
waiting_queue = collections.deque()

# --- Helper Functions ---

def calculate_sha256(file_path):
    """Calculates the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        logging.debug(f"Could not calculate hash for {file_path}")
        return None
def kill_process(pid):
    """Terminate a process by PID."""
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(timeout=3)
        logging.warning(f"[!] Process {pid} terminated successfully.")
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        logging.error(f"[!] Could not terminate process {pid}: {e}")
def can_make_request():
    """Retourne True si une requête VT peut être exécutée maintenant."""
    current_time = time.time()
    while request_times and current_time - request_times[0] > TIME_LIMIT:
        request_times.popleft()
    return len(request_times) < MAX_REQUESTS

def queue_or_execute_request(hash_value):
    """Exécute ou met en file d'attente la requête VT."""
    if can_make_request():
        request_times.append(time.time())
        return check_virustotal(hash_value)
    else:
        logging.warning(f"Limite VirusTotal atteinte, mise en attente : {hash_value}")
        waiting_queue.append(hash_value)
        return None
def process_waiting_queue():
    """Vider la liste d’attente quand possible."""
    while waiting_queue and can_make_request():
        hv = waiting_queue.popleft()
        logging.info(f"Exécution d'une requête en attente : {hv}")
        request_times.append(time.time())
        check_virustotal(hv)

def check_virustotal(hash_value):
    """Query VirusTotal using SHA-256 hash."""
    if not VIRUSTOTAL_API_KEY:
        logging.warning("VirusTotal API key not set. Skipping VT check.")
        return None

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(VIRUSTOTAL_URL + hash_value, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            # check stat containe malicous or suspicious 
            if not stats:
                logging.warning(f"No analysis stats found for {hash_value}")
                return False
            # Example stats: {'malicious': 5, 'suspicious': 1
            if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
                return True
            else:
                return False
        elif response.status_code == 404:
            return False
        else:
            return False
    except Exception as e:
        logging.error(f"VirusTotal check error: {e}")
        return None
    

def is_unsigned_or_invalid_sig(path):
    """
    Uses Microsoft Sigcheck to verify if an executable is signed and valid.
    Returns True if the file is unsigned or has an invalid signature.
    """
    if not path or not os.path.exists(path):
        return True  # File doesn't exist → treat as suspicious

    try:
        # Run sigcheck silently, no banner, only signature info
        result = subprocess.run(
            [SIGCHECK_PATH, "-q", "-nobanner", "-i", path],
            capture_output=True,
            text=True
        )

        # Check if the output says it's signed
        if "Verified: Signed" in result.stdout:
            return False  # Signed and valid
        else:
            return True   # Unsigned or invalid
    except Exception as e:
        logging.error(f"Error verifying signature for {path}: {e}")
        return True


# --- Core Detection Logic ---

def detect_suspicious_processes(alert_callback=None):
    """
    Scans running processes for suspicious activity.
    Calls `alert_callback(alert_dict)` for each alert found.
    Returns the number of alerts generated.
    """
    alerts_generated = 0
    current_time = time.time()

    # --- Track process creation rates ---
    process_creation_counter = defaultdict(int)

    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'create_time', 'username']):
        try:
            # --- Gather Process Information ---
            pid = proc.info['pid']
            ppid = proc.info['ppid']
            name = proc.info['name'].lower() if proc.info['name'] else ""
            exe_path = proc.info['exe']
            cmdline_list = proc.info['cmdline'] if proc.info['cmdline'] else []
            cmdline_str = " ".join(cmdline_list).lower()
            create_time = proc.info['create_time']
            username = proc.info['username']

            # Skip system idle process and system process
            if pid in [0, 4] or name in ['system idle process', 'system']:
                continue

            # --- 1. Check Parent-Child Relationships ---
            try:
                parent_proc = psutil.Process(ppid)
                parent_name = parent_proc.name().lower()
                parent_exe = parent_proc.exe()
                pair = (parent_name, name)

                if pair in SUSPICIOUS_PARENT_CHILD:
                    alert_info = {
                        "type": "Suspicious Parent-Child",
                        "description": f"Suspicious parent-child process pair detected: {parent_name} (PID:{ppid}) -> {name} (PID:{pid})",
                        "severity": "High",
                        "details": {
                            "pid": pid,
                            "ppid": ppid,
                            "name": name,
                            "exe": exe_path,
                            "cmdline": cmdline_str,
                            "parent_name": parent_name,
                            "parent_exe": parent_exe,
                            "timestamp": current_time
                        }
                    }
                    if alert_callback:
                        alert_callback(alert_info)
                    kill_process(pid)
                    alerts_generated += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
                pass 

            # --- 2. Check Suspicious Process Names ---
            if name in SUSPICIOUS_PROCESS_NAMES:
                alert_info = {
                    "type": "Suspicious Process Name",
                    "description": f"Suspicious process name detected: {name}",
                    "severity": "High",
                    "details": {
                        "pid": pid,
                        "ppid": ppid,
                        "name": name,
                        "exe": exe_path,
                        "cmdline": cmdline_str,
                        "timestamp": current_time
                    }
                }
                if alert_callback:
                    alert_callback(alert_info)
                kill_process(pid)
                alerts_generated += 1

            # --- 3. Check Suspicious Command Line Arguments ---
            for pattern, target_proc in SUSPICIOUS_CMDLINE_PATTERNS:
                # If target_proc is None, it means we check for any process with this cmdline pattern
                if (target_proc is None or name == target_proc) and pattern in cmdline_str:
                    alert_info = {
                        "type": "Suspicious Cmdline",
                        "description": f"Suspicious command line argument detected: '{pattern}' in process {name}",
                        "severity": "Medium", # Adjust based on pattern
                        "details": {
                            "pid": pid,
                            "ppid": ppid,
                            "name": name,
                            "exe": exe_path,
                            "cmdline": cmdline_str, 
                            "timestamp": current_time
                        }
                    }
                    if alert_callback:
                        alert_callback(alert_info)
                    alerts_generated += 1
                    break 

            # --- 4. Check Process Image Path ---
            if exe_path:
                normalized_path = exe_path.lower()
                for susp_path in SUSPICIOUS_PATHS:
                    if normalized_path.startswith(susp_path.lower()):
                        alert_info = {
                            "type": "Suspicious Path",
                            "description": f"Process running from suspicious path: {exe_path}",
                            "severity": "Medium",
                            "details": {
                                "pid": pid,
                                "ppid": ppid,
                                "name": name,
                                "exe": exe_path,
                                "cmdline": cmdline_str,
                                "timestamp": current_time
                            }
                        }
                        if alert_callback:
                            alert_callback(alert_info)
                        alerts_generated += 1
                        break 

            # --- 5. Check Digital Signature ---
            #using windows crypto api to check digital signature
            
            if exe_path and os.path.exists(exe_path):
                unsigned = is_unsigned_or_invalid_sig(exe_path)
                #check limite api max per 1 minute 4 requeste 
                if unsigned:
                    sha256 = calculate_sha256(exe_path)
                    vt_result = queue_or_execute_request(sha256) if sha256 else None
                    if vt_result is False:
                        # Erreur critique ou refus → on sort complètement
                        return
                    
                    elif vt_result is None:
                        # Requête mise en attente → pas d'alerte maintenant
                        logging.debug(f"VT check pour {exe_path} en attente, alerte non générée.")
                    else:
                        if vt_result and isinstance(vt_result, dict):
                            if vt_result.get("malicious", 0) > 0:
                                kill_process(pid)
                        alert_info = {
                            "type": "Unsigned Binary",
                            "description": f"Potentially unsigned or unverifiable binary detected: {exe_path}",
                            "severity": "Medium",
                            "details": {
                                "pid": pid,
                                "ppid": ppid,
                                "name": name,
                                "exe": exe_path,
                                "cmdline": cmdline_str,
                                "sha256": sha256,
                                "virustotal": vt_result,
                                "timestamp": current_time
                            }
                        }
                        if alert_callback:
                            alert_callback(alert_info)
                        alerts_generated += 1


            # --- 6. Check for Process Hollowing Targets Being Spawned ---
           
            # if name in TARGET_FOR_INJECTION:
                
            #     alert_info = {                    "type": "Process Hollowing Target",
            #         "description": f"Process {name} (PID:{pid}) is a common target for injection or hollowing.",
            #         "severity": "High",
            #         "details": {
            #             "pid": pid,
            #             "ppid": ppid,
            #             "name": name,
            #             "exe": exe_path,
            #             "cmdline": cmdline_str,
            #             "timestamp": current_time
            #         }
            #     }
            #     if alert_callback:
            #         alert_callback(alert_info)
            #     kill_process(pid)
            #     alerts_generated += 1
                


            # --- 7. Check Process Age for Rapid Spawning (Basic DoS/Spam Check) ---
            age = current_time - create_time
            if age < 60: # Process created in the last minute
                process_creation_counter[name] += 1

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass 
        except Exception as e:
            # logging.error(f"Error checking process PID {proc.info.get('pid', 'Unknown')}: {e}")
            pass

    # --- 8. Check for Rapid Process Creation ---
    for proc_name, count in process_creation_counter.items():
        if count > 20: 
            alert_info = {
                "type": "Rapid Process Creation",
                "description": f"High rate of '{proc_name}' process creation detected ({count} in last minute)",
                "severity": "Medium",
                "details": {
                    "process_name": proc_name,
                    "count": count,
                    "time_window": 60,
                    "timestamp": current_time
                }
            }
            if alert_callback:
                alert_callback(alert_info)
            alerts_generated += 1

    return alerts_generated


# --- Continuous Monitoring ---
def vt_queue_worker():
        while True:
            process_waiting_queue()
            time.sleep(5)  # vérifie toutes les 5 sec

def continuous_monitor(alert_callback, scan_interval=10):
    """Continuously monitors processes."""
    logging.info("Starting continuous process monitoring...")

        # Thread pour traiter la queue VirusTotal
 

    threading.Thread(target=vt_queue_worker, daemon=True).start()

    try:
        while True:
            num_alerts = detect_suspicious_processes(alert_callback)
            if num_alerts == 0:
                logging.debug("Process scan completed. No alerts.")
            else:
                 logging.info(f"Process scan completed. Generated {num_alerts} alert(s).")
            time.sleep(scan_interval)
    except Exception as e:
        logging.error(f"Error in continuous process monitoring: {e}")


