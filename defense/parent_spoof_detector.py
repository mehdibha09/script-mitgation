# process_monitor.py
import psutil
import logging
import os
import hashlib
import time
import threading
from collections import defaultdict

# --- Configuration ---

SUSPICIOUS_PARENT_CHILD = {
    ("explorer.exe", "powershell.exe"),
    ("explorer.exe", "cmd.exe"),
    ("explorer.exe", "mshta.exe"),
    ("explorer.exe", "cscript.exe"), 
    ("explorer.exe", "wscript.exe"),
    ("svchost.exe", "python.exe"), 
    ("svchost.exe", "rundll32.exe"), 
    ("winlogon.exe", "explorer.exe"), 
    ("winlogon.exe", "powershell.exe"),
    ("lsass.exe", "rundll32.exe"), 
    ("lsass.exe", "powershell.exe"),
    ("csrss.exe", "rundll32.exe"), 
    ("csrss.exe", "powershell.exe"),
}

SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz.exe", "psexec.exe", "at.exe", "schtasks.exe", 
    "powershell.exe", "cmd.exe", "mshta.exe", "cscript.exe", "wscript.exe", 
    "rundll32.exe", "regsvr32.exe", "bitsadmin.exe"}

# Suspicious command line arguments or patterns
SUSPICIOUS_CMDLINE_PATTERNS = [
    ("-enc", "powershell.exe"), ("-encodedcommand", "powershell.exe"), ("-e ", "powershell.exe"), # PowerShell encoded commands
    ("FromBase64String", None),
    ("IEX", None), ("Invoke-Expression", None),
    ("/c ", "cmd.exe"), ("/k ", "cmd.exe"), 
    ("rundll32.exe", "javascript:"), 
    ("rundll32.exe", "vbscript:"), 
    ("-s", "powershell.exe"), # PowerShell scripts
    ("-nop", "powershell.exe"), # No profile
    ("-noni", "powershell.exe"), # No interactive
    ("-w hidden", "powershell.exe"), # Hidden window
    ("-windowstyle hidden", "powershell.exe"), # Hidden window style
    ("-ExecutionPolicy Bypass", "powershell.exe"), # Bypass execution policy
    ("-NoLogo", "powershell.exe"), # No logo
    ("-NoProfile", "powershell.exe"), # No profile
    ("-File ", "powershell.exe"), # File execution
    ("-Command ", "powershell.exe"), # Command execution
    ("-EncodedCommand ", "powershell.exe"), # Encoded command execution
    ]

# Suspicious directories where processes should not typically originate
SUSPICIOUS_PATHS = [
    os.path.expanduser("~\\AppData\\Local\\Temp\\"),
    os.path.expanduser("~\\AppData\\Roaming\\"),
    os.path.expanduser("~\\Desktop\\"),
    "C:\\Windows\\Temp\\",
    "C:\\Windows\\System32\\",
    "C:\\Windows\\SysWOW64\\",
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
    "C:\\Program Files\\Common Files\\",
    "C:\\Program Files (x86)\\Common Files\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
    "C:\\Users\\Public\\Documents\\",
    "C:\\Users\\Public\\Downloads\\",]

# Processes that are commonly used by malware for injection or hollowing
TARGET_FOR_INJECTION = {
    "explorer.exe", "svchost.exe", "lsass.exe", "winlogon.exe", "csrss.exe",
    "rundll32.exe", "powershell.exe", "cmd.exe", "mshta.exe", "cscript.exe", "wscript.exe"
}

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

def is_unsigned_or_invalid_sig(path):
    """Placeholder for signature checking.
    A real implementation would use tools like `sigcheck` or libraries like `pefile`.
    """

    if not path or not os.path.exists(path):
        return True 
    if path.lower().endswith('.exe'):
       
        trusted_dirs = [os.getenv('SystemRoot', 'C:\\Windows'), os.path.join(os.getenv('SystemRoot', 'C:\\Windows'), 'System32')]
        if any(path.lower().startswith(d.lower()) for d in trusted_dirs):
            return False 
        
        return True 
    return False 

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

            # --- 5. Check Digital Signature (Simplified Placeholder) ---
            if is_unsigned_or_invalid_sig(exe_path):
                alert_info = {
                    "type": "Unsigned Binary",
                    "description": f"Potentially unsigned or unverifiable binary detected: {exe_path}",
                    "severity": "Medium", # Could be legitimate unsigned software
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

            # --- 6. Check for Process Hollowing Targets Being Spawned ---
           
            if name in TARGET_FOR_INJECTION:
                
                alert_info = {                    "type": "Process Hollowing Target",
                    "description": f"Process {name} (PID:{pid}) is a common target for injection or hollowing.",
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
                


            # --- 7. Check Process Age for Rapid Spawning (Basic DoS/Spam Check) ---
            age = current_time - create_time
            if age < 60: # Process created in the last minute
                process_creation_counter[name] += 1

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass 
        except Exception as e:
            logging.error(f"Error checking process PID {proc.info.get('pid', 'Unknown')}: {e}")

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

def continuous_monitor(alert_callback, scan_interval=10):
    """Continuously monitors processes."""
    logging.info("Starting continuous process monitoring...")
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


