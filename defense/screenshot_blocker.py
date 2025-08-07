import psutil
from logger import MAIN_LOGGER
from utils.common import kill_process_tree
import re
from utils.constants import (
    SUSPICIOUS_PROCESS_NAMES,
    SUSPICIOUS_CMDLINE_PATTERNS,
    SUSPICIOUS_MODULES
)


# def detect_screenshot_activity():
#     """Scan running processes for screenshot-related activity."""
#     for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_info']):
#         try:
#             name = proc.info['name'].lower()
#             cmdline = ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ''
#             pid = proc.info['pid']

#             # Check for processes using PIL.ImageGrab
#             if any(susp in cmdline for susp in SUSPICIOUS_MODULES):
#                 alert = f"Suspicious screenshot attempt detected: PID={pid} Name={name} CMD={cmdline}"
#                 MAIN_LOGGER.logger.critical(alert)
#                 kill_process_tree(pid, kill_parent=True)
#                 return

#         except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
#             pass

def is_screenshot_attempt(proc):
    """Check if a process is likely attempting to take a screenshot."""
    try:
        name = proc.info['name'].lower()
        cmdline = ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ''
        pid = proc.info['pid']

        # Check name and command line
        if name not in SUSPICIOUS_PROCESS_NAMES:
            return False
        if not any(re.search(pattern, cmdline) for pattern in SUSPICIOUS_CMDLINE_PATTERNS):
            return False

        # Check loaded modules for PIL/Pillow
        try:
            modules = proc.memory_maps()
            for module in modules:
                if "PIL" in module.path or "Pillow" in module.path:
                    return True
        except (psutil.AccessDenied, Exception):
            pass

        return False
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False
    
def detect_screenshot_activity():
    """Actively scan for processes attempting to take screenshots."""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if is_screenshot_attempt(proc):
                MAIN_LOGGER.logger.critical(f"SCREENSHOT ATTEMPT DETECTED: PID={proc.info['pid']} Name={proc.info['name']} CMD={' '.join(proc.info['cmdline'])}")
                kill_process_tree(proc.info['pid'], kill_parent=True)
                return  
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass