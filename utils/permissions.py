import ctypes
import sys
from logger import MAIN_LOGGER  # Tu dois avoir MAIN_LOGGER dans logger.py

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