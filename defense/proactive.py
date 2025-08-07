
import time
import traceback
import winreg
import psutil
from logger import MAIN_LOGGER
from utils.common import kill_process_tree

def proactive_defense_thread():
    """A high-frequency thread that actively blocks threats."""
    MAIN_LOGGER.logger.info(" Starting proactive defense thread (5Hz).")

    while True:
        try:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_RUN_KEY, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        if SCREENSHOT_BLOCKER_ENABLED:
                            detect_screenshot_activity()

                        time.sleep(0.2)
                        name, value, _ = winreg.EnumValue(key, i)
                        if name == PERSISTENCE_NAME:
                            value_str = str(value)
                            MAIN_LOGGER.logger.critical(f" BLOCKED REGISTRY PERSISTENCE: {name} = {value_str}")
                            try:
                                key_write = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_RUN_KEY, 0, winreg.KEY_SET_VALUE)
                                winreg.DeleteValue(key_write, name)
                                winreg.CloseKey(key_write)
                                MAIN_LOGGER.logger.info(f" Removed registry key: {name}")
                            except Exception as e:
                                MAIN_LOGGER.logger.error(f"Failed to delete registry key: {e}")
                        i += 1

                    except WindowsError:
                        break
                winreg.CloseKey(key)
            except Exception as e:
                MAIN_LOGGER.logger.error(f"Error in registry check: {e}")

            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        name = proc.info['name'].lower()
                        cmdline = ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ''
                        pid = proc.info['pid']

                        if (name == "python.exe" or name == "pythonw.exe") and ("keylogger" in cmdline or "watchdog" in cmdline):
                            try:
                                modules = proc.memory_maps()
                                for module in modules:
                                    if "PIL" in module.path or "Pillow" in module.path:
                                        MAIN_LOGGER.logger.critical(f" BLOCKED SCREENSHOT ATTEMPT: Keylogger PID={pid} loaded PIL module.")
                                        kill_process_tree(pid, kill_parent=True)
                                        break
                            except (psutil.AccessDenied, Exception) as e:
                                MAIN_LOGGER.logger.warning(f"Could not read modules for PID {pid}: {e}")

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

            except Exception as e:
                MAIN_LOGGER.logger.error(f"Error in screenshot check: {e}")

            time.sleep(0.2)  # Run at 5Hz

        except Exception as e:
            MAIN_LOGGER.logger.critical(f"Proactive defense thread crashed: {e}")
            MAIN_LOGGER.logger.critical(traceback.format_exc())
            time.sleep(5)