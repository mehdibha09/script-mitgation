import winreg
from logger import MAIN_LOGGER
from utils.constants import PERSISTENCE_NAME, REGISTRY_RUN_KEY


def remove_registry_key(value_name):
    """Remove a specific value from the Run key."""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_RUN_KEY, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, value_name)
        winreg.CloseKey(key)
        MAIN_LOGGER.logger.info(f" Removed registry persistence key: {value_name}")
    except Exception as e:
        MAIN_LOGGER.logger.error(f"Failed to remove registry key {value_name}: {e}")


def _open_reg_key(hive, path, rights):
    """Open a registry key, trying WOW64 variations."""
    for flag in (0, winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        try:
            return winreg.OpenKey(hive, path, 0, rights | flag)
        except OSError:
            continue
    raise

def check_and_remove_registry_persistence():
    """Actively check for and remove the keylogger's registry persistence."""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_RUN_KEY, 0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                if name == PERSISTENCE_NAME:
                    value_str = str(value)
                    MAIN_LOGGER.logger.critical(f" REGISTRY PERSISTENCE DETECTED: {name} = {value_str}")
                    # Remove it
                    remove_registry_key(PERSISTENCE_NAME)
                    return
                i += 1
            except WindowsError:
                break
    except Exception as e:
        MAIN_LOGGER.logger.error(f"Error reading registry for persistence: {e}")