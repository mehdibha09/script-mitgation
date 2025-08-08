import subprocess
import time
import sys
import os
import psutil
import platform

def is_main_running():
    """Vérifie si main.py est déjà en cours d'exécution"""
    for proc in psutil.process_iter(['cmdline']):
        try:
            if proc.info['cmdline'] and "main.py" in " ".join(proc.info['cmdline']):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False

def start_main():
    """Lance main.py uniquement s'il ne tourne pas déjà"""
    if is_main_running():
        print("[Watchdog A] main.py is already running. Not starting a new instance.")
        return None

    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "main.py"))

    if platform.system() == "Windows":
        creationflags = subprocess.CREATE_NEW_CONSOLE
    else:
        creationflags = 0

    python_exe = "python3"

    process = subprocess.Popen(
        [python_exe, script_path],
        creationflags=creationflags,
        close_fds=True
    )
    print(f"[Watchdog A] Launched main.py with PID {process.pid}")
    return process.pid

def pid_exists(pid):
    return psutil.pid_exists(pid)

def main():
    pid = start_main()

    try:
        while True:
            if pid is None:
                # main.py tournait déjà, il faut maintenant surveiller celui qui tourne
                for proc in psutil.process_iter(['pid', 'cmdline']):
                    try:
                        if proc.info['cmdline'] and "main.py" in " ".join(proc.info['cmdline']):
                            pid = proc.info['pid']
                            break
                    except Exception:
                        continue

            if pid is not None and not pid_exists(pid):
                print("[Watchdog A] main.py died. Restarting...")
                pid = start_main()
            time.sleep(5)
    except KeyboardInterrupt:
        print("[Watchdog A] Stopped by user")
        try:
            if pid and pid_exists(pid):
                psutil.Process(pid).terminate()
        except Exception:
            pass
        sys.exit(0)
    except Exception as e:
        print(f"[Watchdog A] Error: {e}")
        try:
            if pid and pid_exists(pid):
                psutil.Process(pid).terminate()
        except Exception:
            pass

if __name__ == "__main__":
    main()
