import subprocess
import time
import sys
import os
import psutil  # Nécessaire pour vérifier l'existence du PID
import platform

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.permissions import run_as_admin

def start_watchdog_a():
    script_path = os.path.join(os.path.dirname(__file__), "watchdog_a.py")

    creationflags = 0
    python_exe = sys.executable

    if platform.system() == "Windows":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        # Remplacer python.exe par pythonw.exe pour cacher la console
        pythonw_exe = sys.executable.replace("python.exe", "pythonw.exe")
        if os.path.exists(pythonw_exe):
            python_exe = pythonw_exe

    process = subprocess.Popen(
        [python_exe, script_path],
        creationflags=creationflags,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        close_fds=True
    )
    print(f"[Watchdog B] Launched watchdog_a.py with PID {process.pid}")
    return process.pid

def pid_exists(pid):
    return psutil.pid_exists(pid)

def main():
    run_as_admin()
    pid = start_watchdog_a()
    try:
        while True:
            if not pid_exists(pid):
                print("[Watchdog B] watchdog_a.py died (PID not found). Restarting...")
                pid = start_watchdog_a()
            time.sleep(5)
    except KeyboardInterrupt:
        print("[Watchdog B] Stopped by user")
        try:
            if pid_exists(pid):
                p = psutil.Process(pid)
                p.terminate()
        except Exception:
            pass
        sys.exit(0)
    except Exception as e:
        print(f"[Watchdog B] Error: {e}")
        try:
            if pid_exists(pid):
                psutil.Process(pid).terminate()
        except Exception:
            pass

if __name__ == "__main__":
    main()
