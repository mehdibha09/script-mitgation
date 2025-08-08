import subprocess
import sys
import os
import platform

def launch_script(script_name):
    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "watchDog",script_name))
    python_exe = sys.executable
    creationflags = 0
    if platform.system() == "Windows":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        pythonw_exe = python_exe.replace("python.exe", "pythonw.exe")
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
    print(f"Launched {script_name} with PID {process.pid}")
    return process.pid

def main():
    # Lancer watchdog_b.py (qui lance watchdog_a.py)
    launch_script("watchdog_b.py")
    # Si tu veux lancer main.py directement (pas nécessaire si watchdog_a le fait)
    # launch_script("main.py")

if __name__ == "__main__":
    main()
