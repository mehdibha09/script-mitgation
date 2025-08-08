import subprocess
import time
import sys

def start_main():
    # Démarre le script principal main.py
    return subprocess.Popen([sys.executable, "main.py"])

def main():
    process = start_main()
    try:
        while True:
            retcode = process.poll()
            if retcode is not None:
                # main.py est mort, on relance
                print("[Watchdog A] main.py died. Restarting...")
                process = start_main()
            time.sleep(5)
    except KeyboardInterrupt:
        print("[Watchdog A] Stopped by user")
        process.terminate()
        sys.exit(0)
    except Exception as e:
        print(f"[Watchdog A] Error: {e}")
        process.terminate()

if __name__ == "__main__":
    main()
