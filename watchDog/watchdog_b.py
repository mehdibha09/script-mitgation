import subprocess
import time
import sys

def start_watchdog_a():
    return subprocess.Popen([sys.executable, "watchdog_a.py"])

def main():
    process = start_watchdog_a()
    try:
        while True:
            retcode = process.poll()
            if retcode is not None:
                print("[Watchdog B] watchdog_a.py died. Restarting...")
                process = start_watchdog_a()
            time.sleep(5)
    except KeyboardInterrupt:
        print("[Watchdog B] Stopped by user")
        process.terminate()
        sys.exit(0)
    except Exception as e:
        print(f"[Watchdog B] Error: {e}")
        process.terminate()

if __name__ == "__main__":
    main()
