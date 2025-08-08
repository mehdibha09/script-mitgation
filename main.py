# main.py
import threading
import time
# from utils.permissions import run_as_admin
from scheduler.task_scheduler import add_task_scheduler
from sysmon.monitor import monitor_sysmon_log
from dll_scanner.scanner import run_dll_scanner_periodically
from defense.proactive import proactive_defense_thread
from logger import MAIN_LOGGER, DLL_LOGGER
from defense import parent_spoof_detector
def process_alert_callback(alert_message):
    MAIN_LOGGER.logger.warning(f"Process alert: {alert_message}")

def main():
    print("=" * 60)
    print("Integrated Security Monitor")
    print("Sysmon Monitoring + DLL Scanner + PROACTIVE DEFENSE")
    print("=" * 60)
    print("Press Ctrl+C to stop.")

    # run_as_admin()
    add_task_scheduler()

    # Start DLL scanner
    dll_scan_thread = threading.Thread(
        target=run_dll_scanner_periodically,
        args=(DLL_LOGGER, 1),
        daemon=True
    )
    dll_scan_thread.start()
    MAIN_LOGGER.logger.info("DLL Scanner thread started.")

    # Start proactive defense
    proactive_thread = threading.Thread(
        target=proactive_defense_thread,
        daemon=True
    )
    proactive_thread.start()
    MAIN_LOGGER.logger.info("Proactive defense thread started.")

    # Start Sysmon log monitor
    sysmon_thread = threading.Thread(target=monitor_sysmon_log)
    sysmon_thread.start()
    MAIN_LOGGER.logger.info("Sysmon log monitor thread started.")
     # Start Process Monitor
    process_monitor_thread = threading.Thread(
        target=parent_spoof_detector.continuous_monitor,
        args=(process_alert_callback,),  
        daemon=True
    )
    process_monitor_thread.start()
    MAIN_LOGGER.logger.info("Process spoof detecte thread started.")
    # Keep main thread alive
    print("Entering main loop to keep script alive.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        MAIN_LOGGER.logger.info("Monitor stopped by user.")
    except Exception as e:
        MAIN_LOGGER.logger.critical(f"Main function crashed: {e}", exc_info=True)


if __name__ == "__main__":
    main()