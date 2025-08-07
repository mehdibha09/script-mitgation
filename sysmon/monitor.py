from logger import MAIN_LOGGER
from ctypes import byref, wintypes
import ctypes
import time
from ctypes import wintypes, create_unicode_buffer, windll
import traceback
from sysmon.handlers import (
    detect_processus_suspect,
    detect_event_id_11,
    mitigation_event_id_3,
    detect_pipe_lateral,
    detect_registre
)
from sysmon.utils import analyser_event_xml, get_event_record_id
from defense.registry_blocker import check_and_remove_registry_persistence
from defense.screenshot_blocker import detect_screenshot_activity


from utils.constants import (
    REGISTRY_BLOCKER_ENABLED,
    SCREENSHOT_BLOCKER_ENABLED,
    EVT_QUERY_CHANNEL_PATH,
    EVT_RENDER_EVENT_XML,
    ERROR_NO_MORE_ITEMS,
    )



wevtapi = windll.wevtapi


# Define the function prototypes
EvtQuery = wevtapi.EvtQuery
EvtQuery.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
EvtQuery.restype = wintypes.HANDLE

EvtNext = wevtapi.EvtNext
EvtNext.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
                    wintypes.DWORD, wintypes.DWORD, wintypes.PDWORD]
EvtNext.restype = wintypes.BOOL

EvtRender = wevtapi.EvtRender
EvtRender.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD,
                      wintypes.DWORD, wintypes.LPWSTR, wintypes.PDWORD,
                      wintypes.PDWORD]
EvtRender.restype = wintypes.BOOL

EvtClose = wevtapi.EvtClose
EvtClose.argtypes = [wintypes.HANDLE]
EvtClose.restype = wintypes.BOOL

def render_event(event_handle):
    """Render event to XML string."""
    buffer_size = wintypes.DWORD(0)
    buffer_used = wintypes.DWORD(0)
    property_count = wintypes.DWORD(0)
    
    # First call to get required buffer size
    if not EvtRender(None, event_handle, EVT_RENDER_EVENT_XML, 0, None, byref(buffer_used), byref(property_count)):
        error = ctypes.GetLastError()
        if error != 122:  # ERROR_INSUFFICIENT_BUFFER
            MAIN_LOGGER.logger.error(f"EvtRender failed with error: {error}")
            return None
    
    # Create buffer and render the event
    buf = create_unicode_buffer(buffer_used.value)
    if not EvtRender(None, event_handle, EVT_RENDER_EVENT_XML, buffer_used, buf, byref(buffer_used), byref(property_count)):
        MAIN_LOGGER.logger.error(f"EvtRender failed with error: {ctypes.GetLastError()}")
        return None
    
    return buf.value    


def monitor_sysmon_log():
    """Main Sysmon monitoring loop."""
    channel = "Microsoft-Windows-Sysmon/Operational"
    last_event_id = 0
    MAIN_LOGGER.logger.info("[*] Starting Sysmon monitoring (Winevt API)...")

    event_id_query = "*[System[( EventID-1 or EventID=3 or EventID=11 or EventID=12 or EventID=13 or EventID=14 or EventID=17 or EventID=18)]]"

    try:
        while True:
            query_string = f"{event_id_query} and *[System[EventRecordID > {last_event_id}]]"
            query_handle = EvtQuery(None, channel, query_string, EVT_QUERY_CHANNEL_PATH)

            if not query_handle:
                error_code = ctypes.GetLastError()
                MAIN_LOGGER.logger.error(f"[!] Cannot open Sysmon log '{channel}' with query '{query_string}' (code {error_code}), retrying in 2s")
                time.sleep(2)
                continue # Retry the loop

            event_handles = (wintypes.HANDLE * 100)() # Use wintypes.HANDLE as EVT_HANDLE
            returned = wintypes.DWORD() # Use wintypes.DWORD for the count

            try:
                while True:
                    success = EvtNext(query_handle, 100, event_handles, 1000, 0, byref(returned))
                    if not success:
                        error_code = ctypes.GetLastError()
                        if error_code == ERROR_NO_MORE_ITEMS:
                            break 
                        else:
                            MAIN_LOGGER.logger.error(f"[!] EvtNext failed with error code: {error_code}")
                            break

                    for i in range(returned.value):
                        try:
                            xml_event = render_event(event_handles[i])
                            if not xml_event:
                                continue

                            event_id, event_data = analyser_event_xml(xml_event)
                            if not event_id and event_id == 255:
                                continue

                            event_record_id = get_event_record_id(xml_event)
                            if event_record_id and event_record_id > last_event_id:
                                last_event_id = event_record_id
                                if event_id == 1:
                                    detect_processus_suspect(event_data)
                                elif event_id == 11:
                                    detect_event_id_11(event_data)
                                elif event_id == 3:
                                    mitigation_event_id_3(event_data)
                                elif event_id in (17, 18):
                                    detect_pipe_lateral(event_data)
                                elif event_id in (12, 13, 14):
                                    detect_registre(event_data)
                            if REGISTRY_BLOCKER_ENABLED:
                                check_and_remove_registry_persistence()

                            if SCREENSHOT_BLOCKER_ENABLED:
                                detect_screenshot_activity()
                        except KeyboardInterrupt:
                            MAIN_LOGGER.logger.info("Monitor stopped by user.")
                        except Exception as e:
                            MAIN_LOGGER.logger.critical(f"Monitoring loop crashed: {e}")
                            MAIN_LOGGER.logger.critical(traceback.format_exc())
                            
                        finally:
                            # Always close the individual event handle
                            if event_handles[i]: # Check if handle seems valid
                                EvtClose(event_handles[i])
                            

            finally:
                if query_handle:
                    EvtClose(query_handle)

            time.sleep(1)

    except KeyboardInterrupt:
        MAIN_LOGGER.logger.info("Sysmon monitoring loop interrupted by user.")
    except Exception as e:
        MAIN_LOGGER.logger.critical(f"[CRITICAL] Sysmon monitoring loop crashed unexpectedly: {e}")
        MAIN_LOGGER.logger.critical(traceback.format_exc())



    

