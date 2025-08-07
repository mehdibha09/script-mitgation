from .handlers import (
    detect_processus_suspect,
    detect_event_id_11,
    mitigation_event_id_3,
    detect_pipe_lateral,
    detect_registre,
)
from .monitor import monitor_sysmon_log
from .utils import  analyser_event_xml, get_event_record_id