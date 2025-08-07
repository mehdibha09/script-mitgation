
#que fait import 
from logger import MAIN_LOGGER
import xml.etree.ElementTree as ET


def analyser_event_xml(event_xml):
    """Parse Sysmon XML event."""
    try:
        root = ET.fromstring(event_xml)
        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        event_id_el = root.find('./e:System/e:EventID', ns)
        if event_id_el is None or not event_id_el.text:
            return None, None
        event_id = int(event_id_el.text)
        data_elements = root.findall('.//e:EventData/e:Data', ns)
        event_data = {elem.attrib.get('Name'): (elem.text or "") for elem in data_elements}
        return event_id, event_data
    except Exception as e:
        MAIN_LOGGER.logger.error(f"[!] XML parsing error: {e}")
        return None, None

def get_event_record_id(xml_event):
    """Extract EventRecordID from XML."""
    try:
        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'} 
        root = ET.fromstring(xml_event)
        erid_elem = root.find('./e:System/e:EventRecordID', ns)
        if erid_elem is not None:
            return int(erid_elem.text)
    except:
        pass
    return 0