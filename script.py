import time
import re
import xml.etree.ElementTree as ET
from datetime import datetime
import psutil
import winreg
import os
import traceback
import ctypes
from ctypes import windll, wintypes, byref, create_unicode_buffer
import time
import xml.etree.ElementTree as ET
import traceback

# Constantes Winevt
EVT_QUERY_CHANNEL_PATH = 0x1
EVT_RENDER_EVENT_XML = 1
ERROR_NO_MORE_ITEMS = 259

# Chargement de l'API Winevt.dll
wevtapi = windll.wevtapi

# Définition des fonctions
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

LOG_FILE = "registre_suspect.log"

# -------------------- Config --------------------

PROCESSUS_LEGITIMES = {
    "services.exe", "svchost.exe", "explorer.exe", "wininit.exe",
    "lsass.exe", "csrss.exe", "smss.exe", "winlogon.exe", "taskhostw.exe",
    "spoolsv.exe", "system"
}

UTILISATEURS_SYSTEME = {
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service",
    "trustedinstaller",
    "system"
}

# -------------------- Logging --------------------

def log(msg: str):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"
    line = f"{ts} {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

# -------------------- Helpers --------------------

def est_legitime(proc: psutil.Process) -> bool:
    try:
        name = proc.name().lower()
        user = proc.username().lower()
        exe  = (proc.exe() or "").lower()
    except psutil.Error:
        return True

    if name in PROCESSUS_LEGITIMES and \
       (exe.startswith(r"c:\\windows\\system32") or exe.startswith(r"c:\\windows\\syswow64")) and \
       user in UTILISATEURS_SYSTEME:
        return True
    return False

def kill_process_tree(pid: int, kill_parent: bool = True):
    try:
        parent = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return

    if kill_parent:
        try:
            ppid = parent.ppid()
            if ppid and ppid != 0:
                p = psutil.Process(ppid)
                if not est_legitime(p):
                    log(f"[🔪] Kill parent PID {ppid} ({p.name()})")
                    p.kill()
        except psutil.Error:
            pass

    try:
        children = parent.children(recursive=True)
        for c in children:
            try:
                c.kill()
            except Exception:
                pass
        psutil.wait_procs(children, timeout=3)
    except Exception:
        pass

    try:
        if not est_legitime(parent):
            parent.kill()
    except Exception:
        pass

def is_python_cmd_suspicious(cmd: str) -> bool:
    if not cmd:
        return False
    cmd = cmd.lower()

    red_flags = [
        r"-c\s+.+",
        r"-m\s+base64",
        r"frombase64string",
        r"\bexec\(",
        r"importlib\.import_module",
        r"subprocess\.popen",
        r"powershell",
        r"rundll32", r"regsvr32",
        r"--encodedcommand", r"-enc",
    ]
    for pat in red_flags:
        if re.search(pat, cmd):
            return True

    suspicious_dirs = [
        r"\\appdata\\local\\temp\\",
        r"\\appdata\\roaming\\",
        r"\\programdata\\",
        r"\\public\\",
        r"\\users\\[^\\]+\\downloads\\",
    ]
    for d in suspicious_dirs:
        if re.search(d, cmd) and ".py" in cmd:
            return True

    if len(cmd) > 4000:
        return True

    return False

def est_commande_suspecte(commandline: str) -> bool:
    if not commandline:
        return False
    cl = commandline.lower()

    motifs_suspects = [
        r"encodedcommand", r"-enc", r"base64",
        r"invoke-expression", r"\biex\b",
        r"downloadstring", r"invoke-webrequest", r"start-bitstransfer",
        r"new-object", r"start-process",
        r"bypass", r"-nop", r"hidden",
        r"certutil", r"curl", r"wget", r"bitsadmin",
        r"\.js\b", r"\.vbs\b", r"\.bat\b", r"\.ps1\b",
        r"schtasks", r"reg add", r"regsvr32", r"rundll32"
    ]

    for motif in motifs_suspects:
        if re.search(motif, cl):
            return True
    return False

# -------------------- Détections --------------------

def detect_chiffrement(event_data):
    fichier = (event_data.get("TargetFilename") or "").lower()
    if fichier.endswith((".locked", ".enc", ".crypt", ".encrypted")):
        log(f"[🧨] Fichier chiffré détecté : {fichier}")
        pid_str = event_data.get("ProcessId")
        if pid_str and pid_str.isdigit():
            kill_process_tree(int(pid_str), kill_parent=True)

def _open_reg_key(hive, path, rights):
    for flag in (0, winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        try:
            return winreg.OpenKey(hive, path, 0, rights | flag)
        except OSError:
            continue
    raise

def detect_registre(event_data):
    cle = (event_data.get("TargetObject") or "").lower()
    valeur = (event_data.get("Details") or "").lower()
    event_type = (event_data.get("EventType") or "").lower()
    pid_str = event_data.get("ProcessId")

    cles_suspectes = [
        r"\\run", r"\\runonce", r"\\image file execution options",
        r"\\winlogon", r"\\shell", r"\\services", r"\\appinit_dlls", r"\\policies\\system"
    ]

    commandes_suspectes = [
        "powershell", "cmd.exe", "wscript", "regsvr32",
        ".vbs", ".js", ".bat", ".ps1", "frombase64string", "-enc", "iex"
    ]

    if not any(re.search(cle_suspecte, cle) for cle_suspecte in cles_suspectes):
        return

    log(f"Clé registre critique modifiée : {cle}")

    if not any(cmd in valeur for cmd in commandes_suspectes):
        return

    log(f"[⚠️] Valeur suspecte détectée : {valeur}")

    try:
        parts = cle.split("\\")
        hive_name = parts[0].upper()
        sous_cle = "\\".join(parts[1:-1])
        nom_valeur = parts[-1]

        hive = {
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKCU": winreg.HKEY_CURRENT_USER,
        }.get(hive_name, None)

        if hive:
            if event_type == "setvalue":
                with _open_reg_key(hive, sous_cle, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, nom_valeur)
                    log(f"[✔] Valeur supprimée du registre : {nom_valeur}")
            elif event_type == "createkey":
                parent_path = "\\".join(parts[1:-1])
                with _open_reg_key(hive, parent_path, winreg.KEY_ALL_ACCESS) as parent_key:
                    winreg.DeleteKey(parent_key, nom_valeur)
                    log(f"[✔] Clé supprimée : {cle}")
        else:
            log(f"[!] Hive non reconnu : {hive_name}")

    except Exception as e:
        log(f"[!] Erreur suppression registre : {e}")

    if pid_str and pid_str.isdigit():
        pid = int(pid_str)
        try:
            proc = psutil.Process(pid)
            if not est_legitime(proc):
                log(f"[🔪] Processus suspect tué : {proc.name()} (PID: {pid})")
                proc.kill()
        except Exception as e:
            log(f"[!] Impossible d'accéder au processus {pid} : {e}")

def analyser_event_xml(event_xml: str):
    """Analyse un événement Sysmon au format XML et renvoie (event_id, dict_event_data)"""
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
        # utilise ta fonction log si dispo
        print(f"[!] Erreur parsing XML: {e}")
        return None, None

def monitor_sysmon_log():
    channel = "Microsoft-Windows-Sysmon/Operational"
    query = "*"

    query_handle = EvtQuery(None, channel, query, EVT_QUERY_CHANNEL_PATH)
    if not query_handle:
        err = ctypes.GetLastError()
        raise RuntimeError(f"Impossible d'ouvrir le journal Sysmon (code {err})")

    print("[*] Début de la surveillance Sysmon (Winevt API)…")

    event_handles = (wintypes.HANDLE * 10)()
    returned = wintypes.DWORD()

    while True:
        success = EvtNext(query_handle, 10, event_handles, 1000, 0, byref(returned))

        if not success:
            if ctypes.GetLastError() == ERROR_NO_MORE_ITEMS:
                time.sleep(1)
                continue
            else:
                print(f"[!] EvtNext error: {ctypes.GetLastError()}")
                time.sleep(2)
                continue

        for i in range(returned.value):
            try:
                xml_event = render_event(event_handles[i])
                if not xml_event or "<Event" not in xml_event:
                    continue

                event_id, event_data = analyser_event_xml(xml_event)
                if not event_id:
                    continue

                print(f"[*] Event {event_id} reçu")
                if event_id == 11:
                    detect_chiffrement(event_data)
                elif event_id in (12, 13, 14):
                    detect_registre(event_data)
                elif event_id == 1:
                    detect_processus_suspect(event_data)

            except Exception:
                print("Exception:\n" + traceback.format_exc())
            finally:
                EvtClose(event_handles[i])

        time.sleep(0.2)


def render_event(event_handle):
    buffer_size = wintypes.DWORD(0)
    buffer_used = wintypes.DWORD(0)
    property_count = wintypes.DWORD(0)

    # Premier appel pour obtenir la taille nécessaire
    EvtRender(None, event_handle, EVT_RENDER_EVENT_XML,
              0, None, byref(buffer_used), byref(property_count))

    buf = create_unicode_buffer(buffer_used.value)
    if not EvtRender(None, event_handle, EVT_RENDER_EVENT_XML,
                     buffer_used, buf, byref(buffer_used), byref(property_count)):
        raise RuntimeError(f"EvtRender failed: {ctypes.GetLastError()}")

    return buf.value

if __name__ == "__main__":
    monitor_sysmon_log()
