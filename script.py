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
        log(f"[DEBUG] Vérification légitimité : name={name}, user={user}, exe={exe}")
    except psutil.Error:
        return True

    if name in PROCESSUS_LEGITIMES and \
       (exe.startswith(r"c:\\windows\\system32") or exe.startswith(r"c:\\windows\\syswow64")) and \
       user in UTILISATEURS_SYSTEME:
        log(f"[DEBUG] Processus {name} considéré légitime")
        return True
    log(f"[DEBUG] Processus {name} considéré NON légitime")
    return False


import subprocess

def kill_process_tree(pid: int, kill_parent: bool = True):
    try:
        parent = psutil.Process(pid)
        log(f"[INFO] kill_process_tree appelé pour PID {pid} ({parent.name()})")
    except psutil.NoSuchProcess:
        log(f"[WARN] Processus PID {pid} non trouvé")
        return

    try:
        # Kill l'arbre du PID directement avec /F (force) et /T (tous les enfants)
        subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"], capture_output=True)
        log(f"[🔪] Force kill PID {pid} et son arbre")
    except Exception as e:
        log(f"[ERROR] Erreur taskkill PID {pid} : {e}")

    # Kill le parent si demandé
    if kill_parent:
        try:
            ppid = parent.ppid()
            if ppid and ppid != 0:
                try:
                    subprocess.run(["taskkill", "/PID", str(ppid), "/F", "/T"], capture_output=True)
                    log(f"[🔪] Force kill parent PID {ppid}")
                except Exception as e:
                    log(f"[ERROR] Erreur taskkill parent PID {ppid} : {e}")
        except psutil.Error as e:
            log(f"[ERROR] Erreur obtention parent PID {pid} : {e}")

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

def detect_processus_suspect(event_data):
    import os
    
    print("DEBUG event_data keys:", list(event_data.keys()))

    nom_processus = os.path.basename(event_data.get("Image", "")).lower()
    ligne_commande = (event_data.get("CommandLine") or "").lower()
    pid_str = event_data.get("ProcessId")

    parent_image = os.path.basename(event_data.get("ParentImage", "")).lower()
    parent_cmd = (event_data.get("ParentCommandLine") or "").lower()
    parent_user = (event_data.get("ParentUser") or "").lower()

    print(f"DEBUG Nom processus: {nom_processus}")
    print(f"DEBUG CommandLine: {ligne_commande}")
    print(f"DEBUG Parent image: {parent_image}")
    print(f"DEBUG Parent CommandLine: {parent_cmd}")
    print(f"DEBUG Parent User: {parent_user}")

    processus_suspects = [
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "regsvr32.exe", "rundll32.exe",
        "taskschd.msc", "schtasks.exe", "certutil.exe", "curl.exe",
        "python.exe", "pythonw.exe", "python3.exe", "python3.11.exe"
    ]

    ransomware_keywords = [
        "watchdog.vbs",
        ".vbs",
        "themes",
        "ransomware",
        ".locked",
        "encoder.py",
        "script-mitgation"
    ]

    suspicious = False

    if nom_processus in processus_suspects:
        suspicious = True

    if any(keyword in ligne_commande for keyword in ransomware_keywords):
        suspicious = True

    if any(keyword in parent_cmd for keyword in ransomware_keywords):
        suspicious = True

    if "wscript.exe" == nom_processus and "python" in parent_image:
        suspicious = True

    if not suspicious:
        print("DEBUG Pas suspect")
        return False

    print(f"[⚠️] Processus suspect détecté (ID 1): {nom_processus}")
    print(f"      CommandLine : {ligne_commande}")
    print(f"      Parent : {parent_image} ({parent_user}) -> {parent_cmd}")

    if pid_str and pid_str.isdigit():
        pid = int(pid_str)
        try:
            print(f"[🔪] Kill tree PID={pid} (fonction kill_process_tree non implémentée ici)")
            # kill_process_tree(pid, kill_parent=True)  # Implémenter selon besoin
        except Exception as e:
            print(f"[!] Échec du kill du processus {pid} : {e}")
    return True





# -------------------- Détections --------------------

def detect_chiffrement(event_data):
    fichier = (event_data.get("TargetFilename") or "").lower().strip()
    log(f"[DEBUG] Fichier cible détecté : '{fichier}'")
    if fichier.endswith((".locked", ".enc", ".crypt", ".encrypted")):
        log(f"[🧨] Fichier chiffré détecté : {fichier}")
        pid_str = event_data.get("ProcessId")
        log(f"[DEBUG] ProcessId détecté : {pid_str}")
        if pid_str and pid_str.isdigit():
            kill_process_tree(int(pid_str), kill_parent=True)
        else:
            log("[WARN] ProcessId invalide ou manquant")

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
def get_event_record_id(xml_event):
    """
    Extrait EventRecordID depuis le XML de l'événement.
    """
    import xml.etree.ElementTree as ET
    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    root = ET.fromstring(xml_event)
    erid_elem = root.find('./e:System/e:EventRecordID', ns)
    if erid_elem is not None:
        try:
            return int(erid_elem.text)
        except:
            pass
    return 0


def monitor_sysmon_log():
    channel = "Microsoft-Windows-Sysmon/Operational"
    last_event_id = 0  # ID du dernier événement lu

    print("[*] Début de la surveillance Sysmon (Winevt API)…")

    while True:
        # Requête filtrée pour ne prendre que les événements nouveaux
        query = f"*[System[EventRecordID > {last_event_id}]]"

        query_handle = EvtQuery(None, channel, query, EVT_QUERY_CHANNEL_PATH)
        if not query_handle:
            err = ctypes.GetLastError()
            print(f"[!] Impossible d'ouvrir le journal Sysmon (code {err}), nouvelle tentative dans 2s")
            time.sleep(2)
            continue

        event_handles = (wintypes.HANDLE * 10)()
        returned = wintypes.DWORD()

        while True:
            success = EvtNext(query_handle, 10, event_handles, 1000, 0, byref(returned))

            if not success:
                if ctypes.GetLastError() == ERROR_NO_MORE_ITEMS:
                    break  # Plus d'événements, on refait une nouvelle requête filtrée
                else:
                    print(f"[!] EvtNext error: {ctypes.GetLastError()}")
                    break

            for i in range(returned.value):
                try:
                    xml_event = render_event(event_handles[i])
                    if not xml_event or "<Event" not in xml_event:
                        continue

                    event_id, event_data = analyser_event_xml(xml_event)
                    if not event_id or event_id == 255:
                        continue

                    event_record_id = get_event_record_id(xml_event)
                    if event_record_id > last_event_id:
                        last_event_id = event_record_id

                    #if event_id == 1:
                     #   detect_processus_suspect(event_data)
                    if event_id == 11:
                         detect_chiffrement(event_data)
                # elif event_id in (12, 13, 14):
                #     detect_registre(event_data)
                    print(event_id)

                except Exception:
                    print("Exception:\n" + traceback.format_exc())
                finally:
                    EvtClose(event_handles[i])

        EvtClose(query_handle)
        time.sleep(1)


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
