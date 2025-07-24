import time
import re
import xml.etree.ElementTree as ET
from datetime import datetime
import psutil
import win32evtlog
import winreg
import os
import traceback

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
    """Heuristique simple pour éviter de tuer des processus système légitimes."""
    try:
        name = proc.name().lower()
        user = proc.username().lower()
        exe  = (proc.exe() or "").lower()
    except psutil.Error:
        # Si on ne peut pas accéder, on ne tue pas (principe de précaution)
        return True

    if name in PROCESSUS_LEGITIMES and \
       (exe.startswith(r"c:\windows\system32") or exe.startswith(r"c:\windows\syswow64")) and \
       user in UTILISATEURS_SYSTEME:
        return True
    return False

def kill_process_tree(pid: int, kill_parent: bool = True):
    try:
        parent = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return

    # Optionnel : tuer le parent SI suspect
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

    # Tuer les enfants
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

    # Tuer le parent
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
        r"-c\s+.+",                      # python -c "...."
        r"-m\s+base64",                  # python -m base64 ...
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
        if re.search(patron := motif, cl):
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
    """
    Ouvre une clé registre avec fallback 32/64 bits.
    """
    for flag in (0, winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        try:
            return winreg.OpenKey(hive, path, 0, rights | flag)
        except OSError:
            continue
    raise

def detect_registre(event_data):
    cle = (event_data.get("TargetObject") or "").lower()
    valeur = (event_data.get("Details") or "").lower()
    event_type = (event_data.get("EventType") or "").lower()  # ex: SetValue, CreateKey, ...
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
        # Si la valeur n'a pas l'air louche, on log seulement
        return

    log(f"[⚠️] Valeur suspecte détectée : {valeur}")

    # Tentative de rollback
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

    # Kill du process
    if pid_str and pid_str.isdigit():
        pid = int(pid_str)
        try:
            proc = psutil.Process(pid)
            if not est_legitime(proc):
                log(f"[🔪] Processus suspect tué : {proc.name()} (PID: {pid})")
                proc.kill()
        except Exception as e:
            log(f"[!] Impossible d'accéder au processus {pid} : {e}")

def detect_processus_suspect(event_data):
    nom_processus = (event_data.get("Image") or "").lower()
    ligne_commande = (event_data.get("CommandLine") or "").lower()
    pid_str = event_data.get("ProcessId")

    processus_suspects = [
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "regsvr32.exe", "rundll32.exe",
        "taskschd.msc", "schtasks.exe", "certutil.exe", "curl.exe",
        "python.exe", "pythonw.exe"
    ]

    if not any(p in nom_processus for p in processus_suspects):
        return False

    suspicious = False

    if "python.exe" in nom_processus or "pythonw.exe" in nom_processus:
        if is_python_cmd_suspicious(ligne_commande):
            suspicious = True
    else:
        if "powershell.exe" in nom_processus or "cmd.exe" in nom_processus:
            if est_commande_suspecte(ligne_commande):
                suspicious = True
        else:
            suspicious = True

    if not suspicious:
        return False

    log(f"[⚠️] Processus suspect détecté : {nom_processus}")
    log(f"      Ligne de commande : {ligne_commande}")

    if pid_str and pid_str.isdigit():
        pid = int(pid_str)
        try:
            log(f"[🔪] Kill tree PID={pid}")
            kill_process_tree(pid, kill_parent=True)
        except Exception as e:
            log(f"[!] Échec du kill du processus {pid} : {e}")
    return True

# -------------------- Sysmon parsing --------------------

def analyser_event_xml(event_xml):
    """Analyse un événement Sysmon au format XML"""
    try:
        root = ET.fromstring(event_xml)
        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        event_id = int(root.find('./e:System/e:EventID', ns).text)
        data_elements = root.findall('.//e:EventData/e:Data', ns)

        event_data = {elem.attrib.get('Name'): (elem.text or "") for elem in data_elements}
        return event_id, event_data
    except Exception as e:
        log(f"[!] Erreur parsing XML: {e}")
        return None, None

# -------------------- Main loop --------------------

def monitor_sysmon_log():
    """
    NOTE : win32evtlog.OpenEventLog() n'est pas officiellement supporté
    pour 'Microsoft-Windows-Sysmon/Operational'. Préfère winevt (EvtQuery/EvtSubscribe).
    Ici on garde ton approche et on la protège autant que possible.
    """
    server = 'localhost'
    log_type = 'Microsoft-Windows-Sysmon/Operational'

    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
    except Exception as e:
        log(f"[FATAL] Impossible d'ouvrir le journal Sysmon avec win32evtlog: {e}")
        return

    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    last_record = 0

    log("[*] Début de la surveillance Sysmon…")

    while True:
        try:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
        except Exception as e:
            log(f"[!] ReadEventLog error: {e}")
            time.sleep(2)
            continue

        if not events:
            time.sleep(2)
            continue

        for event in events:
            try:
                if event.RecordNumber <= last_record:
                    continue
                last_record = event.RecordNumber

                # Sur certains environnements, l'XML est dans event.StringInserts[-1], mais ce n'est pas garanti
                if not event.StringInserts:
                    continue

                xml_blob = event.StringInserts[-1]
                if not xml_blob or "<Event " not in xml_blob:
                    # Pas un XML complet -> skip
                    continue

                event_id, event_data = analyser_event_xml(xml_blob)
                if not event_id:
                    continue

                # Route
                if event_id == 11:      # FileCreate
                    detect_chiffrement(event_data)
                elif event_id == 13:    # Registry value set
                    detect_registre(event_data)
                elif event_id == 12:    # Registry key create
                    detect_registre(event_data)
                elif event_id == 14:    # Registry key rename
                    detect_registre(event_data)
                elif event_id == 1:     # ProcessCreate
                    detect_processus_suspect(event_data)
                # autre id 

            except Exception:
                log("Exception dans le traitement d'un événement :\n" + traceback.format_exc())

        # petite pause
        time.sleep(1)

if __name__ == "__main__":
    monitor_sysmon_log()
