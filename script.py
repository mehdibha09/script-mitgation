import time
import win32evtlog
import xml.etree.ElementTree as ET
import psutil
import re
import winreg
from datetime import datetime

LOG_FILE = "registre_suspect.log"

def kill_processus(pid):
    try:
        proc = psutil.Process(pid)
        proc.kill()        
        print(f"processuce avec {pid} et tue en force")
    except psutil.NoSuchProcess:
        print(f" Processus {pid} introuvable.")
    except Exception as e:
        print(f"Échec de l'arrêt du processus {pid} : {e}")

def detect_chiffrement(event_data):
    """Détection simple : fichier renommé avec extension .locked, .enc, etc."""
    fichier = event_data.get("TargetFilename", "").lower()
    if fichier.endswith((".locked", ".enc", ".crypt", ".encrypted")):
        print(f"Fichier chiffré détecté : {fichier}")
        pid= event_data.get("ProcessId")  # PID dans Sysmon
        if pid and pid.isdigit():
            pid = int(pid)
        kill_processus(pid)




def detect_registre(event_data):
    cle = event_data.get("TargetObject", "").lower()
    valeur = event_data.get("Details", "").lower()
    event_type = event_data.get("EventType", "").lower()  # ex: SetValue, CreateKey, etc.
    pid_str = event_data.get("ProcessId")

    cles_suspectes = [
        r"\\run", r"\\runonce", r"\\image file execution options",
        r"\\winlogon", r"\\shell", r"\\services", r"\\appinit_dlls", r"\\policies\\system"
    ]

    processus_legitimes = [
        "services.exe", "svchost.exe", "explorer.exe", "wininit.exe",
        "lsass.exe", "csrss.exe", "smss.exe", "winlogon.exe", "taskhostw.exe",
        "spoolsv.exe", "system"
    ]

    commandes_suspectes = [
        "powershell", "cmd.exe", "wscript", "regsvr32",
        ".vbs", ".js", ".bat", ".ps1", "frombase64string", "-enc", "iex"
    ]

    if any(re.search(cle_suspecte, cle) for cle_suspecte in cles_suspectes):
        print(f"Clé registre critique modifiée : {cle}")

        # Si valeur suspecte détectée
        if any(cmd in valeur for cmd in commandes_suspectes):
            print(f"[⚠️] Valeur suspecte détectée : {valeur}")

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
                        # ➤ Suppression de la valeur
                        with winreg.OpenKey(hive, sous_cle, 0, winreg.KEY_SET_VALUE) as key:
                            winreg.DeleteValue(key, nom_valeur)
                            print(f" Valeur supprimée du registre : {nom_valeur}")
                    elif event_type == "createkey":
                        # ➤ Suppression de la clé entière
                        with winreg.OpenKey(hive, sous_cle, 0, winreg.KEY_ALL_ACCESS) as parent_key:
                            winreg.DeleteKey(parent_key, nom_valeur)
                            print(f"Clé supprimée : {cle}")
                else:
                    print(f"Hive non reconnu : {hive_name}")

            except Exception as e:
                print(f"Erreur suppression registre : {e}")

            # ➤ Kill du processus
            if pid_str and pid_str.isdigit():
                pid = int(pid_str)
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name().lower()
                    exe_path = proc.exe().lower()
                    user = proc.username().lower()
                    
                    if proc_name in processus_legitimes and \
                        (exe_path.startswith(r"c:\\windows\\system32") or exe_path.startswith(r"c:\\windows\\syswow64")) and \
                        user in ["nt authority\\system", "nt authority\\local service", "nt authority\\network service"]:
                        print("Processus système légitime détecté, aucune action.")
                    else:
                        print(f"Processus suspect tué : {proc_name} (PID: {pid})")
                        proc.kill()
                except Exception as e:
                    print(f"Impossible d'accéder au processus {pid} : {e}")


def est_commande_suspecte(commandline):
    """Analyse la ligne de commande pour détecter des motifs malveillants."""
    if not commandline:
        return False

    commandline = commandline.lower()
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
        if re.search(motif, commandline):
            return True
    return False

def detect_processus_suspect(event_data):
    nom_processus = event_data.get("Image", "").lower()
    ligne_commande = event_data.get("CommandLine", "").lower()
    pid_str = event_data.get("ProcessId")

    processus_suspects = [
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "regsvr32.exe", "rundll32.exe",
        "taskschd.msc", "schtasks.exe", "certutil.exe", "curl.exe"
    ]

    if any(p in nom_processus for p in processus_suspects):
        suspicious = False

        if "powershell.exe" in nom_processus or "cmd.exe" in nom_processus:
            if est_commande_suspecte(ligne_commande):
                suspicious = True
        else:
            suspicious = True  # autres processus suspects par défaut

        if suspicious:
            print(f"Processus suspect détecté : {nom_processus}")
            print(f"  Ligne de commande : {ligne_commande}")

            if pid_str and pid_str.isdigit():
                pid = int(pid_str)
                try:
                    proc = psutil.Process(pid)
                    user = proc.username().lower()
                    utilisateurs_autorises = [
                        "nt authority\\system", "system", "trustedinstaller"
                    ]
                    if any(u in user for u in utilisateurs_autorises):
                        print(f"Processus légitime exécuté par : {user}. Pas de kill.")
                    else:
                        print(f"[🔪] Kill de : {proc.name()} (PID {pid}) exécuté par {user}")
                        proc.kill()
                except Exception as e:
                    print(f"Échec du kill du processus {pid} : {e}")
            return True
    return False


def analyser_event_xml(event_xml):
    """Analyse un événement Sysmon au format XML"""
    try:
        root = ET.fromstring(event_xml)
        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        event_id = int(root.find('./e:System/e:EventID', ns).text)
        data_elements = root.findall('.//e:EventData/e:Data', ns)

        event_data = {elem.attrib.get('Name'): elem.text for elem in data_elements}
        return event_id, event_data
    except Exception as e:
        print(f"Erreur parsing XML: {e}")
        return None, None


def monitor_sysmon_log():
    server = 'localhost'
    # path log de sysmon dans event viewer
    log_type = 'Microsoft-Windows-Sysmon/Operational'
    hand = win32evtlog.OpenEventLog(server, log_type)
    # comment lire le log 
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    #le numero dernier line de log 
    last_record = 0
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0) # prend list des evenement 
        if events:
            for event in reversed(events):  # dans l'ordre chronologique
                if event.RecordNumber <= last_record:
                    continue

                last_record = event.RecordNumber
                if event.EventID != 0:
                    event_id, event_data = analyser_event_xml(event.StringInserts[-1])
                    if not event_id:
                        continue

                    #Lancer les fonctions en fonction du type d'événement
                    if event_id == 11:  # FileCreate
                        detect_chiffrement(event_data)
                    elif event_id == 13:  # Registry modification
                        detect_registre(event_data)
                    elif event_id == 1:   # ProcessCreate
                        detect_processus_suspect(event_data)

        time.sleep(2)  # attendre avant de lire de nouveaux logs