
import os
import psutil
from logger import MAIN_LOGGER
from utils.common import kill_process_tree, est_legitime, sauvegarder_binaire_suspect, est_ip_locale, reconstruire_url_depuis_event,est_commande_suspecte

from utils.constants import (
    SMB_PORTS,
    LATERAL_TOOLS)


def detect_smb_propagation(event_data):
    """Detect SMB propagation attempts (Sysmon Event ID 3)."""
    try:
        image = os.path.basename(event_data.get("Image", "")).lower()
        cmd = event_data.get("CommandLine") or ""
        dport = int(event_data.get("DestinationPort", 0))
        dip = event_data.get("DestinationIp", "")
        pid = event_data.get("ProcessId")
    except (ValueError, TypeError):
        return False
    if dport in SMB_PORTS and (image in LATERAL_TOOLS or est_commande_suspecte(cmd)):
        MAIN_LOGGER.logger.warning(f"[*] Suspicious SMB connection: {image} PID={pid} to {dip}:{dport}")
        if pid and pid.isdigit():
            try:
                proc = psutil.Process(int(pid))
                if not est_legitime(proc):
                    kill_process_tree(int(pid), kill_parent=True)
            except Exception as e:
                pass
                #MAIN_LOGGER.logger.error(f"[!] Error handling PID {pid}: {e}")
        return True
    return False


def mitiger_connexion_reseau(event_data):
    """
    Analyse un événement Sysmon NetworkConnect et tue le processus
    s'il fait une connexion suspecte, ou si l'URL/commande contient des mots suspects.
    """
    try:
        proc_name = (event_data.get("Image") or "").lower()
        pid = int(event_data.get("ProcessId", 0))
        dest_ip = event_data.get("DestinationIp", "")
        dest_port = int(event_data.get("DestinationPort", 0))
        command_line = (event_data.get("CommandLine") or "").lower()
        url = (event_data.get("Url") or "").lower()  # Si Sysmon capture cet attribut
    except Exception as e:
        MAIN_LOGGER.logger.error(f"Erreur d'extraction dans event_data : {e}")
        return False
    url = reconstruire_url_depuis_event(event_data)


def detect_keylogger_activity(event_data):
    """
    Détecte une activité suspecte pouvant indiquer un keylogger.
    Critères :
    - Processus courant de type script/exécution interactive
    - Connexion réseau vers IP publique (externe)
    - Ports utilisés typiquement pour exfiltration : 9999, 44444
    - Payload contenant des données indicatives de keylogging
    """

    try:
        image = (event_data.get("Image") or "").lower()
        pid = int(event_data.get("ProcessId", 0))
        dest_ip = event_data.get("DestinationIp", "")
        dest_port = int(event_data.get("DestinationPort", 0))
        payload = event_data.get("Payload", "") or ""
        if dest_port == 443:
            return False
        chemin_exec = image
        nom_processus = os.path.basename(image)

        processus_suspects = [
            "powershell.exe", "cmd.exe", "python.exe", "pythonw.exe",
            "wscript.exe", "cscript.exe", "mshta.exe", "node.exe","python 3.11"
        ]
        ports_suspects = [9999, 44444]

        est_connexion_externe = dest_ip and not est_ip_locale(dest_ip)
        est_port_suspect = dest_port in ports_suspects
        est_processus_douteux = nom_processus in processus_suspects

        if est_processus_douteux or est_connexion_externe or est_port_suspect:
            MAIN_LOGGER.logger.warning(
                f"[⚠️] Connexion suspecte détectée : {nom_processus} -> {dest_ip}:{dest_port}"
            )
            try:
                    proc = psutil.Process(pid)
                    sauvegarder_binaire_suspect(chemin_exec)
                    kill_process_tree(pid, kill_parent=True)
                    MAIN_LOGGER.logger.warning(f"[🔥] Processus keylogger stoppé (PID {pid})")
                    return True
            except Exception as e:
                    MAIN_LOGGER.logger.error(f"[!] Échec arrêt processus keylogger : {e}")
        return False

    except Exception as e:
        MAIN_LOGGER.logger.error(f"[!] Erreur dans detect_keylogger_activity : {e}")
        return False