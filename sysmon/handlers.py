from logger import MAIN_LOGGER
import os
import re
import psutil
import winreg
from utils.common import (
    kill_process_tree, est_legitime, get_hash,
    sauvegarder_binaire_suspect, est_commande_suspecte,
    extract_urls, est_url_suspecte
)
from defense.registry_blocker import _open_reg_key

from defense.behavior_defense import (
    detect_keylogger_activity,
    detect_smb_propagation,
    mitiger_connexion_reseau
)

def detect_processus_suspect(event_data):
    """Détection des processus suspects (Sysmon Event ID 1)"""
    nom_processus = os.path.basename(event_data.get("Image", "")).lower()
    ligne_commande = event_data.get("CommandLine") or ""
    pid_str = event_data.get("ProcessId")
    parent_image = os.path.basename(event_data.get("ParentImage", "")).lower()

    processus_suspects = [
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "regsvr32.exe", "rundll32.exe", "schtasks.exe", "certutil.exe", "curl.exe",
        "python.exe", "pythonw.exe", "python3.exe", "python3.11.exe"
    ]
    ransomware_keywords = [".vbs", "ransomware", ".locked", "encoder.py"]

    # Clés spécifiques pour keylogger (à compléter si besoin)
    indicateurs_keylogger = [
        "pynput", "keyboard", "keylogger", "getasynckeystate", 
        "getforegroundwindow", "listener", "win32gui", "win32api"
    ]

    # Vérification suspicion keylogger via ligne_commande ou image
    is_keylogger = any(ind in ligne_commande.lower() for ind in indicateurs_keylogger) or \
                   any(ind in nom_processus for ind in indicateurs_keylogger)

    # Détection globale
    if (
        nom_processus in processus_suspects or
        any(kw in ligne_commande.lower() for kw in ransomware_keywords) or
        est_commande_suspecte(ligne_commande) or
        (nom_processus == "wscript.exe" and "python" in parent_image) or
        is_keylogger
    ):
        MAIN_LOGGER.logger.warning(f"[⚠️] Suspicious process detected (ID 1): {nom_processus}")
        MAIN_LOGGER.logger.info(f"      CommandLine: {ligne_commande}")

        # Kill direct si keylogger détecté
        if is_keylogger and pid_str and pid_str.isdigit():
            try:
                proc = psutil.Process(int(pid_str))
                proc.terminate()
                MAIN_LOGGER.logger.warning(f"[🚨] Keylogger process killed (PID {pid_str})")
                return
            except Exception as e:
                MAIN_LOGGER.logger.error(f"[!] Erreur kill keylogger PID {pid_str}: {e}")
                return

        # Vérifie présence d’URL malveillante dans la ligne de commande
        urls = extract_urls(ligne_commande)
        for url in urls:
            if est_url_suspecte(url):
                MAIN_LOGGER.logger.warning(f"[⚠️] URL suspecte détectée dans la ligne de commande : {url}")
                try:
                    #if analyse_code_url(url):  # Cette fonction doit être définie par toi
                        if pid_str and pid_str.isdigit():
                            kill_process_tree(int(pid_str), kill_parent=True)
                            return
                except Exception as e:
                    MAIN_LOGGER.logger.error(f"[!] Erreur pendant analyse code URL : {e}")

        # Hash et sauvegarde binaire
        image_path = event_data.get("Image", "")
        sha256 = get_hash(image_path)
        MAIN_LOGGER.logger.info(f"      SHA256 du binaire : {sha256}")
        sauvegarder_binaire_suspect(image_path)

        # Vérification et terminaison du processus si pas légitime
        if pid_str and pid_str.isdigit():
            try:
                proc = psutil.Process(int(pid_str))
                if not est_legitime(proc):
                    kill_process_tree(int(pid_str), kill_parent=True)
                else:
                    MAIN_LOGGER.logger.info(f"[INFO] Process {pid_str} is legitimate.")
            except psutil.NoSuchProcess:
                MAIN_LOGGER.logger.warning(f"[WARN] Process {pid_str} disparu avant action.")
            except psutil.AccessDenied:
                MAIN_LOGGER.logger.error(f"[ERROR] Accès refusé au processus {pid_str}.")
            except Exception as e:
                MAIN_LOGGER.logger.error(f"[!] Erreur gestion processus {pid_str}: {e}")

def detect_event_id_11(event_data):
    """Detect suspicious file creations (Sysmon Event ID 11)."""
    fichier = (event_data.get("TargetFilename") or "").lower().strip()
    pid_str = event_data.get("ProcessId")
    if fichier.endswith((".locked", ".enc", ".crypt", ".encrypted")):
        MAIN_LOGGER.logger.critical(f"[🧨] Encrypted file detected: {fichier}")
        if pid_str and pid_str.isdigit():
            try:
                proc = psutil.Process(int(pid_str))
                # No need to check legitimacy here, creating .locked files is highly suspicious
                kill_process_tree(int(pid_str), kill_parent=True)
            except psutil.NoSuchProcess:
                 MAIN_LOGGER.logger.warning(f"[WARN] Process {pid_str} (file creator) disappeared.")
            except psutil.AccessDenied:
                 pass
                 MAIN_LOGGER.logger.error(f"[ERROR] Access denied killing process {pid_str} (file creator).")
            except Exception as e:
                pass
                MAIN_LOGGER.logger.error(f"[!] Error handling PID {pid_str} (file creator): {e}")
        else:
            MAIN_LOGGER.logger.warning("[WARN] Invalid or missing ProcessId for encrypted file creation")
        return True
    if re.match(r"^\\\\[^\\]+\\(admin\$|c\$|ipc\$)\\", fichier):
        MAIN_LOGGER.logger.warning(f"[🚨] File creation on admin share: {fichier} (PID={pid_str})")
        if pid_str and pid_str.isdigit():
            try:
                proc = psutil.Process(int(pid_str))
                if not est_legitime(proc):
                    kill_process_tree(int(pid_str), kill_parent=True)
                # Consider if we should kill even if legitimate? Depends on policy.
                # For now, stick to legitimacy check.
            except psutil.NoSuchProcess:
                 MAIN_LOGGER.logger.warning(f"[WARN] Process {pid_str} (admin share creator) disappeared.")
            except psutil.AccessDenied:
                 MAIN_LOGGER.logger.error(f"[ERROR] Access denied checking process {pid_str} (admin share creator).")
            except Exception as e:
                MAIN_LOGGER.logger.error(f"[!] Error handling PID {pid_str} (admin share creator): {e}")
        return True
    return False

def mitigation_event_id_3(event_data):
    """Mitigation sur événement Sysmon ID 3 (NetworkConnect)"""
    if detect_smb_propagation(event_data):
        return
    if mitiger_connexion_reseau(event_data):
        return 
    if detect_keylogger_activity(event_data):
        return


def detect_pipe_lateral(event_data):

    """Detect lateral movement via named pipes (Sysmon Event ID 17/18)."""
    pipe = (event_data.get("PipeName") or "").lower()
    pid = event_data.get("ProcessId")

    SUSPICIOUS_PIPES = (r"\psexesvc", r"\remcom_communic", r"\paexec", r"\atsvc")
    if any(p in pipe for p in SUSPICIOUS_PIPES):
        #MAIN_LOGGER.logger.warning(f"[🚨] Suspicious named pipe: {pipe} (PID={pid})")
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

def detect_registre(event_data):
    """Detect suspicious registry modifications (Sysmon Event ID 12/13/14)."""
    cle = (event_data.get("TargetObject") or "").lower()
    valeur = (event_data.get("Details") or "").lower()
    event_type = (event_data.get("EventType") or "").lower()
    pid_str = event_data.get("ProcessId")
    image = (event_data.get("Image") or "").lower()

    cles_suspectes = [
        r"\\run", r"\\runonce", r"\\image file execution options", r"\\winlogon",
        r"\\shell", r"\\services", r"\\policies\\explorer\\run",
        r"\\software\\microsoft\\windows\\currentversion\\policies",
        r"\\software\\microsoft\\windows nt\\currentversion\\winlogon",
        r"\\wow6432node\\microsoft\\windows\\currentversion\\run"
    ]
    commandes_suspectes = [
        "powershell", "cmd.exe", "wscript", "regsvr32", ".vbs", ".js", ".bat", ".ps1",
        "frombase64string", "-enc", "iex", "b64decode", "rundll32"
    ]

    chemins_suspects = [r"\appdata\\", r"\temp\\", r"\local\\", r"\roaming\\"]

    if len(valeur) > 500:
        MAIN_LOGGER.logger.warning(f"[⚠️] Valeur très longue, probablement encodée/obfuscée : {valeur[:100]}...")

    if any(re.search(p, cle) for p in cles_suspectes) or \
       any(cmd in valeur for cmd in commandes_suspectes) or \
       any(p in valeur for p in chemins_suspects):
        
        #MAIN_LOGGER.logger.warning(f"[⚠️] Suspicious registry modification: {cle} => {valeur}")

        # Tentative suppression de la clé ou valeur
        try:
            parts = cle.split("\\")
            hive_name = parts[0].upper()
            sous_cle = "\\".join(parts[1:-1])
            nom_valeur = parts[-1]

            hive_map = {
                "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
                "HKLM": winreg.HKEY_LOCAL_MACHINE,
                "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
                "HKCU": winreg.HKEY_CURRENT_USER,
            }
            hive = hive_map.get(hive_name)

            if hive:
                if event_type == "setvalue":
                    with _open_reg_key(hive, sous_cle, winreg.KEY_SET_VALUE) as key:
                        try:
                            winreg.DeleteValue(key, nom_valeur)
                            MAIN_LOGGER.logger.info(f"[✔] Valeur registre supprimée : {nom_valeur}")
                        except FileNotFoundError:
                            pass
                        except Exception as e:
                            # Si suppression échoue, écrase avec chaîne vide
                            winreg.SetValueEx(key, nom_valeur, 0, winreg.REG_SZ, "")
                            MAIN_LOGGER.logger.warning(f"[!] Écrasé avec valeur vide : {nom_valeur}")
                elif event_type == "createkey":
                    parent_path = "\\".join(parts[1:-1])
                    with _open_reg_key(hive, parent_path, winreg.KEY_ALL_ACCESS) as parent_key:
                        winreg.DeleteKey(parent_key, nom_valeur)
                        MAIN_LOGGER.logger.info(f"[✔] Clé registre supprimée : {cle}")
            else:
                pass
                #MAIN_LOGGER.logger.error(f"[!] Hive inconnue : {hive_name}")
        except Exception as e:
            pass
           # MAIN_LOGGER.logger.error(f"[!] Erreur lors de la suppression dans le registre : {e}")

        # Kill process relié si PID fourni ou via nom image
        try:
            if pid_str and pid_str.isdigit():
                proc = psutil.Process(int(pid_str))
            elif image:
                procs = [p for p in psutil.process_iter(['pid', 'name', 'exe']) if p.info['name'].lower() in image]
                proc = procs[0] if procs else None
            else:
                proc = None

            if proc.name().lower() in {"msedge.exe", "chrome.exe", "firefox.exe"}:
                MAIN_LOGGER.logger.info(f"[ℹ️] Modification registre par navigateur ignorée : {proc.name()} (PID {proc.pid})")
                return
            if proc:
                if not est_legitime(proc):
                    kill_process_tree(proc.pid, kill_parent=True)
                else:
                    MAIN_LOGGER.logger.info(f"[INFO] Processus légitime modifiant le registre : {proc.pid}")
            else:
                MAIN_LOGGER.logger.warning("[] Impossible d’identifier le processus à tuer (PID manquant ou non trouvé).")
        except Exception as e:
            pass
