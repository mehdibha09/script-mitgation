import os
from logger import MAIN_LOGGER
import datetime
import hashlib
import psutil
import re
import base64
from urllib.parse import urlparse
import ipaddress
from pathlib import Path

from utils.constants import (
    PROCESSUS_LEGITIMES,
    UTILISATEURS_SYSTEME,
)



def decode_powershell_base64(commandline):
    """Decode Base64 encoded PowerShell commands."""
    try:
        match = re.search(r"(?:-enc\s+|-encodedcommand\s+)([a-z0-9+/=]+)", commandline, re.I)
        if match:
            encoded_str = match.group(1)
            decoded_bytes = base64.b64decode(encoded_str)
            try:
                return decoded_bytes.decode('utf-16le')
            except UnicodeDecodeError:
                return decoded_bytes.decode('utf-8', errors='ignore')
    except Exception as e:
        MAIN_LOGGER.logger.warning(f"[!] Error decoding PowerShell command: {e}")
    return ""

def reconstruire_url_depuis_event(event_data):
    ip = event_data.get("DestinationIp", "")
    hostname = event_data.get("DestinationHostname", "")
    port = str(event_data.get("DestinationPort", ""))
    
    # S'il y a un hostname, on le prend (plus fiable que l'IP seule)
    domaine = hostname if hostname else ip
    
    # Ajoute un schéma probable (basé sur le port)
    if port == "443":
        url = f"https://{domaine}"
    elif port == "80":
        url = f"http://{domaine}"
    else:
        url = f"http://{domaine}:{port}"

    return url

def est_ip_locale(ip):
    """
    Vérifie si l'IP appartient à un réseau privé.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False  # IP invalide
    

def extract_urls(command_line):
    return [word for word in command_line.split() if word.startswith("http")]


def est_url_suspecte(url):
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    domaines_dangereux = ["github.com", "raw.githubusercontent.com", "cdn.discordapp.com"]
    return any(d in domain for d in domaines_dangereux)

def get_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        return f"[Erreur hash] {e}"

def sauvegarder_binaire_suspect(path):
    try:
        if os.path.exists(path):
            log_file = os.path.join("suspects_paths.txt")
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {path}\n")
    except Exception as e:
        # Pas de MAIN_LOGGER pour éviter affichage console
        with open(os.path.join("samples_suspects", "suspects_paths_errors.txt"), "a", encoding="utf-8") as err_file:
            err_file.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Erreur : {e}\n")


def est_commande_suspecte(commandline: str) -> bool:
    """Check if a command line is suspicious."""
    if not commandline:
        return False
    cl = commandline.lower()
    decoded_cmd = decode_powershell_base64(commandline)
    full_cmd = cl + " " + decoded_cmd.lower()

    motifs_suspects = [
        r"encodedcommand", r"-enc", r"base64", r"invoke-expression", r"\biex\b",
        r"downloadstring", r"invoke-webrequest", r"start-bitstransfer", r"new-object",
        r"start-process", r"bypass", r"-nop", r"hidden", r"certutil", r"curl", r"wget",
        r"bitsadmin", r"\.js\b", r"\.vbs\b", r"\.bat\b", r"\.ps1\b", r"schtasks",
        r"reg add", r"regsvr32", r"rundll32"
    ]
    return any(re.search(motif, full_cmd) for motif in motifs_suspects)

def kill_process_tree(pid: int, kill_parent: bool = True):
    """Kill a process tree using psutil, but protect only the children of this script."""
    try:
        parent = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return

    current_pid = os.getpid()
    current_proc = psutil.Process(current_pid)
    
    # Construire l'ensemble des PID à protéger : juste les enfants du script de mitigation
    protected_pids = {current_pid}
    try:
        for child in current_proc.children(recursive=True):
            protected_pids.add(child.pid)
    except Exception:
        pass

    to_kill = []
    try:
        children = parent.children(recursive=True)
        to_kill.extend([p for p in children if p.pid not in protected_pids])
    except psutil.Error:
        pass

    # Ajouter le parent seulement si kill_parent=True et pas dans la liste protégée
    if kill_parent and parent.pid not in protected_pids:
        to_kill.append(parent)

    MAIN_LOGGER.logger.debug(f"[DEBUG] kill_process_tree called for PID {pid}, kill_parent={kill_parent}")
    for proc_to_kill in to_kill:
        try:
            proc_to_kill.kill()
            MAIN_LOGGER.logger.info(f"[🔪] Killed {proc_to_kill.name()} (PID {proc_to_kill.pid})")
        except psutil.NoSuchProcess:
            MAIN_LOGGER.logger.debug(f"[DEBUG] Process {proc_to_kill.pid} seems to have died already.")
        except psutil.AccessDenied:
            MAIN_LOGGER.logger.warning(f"[⚠️] Access denied to kill PID {proc_to_kill.pid}")
        except Exception as e:
            MAIN_LOGGER.logger.error(f"[ERROR] Exception killing {proc_to_kill.pid}: {e}")


def est_legitime(proc: psutil.Process) -> bool:
    """
    Vérifie si un processus est légitime (chemin, nom, utilisateur).
    """
    try:
        with proc.oneshot():
            name = proc.name().lower()
            exe = (proc.exe() or "").lower()
            user = (proc.username() or "").lower()
    except psutil.Error:
        MAIN_LOGGER.logger.warning(f"[⚠️] Impossible d'accéder au processus {proc.pid}. Considéré légitime par précaution.")
        return True

    exe_path = Path(exe)

    # --- Cas protégé absolu ---
    if name == "explorer.exe":
        MAIN_LOGGER.logger.info(f"[✅] Processus 'explorer.exe' protégé (PID {proc.pid})")
        return True

    # --- Vérification pour processus connus ---
    if name in PROCESSUS_LEGITIMES:
        try:
            is_system_path = any(
                exe_path.is_relative_to(Path(p))
                for p in [r"c:\windows\system32", r"c:\windows\syswow64", r"c:\program files", r"c:\program files (x86)"]
            )
        except Exception:
            is_system_path = False

        is_system_user = user in UTILISATEURS_SYSTEME

        if is_system_path and is_system_user:
            MAIN_LOGGER.logger.debug(f"[✔] Processus légitime confirmé : {name} (PID {proc.pid})")
            return True
        else:
            MAIN_LOGGER.logger.warning(
                f"[❗] Contexte douteux pour processus légitime : {name} "
                f"(PID {proc.pid}) | User: {user} | Path: {exe}"
            )
            # Par précaution, considérer légitime même si contexte douteux.
            return True

    # --- Processus non listé => considérer comme suspect ---
    MAIN_LOGGER.logger.debug(f"[🕵️‍♂️] Processus inconnu ou non listé : {name} (PID {proc.pid})")
    return False
