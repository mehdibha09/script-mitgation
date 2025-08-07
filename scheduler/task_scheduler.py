import os
import sys
import subprocess
from logger import MAIN_LOGGER

def add_task_scheduler(task_name="SecurityMonitor", script_path=None):
    """Ajoute le script au Planificateur de tâches Windows."""
    try:
        if script_path is None:
            script_path = os.path.abspath(sys.argv[0])

        # Vérifie si la tâche existe déjà
        result = subprocess.run(["schtasks", "/Query", "/TN", task_name], capture_output=True, text=True)
        if result.returncode == 0:
            MAIN_LOGGER.logger.info(f"[✔] Scheduled task '{task_name}' already exists.")
            return

        # Commande pour créer la tâche
        cmd = [
            "schtasks", "/Create", "/SC", "ONSTART", "/RL", "HIGHEST",
            "/TN", task_name,
            "/TR", f'"{sys.executable} {script_path}"',
            "/F"
        ]
        result = subprocess.run(" ".join(cmd), capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            MAIN_LOGGER.logger.info(f"[✔] Scheduled task '{task_name}' added.")
        else:
            MAIN_LOGGER.logger.error(f"[!] Error adding task: {result.stderr.strip()}")
    except Exception as e:
        MAIN_LOGGER.logger.error(f"[ERROR] Cannot create scheduled task: {e}")
