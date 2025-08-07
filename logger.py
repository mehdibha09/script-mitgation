# logger.py

import logging
import json
from datetime import datetime

# Fichiers de log
MAIN_LOG_FILE = "security_monitor.log"
DLL_LOG_FILE = "dll_scan.log"

class SecurityLogger:
    """Unified logger for security events."""
    def __init__(self, log_file):
        self.logger = logging.getLogger(f"SecurityMonitor_{log_file}")
        self.logger.setLevel(logging.INFO)

        # Éviter d'ajouter plusieurs handlers si déjà présent
        if not self.logger.handlers:
            handler = logging.FileHandler(log_file, encoding='utf-8')
            handler.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

            # Affichage console uniquement pour le logger principal
            if log_file == MAIN_LOG_FILE:
                console_handler = logging.StreamHandler()
                console_handler.setLevel(logging.INFO)
                console_handler.setFormatter(formatter)
                self.logger.addHandler(console_handler)

    def log_action(self, action_type, details):
        """Log d'une action au format JSON."""
        serializable_details = self._make_serializable(details)
        action_data = {
            "timestamp": datetime.now().isoformat(),
            "action_type": action_type,
            "details": serializable_details
        }
        self.logger.info(f"{action_type.upper()}: {json.dumps(action_data, ensure_ascii=False)}")
        return action_data

    def _make_serializable(self, obj):
        """Rend les objets JSON-serializable pour les logs."""
        if isinstance(obj, dict):
            return {key: self._make_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, datetime):
            return obj.isoformat()
        return obj

# Initialisation des loggers globaux
MAIN_LOGGER = SecurityLogger(MAIN_LOG_FILE)
DLL_LOGGER = SecurityLogger(DLL_LOG_FILE)