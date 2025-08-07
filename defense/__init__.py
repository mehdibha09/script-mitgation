from .behavior_defense import (
    detect_keylogger_activity,
    detect_smb_propagation,
    mitiger_connexion_reseau,
    est_commande_suspecte,
)
from .proactive import proactive_defense_thread
from .registry_blocker import check_and_remove_registry_persistence,_open_reg_key
from .screenshot_blocker import detect_screenshot_activity