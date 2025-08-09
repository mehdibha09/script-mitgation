import os

# --- Dépendance externe : sigcheck ---
SIGCHECK_PATH = r"C:\Tools\sigcheck.exe"  # ⚠️ Assure-toi qu'il existe à ce chemin

VIRUSTOTAL_API_KEY = "63cd3b2efe64cabf3646e065b8edc15847e7077268f5fb95bbd4785a92bafa38"  
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/"
VIRUSTOTAL_API_KEY = "TA_CLE_API_ICI"
# --- Paramètres Rate Limiting ---
MAX_REQUESTS = 4
TIME_LIMIT = 60  # secondes

# --- Relations Parent-Enfant suspectes ---
SUSPICIOUS_PARENT_CHILD = {
    # Explorer.exe ne devrait pas lancer d’interpréteurs ou d’outils système critiques
    ("explorer.exe", "powershell.exe"),
    ("explorer.exe", "cmd.exe"),
    ("explorer.exe", "mshta.exe"),
    ("explorer.exe", "cscript.exe"),
    ("explorer.exe", "wscript.exe"),
    ("explorer.exe", "rundll32.exe"),
    ("explorer.exe", "regsvr32.exe"),
    ("explorer.exe", "python.exe"),
    ("explorer.exe", "pythonw.exe"),

    # svchost.exe détourné pour lancer des payloads
    ("svchost.exe", "powershell.exe"),
    ("svchost.exe", "cmd.exe"),
    ("svchost.exe", "python.exe"),
    ("svchost.exe", "rundll32.exe"),
    ("svchost.exe", "mshta.exe"),
    ("svchost.exe", "wscript.exe"),

    # winlogon.exe – rarement parent direct de ces processus
    ("winlogon.exe", "explorer.exe"),
    ("winlogon.exe", "powershell.exe"),
    ("winlogon.exe", "cmd.exe"),
    ("winlogon.exe", "python.exe"),
    ("winlogon.exe", "rundll32.exe"),

    # lsass.exe ne doit jamais lancer de processus
    ("lsass.exe", "rundll32.exe"),
    ("lsass.exe", "powershell.exe"),
    ("lsass.exe", "cmd.exe"),
    ("lsass.exe", "mshta.exe"),

    # csrss.exe ne doit jamais lancer d’interpréteurs
    ("csrss.exe", "powershell.exe"),
    ("csrss.exe", "cmd.exe"),
    ("csrss.exe", "rundll32.exe"),
    ("csrss.exe", "python.exe"),

    # services.exe détourné dans certains malware
    ("services.exe", "cmd.exe"),
    ("services.exe", "powershell.exe"),
    ("services.exe", "python.exe"),
    ("services.exe", "mshta.exe"),

    # Regedit ou utilitaires système détournés
    ("regedit.exe", "cmd.exe"),
    ("regedit.exe", "powershell.exe"),
    ("taskmgr.exe", "powershell.exe"),

    # Navigateur lançant un script (typiquement phishing ou drive-by download)
    ("chrome.exe", "powershell.exe"),
    ("chrome.exe", "cmd.exe"),
    ("firefox.exe", "powershell.exe"),
    ("msedge.exe", "cmd.exe"),

    # cmd ou powershell lançant un autre outil suspect
    ("cmd.exe", "mshta.exe"),
    ("cmd.exe", "rundll32.exe"),
    ("powershell.exe", "rundll32.exe"),
    ("powershell.exe", "regsvr32.exe"),
}


# --- Noms de processus suspects (souvent utilisés par malware / RATs / scripts) ---
SUSPICIOUS_PROCESS_NAMES = {
    # Outils de post-exploitation / pentest
    "mimikatz.exe", "psexec.exe", "procdump.exe", "netcat.exe", "nc.exe",
    "ncat.exe", "powercat.exe", "xcopy.exe", "certutil.exe", "wmic.exe",
    "sc.exe", "at.exe", "taskkill.exe", "tasklist.exe", "whoami.exe",
    "nbtstat.exe", "ipconfig.exe", "netstat.exe", "net.exe", "arp.exe",

    # Interpréteurs ou scripts souvent utilisés dans des attaques
    "powershell.exe", "pwsh.exe", "cmd.exe", "cscript.exe", "wscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "regedit.exe", "wsl.exe",
    "bash.exe", "sh.exe", "curl.exe", "wget.exe", "python.exe", "pythonw.exe",
    "python3.exe", "python3.11.exe", "node.exe", "java.exe", "javaw.exe",
    "msbuild.exe", "installutil.exe",

    # Exfiltration / communication
    "ftp.exe", "tftp.exe", "telnet.exe", "sftp.exe", "plink.exe", "ssh.exe",
    "teamviewer.exe", "anydesk.exe", "chrome_remote_desktop_host.exe",
    "radmin.exe", "ultravnc.exe", "vncviewer.exe", "putty.exe",

    # RATs ou outils souvent packagés par malware
    "svchosts.exe", "explorer1.exe", "chrome_updater.exe", "servicehost.exe",
    "host.exe", "update.exe", "winlog.exe", "client.exe", "payload.exe",
    "dropper.exe", "backdoor.exe", "rat.exe", "shell.exe", "infostealer.exe",

    # Exécutables masqués comme légitimes mais douteux
    "svch0st.exe", "exp1orer.exe", "lsaas.exe", "rund11.exe", "system32.exe",
    "taskmgr.exe", "sysupdate.exe", "winupdate.exe", "updater.exe"
}

# --- Chemins suspects d'origine de fichiers exécutables ---
SUSPICIOUS_PATHS = [
    # Temp local/user
    os.path.expanduser(r"~\AppData\Local\Temp\\"),
    os.path.expanduser(r"~\AppData\LocalLow\Temp\\"),
    os.path.expanduser(r"~\AppData\Roaming\\"),
    os.path.expanduser(r"~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\\"),
    os.path.expanduser(r"~\AppData\Local\Microsoft\Windows\INetCache\\"),
    os.path.expanduser(r"~\AppData\Local\Microsoft\Windows\Explorer\\ThumbCacheToDelete\\"),
    os.path.expanduser(r"~\AppData\Local\Microsoft\Windows\Explorer\\IconCacheToDelete\\"),
    os.path.expanduser(r"~\AppData\Local\Microsoft\OneDrive\\"),
    os.path.expanduser(r"~\Downloads\\"),
    os.path.expanduser(r"~\Desktop\\"),

    # ProgramData (zone souvent utilisée pour l'installation silencieuse ou les RATs)
    r"C:\ProgramData\\",
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\\",
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\\",
    r"C:\ProgramData\Temp\\",

    # Public folders (utilisé pour déposer des payloads accessibles à tous)
    r"C:\Users\Public\\",
    r"C:\Users\Public\Downloads\\",
    r"C:\Users\Public\Documents\\",
    r"C:\Users\Public\Music\\",
    r"C:\Users\Public\Videos\\",
    r"C:\Users\Public\Pictures\\",

    # Chemins Windows "non sécurisés"
    r"C:\Windows\Temp\\",
    r"C:\Windows\Tasks\\",  # tâches planifiées anciennes
    r"C:\Windows\debug\\",
    r"C:\Windows\tracing\\",
    r"C:\Windows\System32\Tasks\\",  # persistance
    r"C:\Windows\System32\LogFiles\\WMI\\",
    r"C:\Windows\System32\Spool\\Drivers\\",  # injection via DLL

    # Chemins typiques de RATs personnalisés ou de loaders
    r"C:\PerfLogs\\",
    r"C:\Intel\\",  # souvent utilisé comme leurre
    r"C:\Recovery\\",
    r"C:\$Recycle.Bin\\",
    r"C:\System Volume Information\\",

    # Installations silencieuses ou fake software
    r"C:\Temp\\",
    r"C:\TMP\\",
    r"C:\Logs\\",
    r"C:\Tools\\",
    r"C:\Drivers\\",
    r"C:\Backups\\",
]

SUSPICIOUS_CMDLINE_PATTERNS = [
    # --- PowerShell obfuscation, download & bypass ---
    ("-enc", "powershell.exe"), ("-encodedcommand", "powershell.exe"),
    ("-e ", "powershell.exe"), ("-nop", "powershell.exe"),
    ("-noni", "powershell.exe"), ("-w hidden", "powershell.exe"),
    ("-windowstyle hidden", "powershell.exe"),
    ("-executionpolicy bypass", "powershell.exe"),
    ("-noprofile", "powershell.exe"), ("-nolog", "powershell.exe"),
    ("-file", "powershell.exe"), ("-command", "powershell.exe"),
    ("iex", "powershell.exe"), ("invoke-expression", "powershell.exe"),
    ("invoke-webrequest", "powershell.exe"),
    ("invoke-restmethod", "powershell.exe"),
    ("frombase64string", "powershell.exe"),
    ("new-object net.webclient", "powershell.exe"),
    ("downloadstring", "powershell.exe"),
    ("start-bitstransfer", "powershell.exe"),
    ("add-type", "powershell.exe"),

    # --- CMD obfuscation / persistence / injection ---
    ("/c ", "cmd.exe"), ("/k ", "cmd.exe"),
    ("cmd.exe", "powershell"), ("cmd.exe", "mshta"),
    ("cmd.exe", "wscript"), ("cmd.exe", "cscript"),
    ("cmd.exe", "certutil"), ("cmd.exe", "bitsadmin"),

    # --- Rundll32 attacks / LOLBins ---
    ("rundll32.exe", "javascript:"), ("rundll32.exe", "vbscript:"),
    ("rundll32.exe", "shell32"), ("rundll32.exe", "url.dll"),
    ("rundll32.exe", "launchapplication"),

    # --- Python malware scripts ---
    (r"keylogger", "python.exe"), (r"logger", "python.exe"),
    (r"stealer", "python.exe"), (r"grabber", "python.exe"),
    (r"imagegrab", "python.exe"), (r"pynput", "python.exe"),
    (r"pil", "python.exe"), (r"screenshot", "python.exe"),
    (r"reverse_shell", "python.exe"), (r"socket", "python.exe"),

    # --- MSHTA / HTA / Script-based LOLBins ---
    ("mshta", "http:"), ("mshta", "https:"), ("mshta", ".hta"),
    ("mshta", "vbscript:"), ("mshta", "javascript:"),

    # --- WScript / CScript abuses ---
    ("wscript.exe", ".vbs"), ("wscript.exe", ".js"),
    ("cscript.exe", ".vbs"), ("cscript.exe", ".js"),
    ("cscript.exe", "shell.application"),
    ("wscript.exe", "shell.application"),

    # --- Certutil / Living-off-the-Land ---
    ("certutil", "-urlcache"), ("certutil", "-decode"),
    ("certutil", "-encode"), ("certutil", "-f"),
    ("bitsadmin", "/transfer"),

    # --- Persistence / startup injection ---
    ("reg add", None), ("schtasks", "/create"),
    ("sc", "create"), ("sc", "config"),
    ("copy", "startup"), ("move", "startup"),

    # --- Powershell over encoded web payload ---
    ("powershell", "http:"), ("powershell", "https:"),
    ("powershell", ".ps1"),

    # --- Others suspicious ---
    ("whoami", None), ("netstat", None),
    ("tasklist", None), ("taskkill", None),
    ("systeminfo", None), ("quser", None),
]


SUSPICIOUS_MODULES = {
    # --- Espionnage d'écran / Screenshot / Webcam ---
    "PIL", "ImageGrab", "pyautogui", "mss", "opencv", "cv2",

    # --- Keyloggers / capture clavier-souris ---
    "pynput", "pyxhook", "keyboard", "mouse", "pyHook", "pyuserinput",

    # --- Contrôle / Automatisation (souvent malveillant) ---
    "pyautogui", "autopy", "pywinauto",

    # --- Réseaux / Communication (exfiltration, C2) ---
    "socket", "requests", "httpx", "urllib", "smtplib", "ftplib",

    # --- Chiffrement / Obfuscation (souvent ransomware) ---
    "cryptography", "pyAesCrypt", "base64", "hashlib",

    # --- Compression / Stéganographie ---
    "zlib", "zipfile", "tarfile", "lzma", "stegano", "pyzipper",

    # --- Téléchargement / Droppers ---
    "urllib.request", "requests", "wget",

    # --- Exécution dynamique / Bypass ---
    "subprocess", "os.system", "eval", "exec", "ctypes", "inspect",

    # --- Collecte d'infos système / privilèges ---
    "psutil", "platform", "getpass", "win32api", "win32security", "wmi",

    # --- Persistence / manipulation registre (Windows) ---
    "winreg", "pywin32", "win32com.client", "ctypes",

    # --- Webcam / Audio / Capture ---
    "sounddevice", "pyaudio", "cv2", "speech_recognition",

    # --- Modules suspects génériques / low-level ---
    "ctypes", "pydbg", "pyhook", "pefile", "pycrypto"
}


# --- Processus cibles fréquents pour injection / hollowing ---
TARGET_FOR_INJECTION = {
    "explorer.exe", "svchost.exe", "lsass.exe", "winlogon.exe",
    "csrss.exe", "rundll32.exe", "powershell.exe", "cmd.exe",
    "mshta.exe", "cscript.exe", "wscript.exe"
}

# --- Processus légitimes système (protégés) ---
PROCESSUS_LEGITIMES = {
    "services.exe", "svchost.exe", "explorer.exe", "wininit.exe",
    "lsass.exe", "csrss.exe", "smss.exe", "winlogon.exe", "taskhostw.exe",
    "spoolsv.exe", "msedge.exe", "chrome.exe", "firefox.exe"
}

# --- Utilisateurs système ---
UTILISATEURS_SYSTEME = {
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service",
    "nt authority\\trusted installer",
    "local service",
    "network service",
    "system",
    "administrator",
    "administrateur",
    "service",
    "local system",
    "trustedinstaller",
    "networkservice",
    "localservice",
}


# --- Ports SMB pour détection latéralisation ---
SMB_PORTS = {445, 139}

# --- Outils de mouvement latéral fréquemment utilisés ---
LATERAL_TOOLS = {
    "powershell.exe", "cmd.exe", "psexec.exe", "wmic.exe", "wmiprvse.exe",
    "sc.exe", "reg.exe", "rundll32.exe", "at.exe", "schtasks.exe",
    "python.exe", "pythonw.exe", "python3.exe", "python3.11.exe"
}

# --- Persistance via registre ---
PERSISTENCE_NAME = "WatchdogAuto"
REGISTRY_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

# --- Comportements à bloquer ---
REGISTRY_BLOCKER_ENABLED = True
SCREENSHOT_BLOCKER_ENABLED = True

# --- Constantes Windows pour lecture d'événements (EvtQuery) ---
WINDOWS_AVAILABLE = (os.name == 'nt')
EVT_QUERY_CHANNEL_PATH = 0x1
EVT_RENDER_EVENT_XML = 1
ERROR_NO_MORE_ITEMS = 259
