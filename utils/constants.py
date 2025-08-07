import os

SUSPICIOUS_PROCESS_NAMES = {"python.exe", "pythonw.exe", "powershell.exe", "wscript.exe"}
SUSPICIOUS_CMDLINE_PATTERNS = [
    r'.*keylogger.*\.py',
    r'.*logger.*\.py',
    r'.*spy.*\.py',
    r'.*monitor.*\.py',
    r'.*ImageGrab.*',
    r'.*PIL.*'
]
SUSPICIOUS_MODULES = {"PIL", "ImageGrab", "screenshot"}


PROCESSUS_LEGITIMES = {
    "services.exe", "svchost.exe", "explorer.exe", "wininit.exe",
    "lsass.exe", "csrss.exe", "smss.exe", "winlogon.exe", "taskhostw.exe",
    "spoolsv.exe"
}
UTILISATEURS_SYSTEME = {
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service",
    "trustedinstaller"
}


WINDOWS_AVAILABLE = (os.name == 'nt')



SMB_PORTS = {445, 139}
LATERAL_TOOLS = {
    "powershell.exe", "cmd.exe", "psexec.exe", "wmic.exe", "wmiprvse.exe",
    "sc.exe", "reg.exe", "rundll32.exe", "at.exe", "schtasks.exe",
    "python.exe", "pythonw.exe", "python3.exe", "python3.11.exe"
}


# Registry persistence configuration
PERSISTENCE_NAME = "WatchdogAuto"
REGISTRY_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


REGISTRY_BLOCKER_ENABLED = True
SCREENSHOT_BLOCKER_ENABLED = True


EVT_QUERY_CHANNEL_PATH = 0x1
EVT_RENDER_EVENT_XML = 1
ERROR_NO_MORE_ITEMS = 259