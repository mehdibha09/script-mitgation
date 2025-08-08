import os

SIGCHECK_PATH = r"C:\Tools\sigcheck.exe"  # Adjust path to sigcheck.exe as needed
SUSPICIOUS_PARENT_CHILD = {
    ("explorer.exe", "powershell.exe"),
    ("explorer.exe", "cmd.exe"),
    ("explorer.exe", "mshta.exe"),
    ("explorer.exe", "cscript.exe"), 
    ("explorer.exe", "wscript.exe"),
    ("svchost.exe", "python.exe"), 
    ("svchost.exe", "rundll32.exe"), 
    ("winlogon.exe", "explorer.exe"), 
    ("winlogon.exe", "powershell.exe"),
    ("lsass.exe", "rundll32.exe"), 
    ("lsass.exe", "powershell.exe"),
    ("csrss.exe", "rundll32.exe"), 
    ("csrss.exe", "powershell.exe"),
}

SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz.exe", "psexec.exe", "at.exe", "schtasks.exe", 
    "powershell.exe", "cmd.exe", "mshta.exe", "cscript.exe", "wscript.exe", 
    "rundll32.exe", "regsvr32.exe", "bitsadmin.exe"}

# Suspicious command line arguments or patterns
SUSPICIOUS_CMDLINE_PATTERNS = [
    ("-enc", "powershell.exe"), ("-encodedcommand", "powershell.exe"), ("-e ", "powershell.exe"), # PowerShell encoded commands
    ("FromBase64String", None),
    ("IEX", None), ("Invoke-Expression", None),
    ("/c ", "cmd.exe"), ("/k ", "cmd.exe"), 
    ("rundll32.exe", "javascript:"), 
    ("rundll32.exe", "vbscript:"), 
    ("-s", "powershell.exe"), # PowerShell scripts
    ("-nop", "powershell.exe"), # No profile
    ("-noni", "powershell.exe"), # No interactive
    ("-w hidden", "powershell.exe"), # Hidden window
    ("-windowstyle hidden", "powershell.exe"), # Hidden window style
    ("-ExecutionPolicy Bypass", "powershell.exe"), # Bypass execution policy
    ("-NoLogo", "powershell.exe"), # No logo
    ("-NoProfile", "powershell.exe"), # No profile
    ("-File ", "powershell.exe"), # File execution
    ("-Command ", "powershell.exe"), # Command execution
    ("-EncodedCommand ", "powershell.exe"), # Encoded command execution
    ]

# Suspicious directories where processes should not typically originate
SUSPICIOUS_PATHS = [
    os.path.expanduser("~\\AppData\\Local\\Temp\\"),
    os.path.expanduser("~\\AppData\\Roaming\\"),
    os.path.expanduser("~\\Desktop\\"),
    "C:\\Windows\\Temp\\",
    "C:\\Windows\\System32\\",
    "C:\\Windows\\SysWOW64\\",
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
    "C:\\Program Files\\Common Files\\",
    "C:\\Program Files (x86)\\Common Files\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
    "C:\\Users\\Public\\Documents\\",
    "C:\\Users\\Public\\Downloads\\",]

# Processes that are commonly used by malware for injection or hollowing
TARGET_FOR_INJECTION = {
    "explorer.exe", "svchost.exe", "lsass.exe", "winlogon.exe", "csrss.exe",
    "rundll32.exe", "powershell.exe", "cmd.exe", "mshta.exe", "cscript.exe", "wscript.exe"
}
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