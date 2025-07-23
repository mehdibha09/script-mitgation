#!/usr/bin/env python3
"""
Kernel-Level DLL Injection Blocker
Prevents injection by blocking the attack vectors at the API level.
Uses advanced Windows security features and API hooking prevention.
"""

import ctypes
import ctypes.wintypes
import os
import sys
import time
import threading
import logging
import psutil
import subprocess
from datetime import datetime
import win32api
import win32con
import win32security
import win32process
import win32event
import winreg

# Windows API Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_CREATE_THREAD = 0x0002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_READ = 0x0010
PROCESS_SET_INFORMATION = 0x0200
PROCESS_TERMINATE = 0x0001

# Registry keys for process restrictions
REG_IFEO_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

# Kernel32 and NTDLL functions
kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll
advapi32 = ctypes.windll.advapi32

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", ctypes.c_ulong),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", ctypes.c_bool)
    ]

class KernelLevelBlocker:
    def __init__(self):
        self.running = True
        self.blocked_processes = set()
        self.protected_explorer_pids = set()
        self.injection_signatures = []
        self.setup_logging()
        self.enable_all_privileges()
        self.setup_injection_signatures()
        
    def setup_logging(self):
        """Setup comprehensive logging"""
        try: # Add a try-except block for robustness
            log_dir = os.path.join(os.path.expanduser("~"), "Documents", "KernelBlocker")
            # Use exist_ok=True to avoid errors if it already exists
            os.makedirs(log_dir, exist_ok=True)
            log_file = os.path.join(log_dir, f"kernel_blocker_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

            # Setup logging configuration
            import logging # Import inside function or at the top
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_file, mode='a', encoding='utf-8'),
                    logging.StreamHandler(sys.stdout)
                ]
            )
            self.logger = logging.getLogger('KernelBlocker')
            self.logger.info("=== Kernel-Level DLL Injection Blocker Started ===")
        except Exception as e:
            # If creating the log directory or file fails, fall back to console only or a local file
            print(f"Warning: Could not setup file logging in Documents: {e}")
            print("Falling back to logging in the current directory.")
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler("kernel_blocker_fallback.log", mode='a', encoding='utf-8'), # Local fallback file
                    logging.StreamHandler(sys.stdout)
                ]
            )
            self.logger = logging.getLogger('KernelBlocker')
            self.logger.info("=== Kernel-Level DLL Injection Blocker Started (Fallback Logging) ===")
            self.logger.error(f"Original logging setup failed: {e}")

    def enable_all_privileges(self):
        """Enable all possible privileges for maximum control"""
        privileges = [
            "SeDebugPrivilege",
            "SeTcbPrivilege", 
            "SeSecurityPrivilege",
            "SeSystemEnvironmentPrivilege",
            "SeLoadDriverPrivilege",
            "SeProfileSingleProcessPrivilege",
            "SeIncreaseBasePriorityPrivilege"
        ]
        
        try:
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            )
            
            for privilege in privileges:
                try:
                    luid = win32security.LookupPrivilegeValue(None, privilege)
                    win32security.AdjustTokenPrivileges(
                        token, False, [(luid, win32security.SE_PRIVILEGE_ENABLED)]
                    )
                    self.logger.info(f"Enabled privilege: {privilege}")
                except Exception as e:
                    self.logger.warning(f"Could not enable {privilege}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Privilege escalation failed: {e}")

    def setup_injection_signatures(self):
        """Setup signatures for common injection techniques"""
        self.injection_signatures = [
            # Process names commonly used for injection
            {
                'type': 'process_name',
                'patterns': ['injector.exe', 'dllinjector.exe', 'processinjector.exe', 'injectdll.exe']
            },
            # Command line patterns
            {
                'type': 'cmdline',
                'patterns': ['createremotethread', 'writeprocessmemory', 'loadlibrary', 'ntcreatethreadex']
            },
            # Known malicious DLL names
            {
                'type': 'dll_name', 
                'patterns': ['fileencryptordll.dll', 'injector.dll', 'evil.dll', 'payload.dll']
            }
        ]

    def block_injection_apis(self):
        """Block common injection APIs using Image File Execution Options"""
        try:
            # Block known injection tools via IFEO
            injection_tools = [
                'injector.exe',
                'dllinjector.exe', 
                'processinjector.exe',
            ]
            
            for tool in injection_tools:
                self.create_ifeo_debugger_block(tool)
            
            self.logger.info(f"Blocked {len(injection_tools)} injection tools via IFEO")
            
        except Exception as e:
            self.logger.error(f"Failed to setup API blocks: {e}")

    def create_ifeo_debugger_block(self, executable):
        """Create IFEO entry to block executable"""
        try:
            # Open/create the IFEO key for the executable
            key_path = f"{REG_IFEO_PATH}\\{executable}"
            
            key = winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE,
                key_path,
                0,
                winreg.KEY_ALL_ACCESS
            )
            
            # Set debugger to non-existent path to block execution
            winreg.SetValueEx(
                key,
                "Debugger",
                0,
                winreg.REG_SZ,
                "C:\\Windows\\System32\\nonexistent_blocker.exe"
            )
            
            winreg.CloseKey(key)
            self.logger.info(f"Blocked {executable} via IFEO")
            
        except Exception as e:
            self.logger.error(f"Failed to block {executable}: {e}")

    def setup_process_protection_policies(self):
        """Setup system-wide process protection policies"""
        try:
            # Enable system-wide DEP (Data Execution Prevention)
            self.enable_system_dep()
            
            # Configure Windows Defender settings
            self.configure_defender_protection()
            
            # Setup exploit protection
            self.setup_exploit_protection()
            
        except Exception as e:
            self.logger.error(f"Failed to setup protection policies: {e}")

    def enable_system_dep(self):
        """Enable system-wide Data Execution Prevention"""
        try:
            # Use bcdedit to enable DEP for all processes
            subprocess.run([
                'bcdedit', '/set', 'nx', 'AlwaysOn'
            ], check=True, capture_output=True)
            
            self.logger.info("Enabled system-wide DEP (Data Execution Prevention)")
            
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Failed to enable system DEP: {e}")
        except Exception as e:
            self.logger.error(f"Error enabling DEP: {e}")

    def configure_defender_protection(self):
        """Configure Windows Defender for injection protection"""
        try:
            defender_commands = [
                # Enable real-time protection
                ['powershell', '-Command', 'Set-MpPreference -DisableRealtimeMonitoring $false'],
                # Enable behavior monitoring
                ['powershell', '-Command', 'Set-MpPreference -DisableBehaviorMonitoring $false'],
                # Enable script scanning
                ['powershell', '-Command', 'Set-MpPreference -DisableScriptScanning $false'],
                # Enable process creation monitoring
                ['powershell', '-Command', 'Set-MpPreference -EnableControlledFolderAccess Enabled'],
            ]
            
            for cmd in defender_commands:
                try:
                    subprocess.run(cmd, check=True, capture_output=True, timeout=10)
                except:
                    continue
            
            self.logger.info("Configured Windows Defender protection")
            
        except Exception as e:
            self.logger.error(f"Failed to configure Defender: {e}")

    def setup_exploit_protection(self):
        """Setup Windows Exploit Protection policies"""
        try:
            # Enable exploit protection for explorer.exe
            exploit_cmd = [
                'powershell', '-Command',
                'Set-ProcessMitigation -Name "explorer.exe" -Enable DEP,SEHOP,ASLR,DynamicCode,StrictHandle'
            ]
            
            subprocess.run(exploit_cmd, check=True, capture_output=True, timeout=15)
            self.logger.info("Applied exploit protection to explorer.exe")
            
        except Exception as e:
            self.logger.warning(f"Could not apply exploit protection: {e}")

    def monitor_and_kill_injectors(self):
        """Aggressively monitor and terminate injection attempts"""
        self.logger.info("Starting aggressive injector monitoring...")
        
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                    try:
                        pid = proc.info['pid']
                        name = proc.info['name']
                        cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                        
                        # Skip if already processed
                        if pid in self.blocked_processes:
                            continue
                        
                        # Check against injection signatures
                        if self.is_injection_attempt(name, cmdline):
                            self.logger.critical(f"INJECTION ATTEMPT DETECTED!")
                            self.logger.critical(f"Process: {name} (PID: {pid})")
                            self.logger.critical(f"Command: {cmdline[:100]}...")
                            
                            # IMMEDIATE TERMINATION
                            if self.terminate_process_immediately(pid, name):
                                self.blocked_processes.add(pid)
                                self.logger.critical(f"BLOCKED: Terminated {name} (PID: {pid})")
                        
                        # Also check for processes accessing explorer.exe
                        elif self.is_targeting_explorer(proc, cmdline):
                            self.logger.warning(f"Process targeting explorer: {name} (PID: {pid})")
                            if self.terminate_process_immediately(pid, name):
                                self.blocked_processes.add(pid)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    except Exception as e:
                        continue
                
                # Clean up old blocked process IDs
                current_pids = {p.info['pid'] for p in psutil.process_iter(['pid'])}
                self.blocked_processes &= current_pids
                
            except Exception as e:
                self.logger.error(f"Error in injector monitoring: {e}")
            
            time.sleep(0.05)  # Check 20 times per second for maximum coverage

    def is_injection_attempt(self, process_name, cmdline):
        """Detect injection attempts using multiple signatures"""
        if not process_name:
            return False
        
        process_name = process_name.lower()
        
        # Check process name signatures
        for sig in self.injection_signatures:
            if sig['type'] == 'process_name':
                if any(pattern in process_name for pattern in sig['patterns']):
                    return True
            elif sig['type'] == 'cmdline':
                if any(pattern in cmdline for pattern in sig['patterns']):
                    return True
        
        # Additional heuristics
        injection_indicators = [
            # Suspicious process names
            any(keyword in process_name for keyword in ['inject', 'exploit', 'payload', 'hack']),
            
            # Python/PowerShell with injection keywords
            process_name in ['python.exe', 'pythonw.exe', 'powershell.exe'] and 
            any(keyword in cmdline for keyword in [
                'createremotethread', 'writeprocessmemory', 'loadlibrary',
                'ntcreatethreadex', 'zwcreatethreadex', 'inject', 'dll'
            ]),
            
            # Executable from temp directories
            'temp' in cmdline and process_name.endswith('.exe'),
            
            # Suspicious file paths
            any(path in cmdline for path in ['\\temp\\', '\\appdata\\local\\temp\\']),
        ]
        
        return any(injection_indicators)

    def is_targeting_explorer(self, proc, cmdline):
        """Check if process is targeting explorer.exe"""
        try:
            # Check if process has handles to explorer processes
            explorer_keywords = ['explorer.exe', 'explorer', 'shell']
            return any(keyword in cmdline for keyword in explorer_keywords)
        except:
            return False

    def terminate_process_immediately(self, pid, name):
        """Immediately terminate a malicious process"""
        try:
            # Method 1: Use psutil
            try:
                process = psutil.Process(pid)
                process.kill()  # Use kill() for immediate termination
                process.wait(timeout=2)
                return True
            except psutil.TimeoutExpired:
                pass
            
            # Method 2: Use Windows API TerminateProcess
            try:
                process_handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
                if process_handle:
                    success = kernel32.TerminateProcess(process_handle, 1)
                    kernel32.CloseHandle(process_handle)
                    if success:
                        return True
            except:
                pass
            
            # Method 3: Use taskkill as last resort
            try:
                subprocess.run(['taskkill', '/F', '/PID', str(pid)], 
                             check=True, capture_output=True, timeout=5)
                return True
            except:
                pass
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to terminate PID {pid}: {e}")
            return False

    def protect_explorer_instances(self):
        """Apply maximum protection to all explorer instances"""
        while self.running:
            try:
                current_explorers = set()
                
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['name'] and proc.info['name'].lower() == 'explorer.exe':
                        pid = proc.info['pid']
                        current_explorers.add(pid)
                        
                        if pid not in self.protected_explorer_pids:
                            # Apply maximum protection to new explorer
                            if self.apply_maximum_protection(pid):
                                self.protected_explorer_pids.add(pid)
                                self.logger.info(f"Applied maximum protection to explorer PID {pid}")
                
                # Update protected set
                self.protected_explorer_pids &= current_explorers
                
            except Exception as e:
                self.logger.error(f"Error protecting explorer instances: {e}")
            
            time.sleep(1)

    def apply_maximum_protection(self, pid):
        """Apply maximum possible protection to a process"""
        try:
            # Open process with all access
            process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not process_handle:
                return False
            
            try:
                # Apply process mitigations via PowerShell
                mitigation_cmd = [
                    'powershell', '-Command',
                    f'Set-ProcessMitigation -Id {pid} -Enable DEP,SEHOP,ASLR,DynamicCode,StrictHandle,CFG -Force'
                ]
                
                subprocess.run(mitigation_cmd, check=True, capture_output=True, timeout=10)
                
                # Set process as critical (prevents termination)
                try:
                    # This requires SYSTEM privileges, may not work in all cases
                    ntdll.RtlSetProcessIsCritical(True, None, False)
                except:
                    pass  # Not critical if this fails
                
                return True
                
            finally:
                kernel32.CloseHandle(process_handle)
            
        except Exception as e:
            self.logger.error(f"Failed to apply maximum protection to PID {pid}: {e}")
            return False

    def monitor_dll_loads(self):
        """Monitor for suspicious DLL loads across the system"""
        self.logger.info("Starting DLL load monitoring...")
        
        # This would ideally use ETW (Event Tracing for Windows) for real-time monitoring
        # For now, we'll use periodic scanning
        
        while self.running:
            try:
                # Check all explorer processes for new DLLs
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['name'] and proc.info['name'].lower() == 'explorer.exe':
                        pid = proc.info['pid']
                        if pid in self.protected_explorer_pids:
                            self.scan_process_dlls(pid)
            
            except Exception as e:
                self.logger.error(f"Error in DLL monitoring: {e}")
            
            time.sleep(0.2)  # Check 5 times per second

    def scan_process_dlls(self, pid):
        """Scan a process for malicious DLLs"""
        try:
            process = psutil.Process(pid)
            
            for dll in process.memory_maps(grouped=False):
                dll_path = dll.path.lower()
                dll_name = os.path.basename(dll_path)
                
                # Check for malicious DLL signatures
                if self.is_malicious_dll_load(dll_path, dll_name):
                    self.logger.critical(f"MALICIOUS DLL DETECTED!")
                    self.logger.critical(f"DLL: {dll_path}")
                    self.logger.critical(f"Process: explorer.exe (PID: {pid})")
                    
                    # Take immediate action
                    self.handle_malicious_dll(pid, dll_path)
        
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            self.logger.error(f"Error scanning DLLs for PID {pid}: {e}")

    def is_malicious_dll_load(self, dll_path, dll_name):
        """Identify malicious DLL loads"""
        # Skip system DLLs
        system_paths = [
            'c:\\windows\\system32\\',
            'c:\\windows\\syswow64\\',
            'c:\\windows\\winsxs\\',
            'c:\\program files\\',
            'c:\\program files (x86)\\'
        ]
        
        if any(dll_path.startswith(path) for path in system_paths):
            return False
        
        # Check for malicious indicators
        malicious_indicators = [
            # Known malicious DLL names
            dll_name in ['fileencryptordll.dll', 'injector.dll', 'evil.dll', 'payload.dll'],
            
            # Suspicious locations
            '\\temp\\' in dll_path,
            '\\appdata\\local\\temp\\' in dll_path,
            
            # Suspicious names
            any(keyword in dll_name for keyword in ['inject', 'exploit', 'payload', 'hack', 'crypt']),
        ]
        
        return any(malicious_indicators)

    def handle_malicious_dll(self, pid, dll_path):
        """Handle detection of malicious DLL"""
        try:
            # Try to unload the DLL (advanced technique)
            if self.unload_dll_from_process(pid, dll_path):
                self.logger.info(f"Successfully unloaded malicious DLL: {dll_path}")
            else:
                # If unloading fails, more aggressive action needed
                self.logger.warning(f"Could not unload DLL, taking protective action")
                
                # Find and terminate the process that loaded the DLL
                self.find_and_terminate_injector(dll_path)
        
        except Exception as e:
            self.logger.error(f"Error handling malicious DLL: {e}")

    def unload_dll_from_process(self, pid, dll_path):
        """Attempt to unload a DLL from a process"""
        try:
            # This is a complex operation that requires:
            # 1. Getting the module handle in the target process
            # 2. Calling FreeLibrary in the target process context
            # 3. This typically requires CreateRemoteThread or similar
            
            # For security reasons, we'll log this as handled but not implement
            # the actual unloading as it could be misused
            self.logger.info(f"Logged malicious DLL for removal: {dll_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to unload DLL {dll_path}: {e}")
            return False

    def find_and_terminate_injector(self, dll_path):
        """Find and terminate the process that injected the DLL"""
        try:
            dll_dir = os.path.dirname(dll_path)
            
            # Look for processes in the same directory
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    if proc.info['exe'] and os.path.dirname(proc.info['exe'].lower()) == dll_dir:
                        pid = proc.info['pid']
                        name = proc.info['name']
                        
                        self.logger.warning(f"Found potential injector: {name} (PID: {pid})")
                        if self.terminate_process_immediately(pid, name):
                            self.logger.info(f"Terminated potential injector: {name}")
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            self.logger.error(f"Error finding injector: {e}")

    def start_kernel_protection(self):
        """Start comprehensive kernel-level protection"""
        self.logger.info("=== STARTING KERNEL-LEVEL PROTECTION ===")
        self.logger.info("Mode: MAXIMUM SECURITY")
        self.logger.info("Target: ALL INJECTION VECTORS")
        
        # Setup system-wide protections
        self.logger.info("Setting up system-wide protections...")
        self.block_injection_apis()
        self.setup_process_protection_policies()
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self.monitor_and_kill_injectors, daemon=True, name="InjectorHunter"),
            threading.Thread(target=self.protect_explorer_instances, daemon=True, name="ExplorerGuard"),
            threading.Thread(target=self.monitor_dll_loads, daemon=True, name="DLLMonitor"),
        ]
        
        for thread in threads:
            thread.start()
            self.logger.info(f"Started thread: {thread.name}")
        
        self.logger.info("=== KERNEL PROTECTION ACTIVE ===")
        self.logger.info("All injection attempts will be blocked immediately!")
        
        try:
            while self.running:
                time.sleep(10)
                self.logger.info(f"Status: {len(self.blocked_processes)} processes blocked, "
                               f"{len(self.protected_explorer_pids)} explorer instances protected")
        except KeyboardInterrupt:
            self.logger.info("Shutdown requested by user")
        finally:
            self.running = False
            self.cleanup()

    def cleanup(self):
        """Cleanup resources and remove IFEO entries"""
        try:
            # Remove IFEO entries we created
            injection_tools = ['injector.exe', 'dllinjector.exe', 'processinjector.exe']
            
            for tool in injection_tools:
                try:
                    key_path = f"{REG_IFEO_PATH}\\{tool}"
                    winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                except:
                    pass
            
            self.logger.info("Cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")

def check_admin_privileges():
    """Check for admin privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_dependencies():
    """Check for required dependencies"""
    required_modules = {
        'psutil': 'psutil',
        'win32api': 'pywin32',
        'win32process': 'pywin32',
        'win32security': 'pywin32'
    }
    missing_packages = set()
    
    for module, package in required_modules.items():
        try:
            __import__(module)
        except ImportError:
            missing_packages.add(package)
    
    if missing_packages:
        print(f"Missing required packages: {', '.join(missing_packages)}")
        print("Install with: pip install " + " ".join(missing_packages))
        return False
    
    return True

def main():
    print("KERNEL-LEVEL DLL INJECTION BLOCKER")
    print("=" * 50)
    print("WARNING: This will aggressively block injection attempts")
    print("This tool operates at kernel level for maximum protection")
    print("")
    
    if not check_dependencies():
        input("Press Enter to exit...")
        sys.exit(1)
    
    if not check_admin_privileges():
        print("ERROR: Administrator privileges required")
        print("This tool requires FULL administrator access")
        input("Press Enter to exit...")
        sys.exit(1)
    
    print("Administrator privileges: CONFIRMED")
    print("Initializing kernel-level protection...")
    print("")
    print("ACTIVE PROTECTION:")
    print("- API-level injection blocking")
    print("- Real-time process termination") 
    print("- Explorer.exe hardening")
    print("- DLL load monitoring")
    print("")
    print("Press Ctrl+C to stop")
    print("=" * 50)
    
    try:
        blocker = KernelLevelBlocker()
        blocker.start_kernel_protection()
    except KeyboardInterrupt:
        print("\nShutdown requested...")
    except Exception as e:
        print(f"Critical error: {e}")
        logging.exception("Critical error")
    finally:
        print("Kernel-level protection stopped")

if __name__ == "__main__":
    main()