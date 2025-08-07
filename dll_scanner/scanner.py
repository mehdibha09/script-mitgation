


import os
import subprocess
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
import time
import traceback

from utils.constants import (
  WINDOWS_AVAILABLE
)



# --- DLL Scanner ---
class DLLSecurityScanner:
    """Scanner for suspicious DLLs in user directories."""
    def __init__(self, logger):
        self.logger = logger
        self.scan_paths = [
    str(Path.home() / 'Desktop'),
    str(Path.home() / 'Downloads')
]

        self.suspicious_content_patterns = [
            'encrypt', 'decrypt', 'ransom', 'bitcoin', 'wallet', 'payment', '.onion',
            'createremotethread', 'virtualallocex', 'writeprocessmemory',
            'setwindowshookex', 'loadlibrary', 'getprocaddress',
            'urldownloadtofile', 'internetopen', 'httpopen',
            'deletefile', 'movefile', 'copyfile',
        ]
        self.scan_cycle_counter = 0

    def is_digitally_signed(self, file_path):
        """Check if a DLL is digitally signed."""
        if not WINDOWS_AVAILABLE:
            return None
        try:
            cmd = f'powershell -Command "(Get-AuthenticodeSignature \'{file_path}\').Status -eq \'Valid\'"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=30)
            if result.returncode == 0:
                if "True" in result.stdout:
                    return True
                elif "False" in result.stdout:
                    return False
            return None
        except subprocess.TimeoutExpired:
            self.logger.logger.warning(f"Timeout checking signature for {file_path}")
            return None
        except Exception as e:
            self.logger.logger.warning(f"Could not verify signature for {file_path}: {e}")
            return None

    def get_file_metadata(self, file_path):
        """Get file metadata and hash."""
        try:
            stat = os.stat(file_path)
            path_obj = Path(file_path)
            metadata = {
                'path': str(file_path),
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'is_signed': self.is_digitally_signed(file_path),
                'extension': path_obj.suffix.lower(),
                'filename': path_obj.name
            }
            hash_sha256 = hashlib.sha256()
            try:
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_sha256.update(chunk)
                metadata['sha256'] = hash_sha256.hexdigest()
            except IOError:
                metadata['sha256'] = "Error"
            return metadata
        except Exception as e:
            self.logger.logger.error(f"Error getting metadata for {file_path}: {e}")
            return None

    def is_suspicious_location(self, dll_path):
        """Check if DLL is in a suspicious location."""
        path_str = str(dll_path).lower()
        suspicious_indicators = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
            '\\users\\public\\', '\\programdata\\temp\\',
            '\\windows\\temp\\', '\\$recycle.bin\\',
            '\\downloads\\', '\\desktop\\'
        ]
        return any(indicator in path_str for indicator in suspicious_indicators)

    def analyze_dll_content(self, dll_path):
        """Analyze DLL content for suspicious strings."""
        suspicious_patterns = []
        try:
            with open(dll_path, 'rb') as f:
                content = f.read(16384)
                content_str = content.decode('latin-1', errors='ignore').lower()
                for indicator in self.suspicious_content_patterns:
                    if indicator in content_str:
                        suspicious_patterns.append(indicator)
        except Exception:
            pass
        return suspicious_patterns

    def calculate_risk_score(self, metadata, content_patterns, location_suspicious):
        """Calculate risk score with breakdown."""
        risk_score = 0
        score_details = []

        if metadata['is_signed'] is False:
            risk_score += 40
            score_details.append("Not signed (+40)")
        elif metadata['is_signed'] is None:
            risk_score += 20
            score_details.append("Signature check failed (+20)")

        if location_suspicious:
            risk_score += 30
            score_details.append("Suspicious location (+30)")

        pattern_count = len(content_patterns)
        pattern_score = pattern_count * 10
        risk_score += pattern_score
        if pattern_count > 0:
            score_details.append(f"Contains {pattern_count} patterns (+{pattern_score})")

        try:
            modified_dt = datetime.fromisoformat(metadata['modified'])
            file_age = datetime.now() - modified_dt
            if file_age < timedelta(hours=1):
                risk_score += 25
                score_details.append("Very recent (<1h) (+25)")
            elif file_age < timedelta(days=1):
                risk_score += 15
                score_details.append("Recent (<1d) (+15)")
        except Exception:
            pass

        size = metadata['size']
        if size < 10000 or size > 50000000:
            risk_score += 10
            score_details.append("Unusual size (+10)")

        return risk_score, score_details

    def delete_dll(self, dll_path, metadata, risk_score, risk_factors, score_details):
        """Delete a suspicious DLL."""
        try:
            deletion_log = {
                'cycle_id': self.scan_cycle_counter,
                'deleted_path': str(dll_path),
                'timestamp': datetime.now().isoformat(),
                'risk_score': risk_score,
                'risk_factors': risk_factors,
                'score_breakdown': score_details,
                'metadata': metadata
            }
            Path(dll_path).unlink()
            self.logger.log_action("DLL_DELETED", deletion_log)
            print(f"[DLL_SCAN] Deleted: {dll_path}") # Immediate console feedback
            return True
        except PermissionError as e:
            error_log = {'cycle_id': self.scan_cycle_counter, 'path': str(dll_path), 'error': f"Permission denied: {e}", 'risk_score': risk_score, 'risk_factors': risk_factors, 'metadata': metadata}
            self.logger.logger.error(f"Permission denied deleting {dll_path}: {e}")
            self.logger.log_action("DLL_DELETE_FAILED", error_log)
            return False
        except Exception as e:
            error_log = {'cycle_id': self.scan_cycle_counter, 'path': str(dll_path), 'error': f"Error: {e}", 'risk_score': risk_score, 'risk_factors': risk_factors, 'metadata': metadata}
            self.logger.logger.error(f"Failed to delete {dll_path}: {e}")
            self.logger.log_action("DLL_DELETE_FAILED", error_log)
            return False

    def scan_and_delete_suspicious_dlls(self, risk_threshold=50):
        """Scan and delete suspicious DLLs."""
        self.scan_cycle_counter += 1
        cycle_start_time = datetime.now()
        self.logger.logger.info(f"--- Starting DLL Scan Cycle {self.scan_cycle_counter} ---")
        scan_results = {'cycle_id': self.scan_cycle_counter, 'start_time': cycle_start_time.isoformat(), 'scanned': 0, 'deleted': 0, 'suspicious': 0, 'errors': 0}

        for scan_path in self.scan_paths:
            if not os.path.exists(scan_path):
                self.logger.logger.warning(f"Scan path inaccessible: {scan_path}")
                scan_results['errors'] += 1
                continue
            self.logger.logger.info(f"Scanning directory: {scan_path}")

            try:
                for root, dirs, files in os.walk(scan_path):
                    root_lower = root.lower()
                    if any(sys_dir in root_lower for sys_dir in ['\\windows\\system32\\', '\\windows\\syswow64\\', '\\windows\\winsxs\\']):
                        continue

                    for file in files:
                        if file.lower().endswith('.dll'):
                            dll_path = os.path.join(root, file)
                            try:
                                scan_results['scanned'] += 1
                                metadata = self.get_file_metadata(dll_path)
                                if not metadata:
                                    scan_results['errors'] += 1
                                    continue

                                location_suspicious = self.is_suspicious_location(dll_path)
                                content_patterns = self.analyze_dll_content(dll_path)
                                any_suspicion = location_suspicious or content_patterns or metadata['is_signed'] is False

                                risk_score, score_details = self.calculate_risk_score(metadata, content_patterns, location_suspicious)

                                if risk_score >= risk_threshold:
                                    scan_results['suspicious'] += 1
                                    risk_factors = []
                                    if metadata['is_signed'] is False: risk_factors.append("unsigned")
                                    if location_suspicious: risk_factors.append("suspicious_location")
                                    if content_patterns: risk_factors.extend([f"pattern_{p}" for p in content_patterns[:5]])

                                    log_details = {'cycle_id': self.scan_cycle_counter, 'path': dll_path, 'risk_score': risk_score, 'risk_factors': risk_factors, 'score_breakdown': score_details, 'metadata': metadata}
                                    self.logger.log_action("DLL_SUSPICIOUS", log_details)

                                    if self.delete_dll(dll_path, metadata, risk_score, risk_factors, score_details):
                                        scan_results['deleted'] += 1

                            except Exception as e:
                                scan_results['errors'] += 1
                                self.logger.logger.error(f"Error processing {dll_path}: {e}", exc_info=True)

            except Exception as e:
                self.logger.logger.error(f"Error scanning directory {scan_path}: {e}", exc_info=True)
                scan_results['errors'] += 1

        cycle_end_time = datetime.now()
        scan_results['end_time'] = cycle_end_time.isoformat()
        scan_results['duration_seconds'] = (cycle_end_time - cycle_start_time).total_seconds()
        self.logger.logger.info(f"--- DLL Scan Cycle {self.scan_cycle_counter} Completed ---")
        self.logger.logger.info(f"Results: {scan_results}")
        return scan_results

def run_dll_scanner_periodically(logger_instance, interval_seconds=60):
    """Run DLL scanner periodically."""
    scanner = DLLSecurityScanner(logger_instance)
    try:
        while True:
            if results['suspicious']!=0 or results['deleted']!=0:
                print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] --- Initiating DLL Scan Cycle ---")
                results = scanner.scan_and_delete_suspicious_dlls(risk_threshold=50)
                print(f"--- Scan Cycle Summary ---")
                print(f"  Cycle ID: {results.get('cycle_id', 'N/A')}")
                print(f"  Scanned: {results['scanned']} DLLs")
                print(f"  Suspicious: {results['suspicious']} DLLs")
                print(f"  Deleted: {results['deleted']} DLLs")
                print(f"  Errors: {results['errors']}")
                print(f"  Duration: {results.get('duration_seconds', 'N/A'):.2f} seconds")
                print(f"--- Waiting {interval_seconds} seconds ---\n")
            time.sleep(interval_seconds)
    except Exception as e:
        logger_instance.logger.critical(f"DLL Scanner crashed: {e}")
        logger_instance.logger.critical(traceback.format_exc())