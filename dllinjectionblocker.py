#!/usr/bin/env python3

import os
import sys
import time
import json
import hashlib
import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
import psutil

# Required imports
try:
    import psutil
except ImportError as e:
    print(f"Missing required module: {e}")
    print("Install with: pip install psutil")
    sys.exit(1)

WINDOWS_AVAILABLE = (os.name == 'nt')

class SecurityLogger:
    """Simple logging for security events"""
    def __init__(self, log_file="dll_scan.log"):
        self.logger = logging.getLogger("DLLScanner")
        self.logger.setLevel(logging.INFO)

        # File handler
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.INFO)

        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def log_action(self, action_type, details):
        """Log an action with structured data"""
        # Ensure datetime objects are serializable for logging
        serializable_details = self._make_serializable(details)
        action_data = {
            "timestamp": datetime.now().isoformat(),
            "action_type": action_type,
            "details": serializable_details
        }
        self.logger.info(f"{action_type.upper()}: {json.dumps(action_data)}")
        return action_data

    def _make_serializable(self, obj):
        """Recursively convert non-serializable objects (like datetime) to strings."""
        if isinstance(obj, dict):
            return {key: self._make_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, datetime):
            return obj.isoformat()
        # Add other non-serializable types if needed
        return obj

class DLLSecurityScanner:
    """DLL scanner focused on user directories with deletion capability"""
    def __init__(self, logger):
        self.logger = logger
        self.suspicious_dll_cache = set()

        # Focus on user directories
        self.scan_paths = [
            'C:\\Users',
            str(Path.home() / 'Desktop')
        ]

        # Suspicious patterns indicating potential malware
        self.suspicious_content_patterns = [
            # Crypto/Ransomware indicators
            'encrypt', 'decrypt', 'ransom', 'bitcoin', 'wallet',
            'payment', '.onion',
            # Process injection indicators
            'createremotethread', 'virtualallocex', 'writeprocessmemory',
            'setwindowshookex', 'loadlibrary', 'getprocaddress',
            # Network indicators
            'urldownloadtofile', 'internetopen', 'httpopen',
            # File operations
            'deletefile', 'movefile', 'copyfile',
        ]

    def is_digitally_signed(self, file_path):
        """Check if a file is digitally signed using Windows tools"""
        if not WINDOWS_AVAILABLE:
            return None
        try:
            # Use PowerShell to check digital signature
            cmd = f'powershell -Command "(Get-AuthenticodeSignature \'{file_path}\').Status -eq \'Valid\'"'
            # Increased timeout and catch TimeoutExpired
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=30)
            if result.returncode == 0 and "True" in result.stdout:
                return True
            return False
        except subprocess.TimeoutExpired:
            self.logger.logger.warning(f"Timeout checking signature for {file_path}")
            return None
        except Exception as e:
            self.logger.logger.warning(f"Could not verify signature for {file_path}: {e}")
            return None

    def get_file_metadata(self, file_path):
        """Extract file metadata and hash"""
        try:
            stat = os.stat(file_path)
            path_obj = Path(file_path)

            metadata = {
                'path': str(file_path),
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime), # Keep as datetime object internally
                'is_signed': self.is_digitally_signed(file_path),
                'extension': path_obj.suffix.lower(),
                'filename': path_obj.name
            }

            # Calculate file hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()
                for chunk in iter(lambda: f.read(4096), b""):
                    file_hash.update(chunk)
                metadata['sha256'] = file_hash.hexdigest()

            return metadata
        except Exception as e:
            self.logger.logger.error(f"Error getting metadata for {file_path}: {e}")
            return None

    def is_suspicious_location(self, dll_path):
        """Check if DLL is in a suspicious user location"""
        path_str = str(dll_path).lower()

        # Suspicious user locations
        suspicious_indicators = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
            '\\users\\public\\', '\\programdata\\temp\\',
            '\\windows\\temp\\', '\\$recycle.bin\\',
            '\\downloads\\', '\\desktop\\'
        ]

        return any(indicator in path_str for indicator in suspicious_indicators)

    def analyze_dll_content(self, dll_path):
        """Analyze DLL content for suspicious patterns"""
        suspicious_patterns = []
        try:
            with open(dll_path, 'rb') as f:
                content = f.read(8192)  # Read first 8KB
                content_str = content.decode('latin-1', errors='ignore').lower()

                for indicator in self.suspicious_content_patterns:
                    if indicator in content_str:
                        suspicious_patterns.append(indicator)
        except Exception as e:
             self.logger.logger.warning(f"Could not analyze content for {dll_path}: {e}")
        return suspicious_patterns

    def calculate_risk_score(self, metadata, content_patterns, location_suspicious):
        """Calculate risk score for a DLL"""
        risk_score = 0

        # Unsigned file increases risk
        if metadata['is_signed'] is False:
            risk_score += 40
        elif metadata['is_signed'] is None:
            risk_score += 20

        # Location check
        if location_suspicious:
            risk_score += 30

        # Content patterns
        risk_score += len(content_patterns) * 10

        # File age (newer files are more suspicious)
        # metadata['modified'] is a datetime object
        file_age = datetime.now() - metadata['modified']
        if file_age < timedelta(hours=1):
            risk_score += 25
        elif file_age < timedelta(days=1):
            risk_score += 15

        # Unusual file size
        size = metadata['size']
        if size < 10000 or size > 50000000:  # < 10KB or > 50MB
            risk_score += 10

        return risk_score

    def delete_dll(self, dll_path, metadata, risk_score, risk_factors):
        """Permanently delete a suspicious DLL"""
        try:
            dll_path_obj = Path(dll_path)

            # Log deletion details (ensure metadata is serializable for logging)
            log_metadata = self.logger._make_serializable(metadata.copy())

            deletion_log = {
                'deleted_path': str(dll_path),
                'timestamp': datetime.now().isoformat(),
                'risk_score': risk_score,
                'risk_factors': risk_factors,
                'metadata': log_metadata
            }

            # Delete the file
            dll_path_obj.unlink()
            self.logger.log_action("DLL_DELETED", deletion_log)
            print(f"  Deleted: {dll_path}") # Print to console immediately
            return True
        except PermissionError as e:
            self.logger.logger.error(f"Permission denied deleting {dll_path}: {e}")
            print(f"  Failed (Permission): {dll_path}")
            return False
        except Exception as e:
            self.logger.logger.error(f"Failed to delete {dll_path}: {e}")
            print(f"  Failed (Error): {dll_path}")
            return False

    def scan_and_delete_suspicious_dlls(self, risk_threshold=50):
        """Scan user directories and delete suspicious DLLs"""
        self.logger.logger.info(f"Starting DLL scan in user directories with risk threshold: {risk_threshold}")

        scan_results = {
            'scanned': 0,
            'deleted': 0,
            'suspicious': 0,
            'errors': 0
        }

        for scan_path in self.scan_paths:
            if not os.path.exists(scan_path):
                self.logger.logger.warning(f"Scan path does not exist: {scan_path}")
                continue

            self.logger.logger.info(f"Scanning directory: {scan_path}")

            try:
                # Walk through the directory tree
                for root, dirs, files in os.walk(scan_path):
                    # Skip Windows system directories
                    if any(sys_dir in root.lower() for sys_dir in ['\\windows\\system32\\', '\\windows\\syswow64\\']):
                        continue

                    for file in files:
                        if file.lower().endswith('.dll'):
                            dll_path = os.path.join(root, file)

                            try:
                                scan_results['scanned'] += 1

                                # Skip if already processed in this run
                                # Note: cache is reset each full scan cycle
                                # if dll_path in self.suspicious_dll_cache:
                                #     continue

                                # Get metadata
                                metadata = self.get_file_metadata(dll_path)
                                if not metadata:
                                    scan_results['errors'] += 1
                                    continue

                                # Check location and content
                                location_suspicious = self.is_suspicious_location(dll_path)
                                content_patterns = self.analyze_dll_content(dll_path)

                                # Calculate risk
                                risk_score = self.calculate_risk_score(
                                    metadata, content_patterns, location_suspicious
                                )

                                if risk_score >= risk_threshold:
                                    scan_results['suspicious'] += 1
                                    risk_factors = []

                                    if metadata['is_signed'] is False:
                                        risk_factors.append("unsigned")
                                    if location_suspicious:
                                        risk_factors.append("suspicious_location")
                                    if content_patterns:
                                        risk_factors.extend([f"pattern_{p}" for p in content_patterns[:3]])

                                    # Delete the suspicious DLL
                                    if self.delete_dll(dll_path, metadata, risk_score, risk_factors):
                                        scan_results['deleted'] += 1
                                        # self.suspicious_dll_cache.add(dll_path) # Add if caching per run

                                # Progress update (more frequent for continuous mode feedback)
                                if scan_results['scanned'] % 50 == 0:
                                    self.logger.logger.info(f"Scanned {scan_results['scanned']} DLLs so far...")

                            except Exception as e:
                                scan_results['errors'] += 1
                                self.logger.logger.error(f"Error scanning {dll_path}: {e}")

            except Exception as e:
                self.logger.logger.error(f"Error scanning directory {scan_path}: {e}")

        self.logger.logger.info(f"DLL scan cycle completed: {scan_results}")
        return scan_results

def main():
    """Main entry point for continuous scanning"""
    print("User Directory DLL Scanner & Remover - Continuous Mode")
    print("=" * 55)
    print("Press Ctrl+C to stop the scanner.")

    # Setup
    logger = SecurityLogger()
    scanner = DLLSecurityScanner(logger)

    scan_interval_seconds = 2

    try:
        while True:
            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting scan cycle...")
            # Scan and delete suspicious DLLs
            results = scanner.scan_and_delete_suspicious_dlls(risk_threshold=50)

            print(f"Scan Cycle Results:")
            print(f"  Scanned: {results['scanned']} DLLs")
            print(f"  Suspicious: {results['suspicious']} DLLs")
            print(f"  Deleted: {results['deleted']} DLLs")
            print(f"  Errors: {results['errors']}")
            print(f"Waiting {scan_interval_seconds} seconds before next scan...")

            # Wait before the next scan cycle
            time.sleep(scan_interval_seconds)

    except KeyboardInterrupt:
        print("\nReceived interrupt signal. Shutting down...")
        logger.logger.info("Scanner stopped by user.")
    except Exception as e:
        logger.logger.critical(f"Scanner crashed unexpectedly: {e}")
        print(f"\nScanner encountered a critical error and stopped: {e}")


if __name__ == "__main__":
    main()