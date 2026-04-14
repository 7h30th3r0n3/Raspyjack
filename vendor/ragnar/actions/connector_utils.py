"""
connector_utils.py - Utility functions for optimizing connector actions.
This module provides shared functionality for credential checking and file tracking
across different protocol connectors (SSH, FTP, SMB, RDP, Telnet, SQL).
"""

import os
import json
import logging
from datetime import datetime
from logger import Logger

# Helper modules should not be registered as runnable actions
BYPASS_ACTION_MODULE = True

logger = Logger(name="connector_utils.py", level=logging.DEBUG)


class CredentialChecker:
    """Helper class to check and verify existing credentials before bruteforcing."""
    
    @staticmethod
    def check_existing_credentials(credentials_file, ip):
        """
        Check if credentials already exist for the given IP.
        
        Args:
            credentials_file: Path to the CSV file containing credentials
            ip: IP address to check
            
        Returns:
            List of (username, password) tuples, or None if no credentials exist
        """
        if not os.path.exists(credentials_file):
            return None
        
        credentials = []
        try:
            with open(credentials_file, 'r') as f:
                lines = f.readlines()[1:]  # Skip header
                for line in lines:
                    parts = line.strip().split(',')
                    if len(parts) >= 5 and parts[1] == ip:
                        credentials.append((parts[3], parts[4]))  # (user, password)
        except Exception as e:
            logger.warning(f"Error reading existing credentials from {credentials_file}: {e}")
            return None
        
        return credentials if credentials else None


class FileTracker:
    """Helper class to track stolen files and avoid re-downloading."""
    
    def __init__(self, protocol, datadir):
        """
        Initialize the file tracker.
        
        Args:
            protocol: Protocol name (ssh, ftp, smb, rdp, telnet)
            datadir: Data directory for storing tracking files
        """
        self.protocol = protocol
        self.db_file = os.path.join(datadir, f'stolen_files_{protocol}.json')
        self.stolen_files = {}
        self._load_db()
    
    def _load_db(self):
        """Load the database of already stolen files."""
        try:
            if os.path.exists(self.db_file):
                with open(self.db_file, 'r') as f:
                    self.stolen_files = json.load(f)
            else:
                self.stolen_files = {}
        except Exception as e:
            logger.warning(f"Could not load stolen files database for {self.protocol}: {e}")
            self.stolen_files = {}
    
    def _save_db(self):
        """Save the database of stolen files."""
        try:
            with open(self.db_file, 'w') as f:
                json.dump(self.stolen_files, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save stolen files database for {self.protocol}: {e}")
    
    def is_file_stolen(self, ip, remote_file):
        """
        Check if a file has already been stolen from this host.
        
        Args:
            ip: IP address of the host
            remote_file: Path to the remote file
            
        Returns:
            True if file was already stolen, False otherwise
        """
        if ip not in self.stolen_files:
            return False
        return remote_file in self.stolen_files[ip]
    
    def mark_file_stolen(self, ip, remote_file):
        """
        Mark a file as stolen.
        
        Args:
            ip: IP address of the host
            remote_file: Path to the remote file
        """
        if ip not in self.stolen_files:
            self.stolen_files[ip] = []
        if remote_file not in self.stolen_files[ip]:
            self.stolen_files[ip].append(remote_file)
            self._save_db()
    
    def filter_new_files(self, ip, file_list):
        """
        Filter a list of files to only include files not yet stolen.
        
        Args:
            ip: IP address of the host
            file_list: List of file paths
            
        Returns:
            Tuple of (new_files, already_stolen_count)
        """
        new_files = [f for f in file_list if not self.is_file_stolen(ip, f)]
        already_stolen_count = len(file_list) - len(new_files)
        return new_files, already_stolen_count


class TimestampTracker:
    """Helper class to track action timestamps and enforce minimum intervals."""
    
    def __init__(self, action_name, datadir, interval_hours=24):
        """
        Initialize the timestamp tracker.
        
        Args:
            action_name: Name of the action (e.g., 'lynis_pentest')
            datadir: Data directory for storing tracking files
            interval_hours: Minimum hours between executions
        """
        self.action_name = action_name
        self.interval_hours = interval_hours
        self.db_file = os.path.join(datadir, f'{action_name}_timestamps.json')
        self.timestamps = {}
        self._load_db()
    
    def _load_db(self):
        """Load the database of timestamps."""
        try:
            if os.path.exists(self.db_file):
                with open(self.db_file, 'r') as f:
                    self.timestamps = json.load(f)
            else:
                self.timestamps = {}
        except Exception as e:
            logger.warning(f"Could not load timestamps for {self.action_name}: {e}")
            self.timestamps = {}
    
    def _save_db(self):
        """Save the database of timestamps."""
        try:
            with open(self.db_file, 'w') as f:
                json.dump(self.timestamps, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save timestamps for {self.action_name}: {e}")
    
    def should_run(self, ip):
        """
        Check if the action should run based on last run time.
        
        Args:
            ip: IP address of the host
            
        Returns:
            Tuple of (should_run: bool, reason: str)
        """
        if ip not in self.timestamps:
            return True, "Never run before"
        
        try:
            last_run = datetime.fromisoformat(self.timestamps[ip])
            time_since_last = datetime.utcnow() - last_run
            hours_since = time_since_last.total_seconds() / 3600
            
            if hours_since >= self.interval_hours:
                return True, f"Last run {hours_since:.1f} hours ago"
            else:
                hours_remaining = self.interval_hours - hours_since
                return False, f"Last run {hours_since:.1f} hours ago, retry in {hours_remaining:.1f} hours"
        except Exception as e:
            logger.warning(f"Error parsing timestamp for {ip}: {e}")
            return True, "Invalid timestamp"
    
    def mark_run(self, ip):
        """
        Mark the action as run for the given IP.
        
        Args:
            ip: IP address of the host
        """
        self.timestamps[ip] = datetime.utcnow().isoformat()
        self._save_db()
