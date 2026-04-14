# nmap_logger.py
# Utility module for logging all nmap commands and their results to data/logs/nmap.log

import os
import subprocess
import logging
from datetime import datetime
from typing import List, Optional, Union
import threading

class NmapLogger:
    """
    Centralized logger for all nmap operations in Ragnar.
    Ensures all nmap commands and their results are logged to data/logs/nmap.log
    """
    
    def __init__(self, log_file: str = None):
        # Default to data/logs/nmap.log in the project directory
        if log_file is None:
            project_root = os.path.dirname(os.path.abspath(__file__))
            log_file = os.path.join(project_root, 'data', 'logs', 'nmap.log')
        self.log_file = log_file
        self.lock = threading.Lock()
        self._ensure_log_directory()
        self._setup_logger()
    
    def _ensure_log_directory(self):
        """Ensure the log directory exists"""
        log_dir = os.path.dirname(self.log_file)
        os.makedirs(log_dir, exist_ok=True)
    
    def _setup_logger(self):
        """Setup the logger for nmap operations"""
        self.logger = logging.getLogger('nmap_operations')
        self.logger.setLevel(logging.INFO)
        
        # Remove existing handlers to avoid duplicates
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Create file handler
        handler = logging.FileHandler(self.log_file, mode='a')
        formatter = logging.Formatter(
            '%(asctime)s - NMAP - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def log_command(self, command: List[str], context: str = ""):
        """Log an nmap command before execution"""
        with self.lock:
            command_str = ' '.join(command)
            context_str = f" ({context})" if context else ""
            self.logger.info(f"COMMAND{context_str}: {command_str}")
    
    def log_result(self, stdout: str, stderr: str, returncode: int, context: str = ""):
        """Log the result of an nmap command"""
        with self.lock:
            context_str = f" ({context})" if context else ""
            
            self.logger.info(f"RESULT{context_str}: Return code: {returncode}")
            
            if stdout:
                self.logger.info(f"STDOUT{context_str}:")
                for line in stdout.strip().split('\n'):
                    if line.strip():
                        self.logger.info(f"  {line}")
            
            if stderr:
                self.logger.warning(f"STDERR{context_str}:")
                for line in stderr.strip().split('\n'):
                    if line.strip():
                        self.logger.warning(f"  {line}")
    
    def log_scan_operation(self, operation: str, details: str = ""):
        """Log a general nmap scan operation"""
        with self.lock:
            details_str = f" - {details}" if details else ""
            self.logger.info(f"OPERATION: {operation}{details_str}")
    
    def run_nmap_command(self, command: List[str], context: str = "", **kwargs) -> subprocess.CompletedProcess:
        """
        Run an nmap command and log both the command and its results
        
        Args:
            command: List of command arguments (should start with 'nmap')
            context: Additional context for logging
            **kwargs: Additional arguments to pass to subprocess.run
        
        Returns:
            subprocess.CompletedProcess object
        """
        # Ensure we're dealing with an nmap command
        if not command or command[0] != 'nmap':
            raise ValueError("Command must start with 'nmap'")
        
        # Log the command
        self.log_command(command, context)
        
        # Set default kwargs for subprocess.run
        run_kwargs = {
            'capture_output': True,
            'text': True,
            **kwargs
        }
        
        try:
            # Execute the command
            result = subprocess.run(command, **run_kwargs)
            
            # Log the result
            self.log_result(result.stdout, result.stderr, result.returncode, context)
            
            return result
            
        except Exception as e:
            # Log the exception
            with self.lock:
                context_str = f" ({context})" if context else ""
                self.logger.error(f"EXCEPTION{context_str}: {str(e)}")
            raise

# Global instance for use throughout Ragnar
nmap_logger = NmapLogger()