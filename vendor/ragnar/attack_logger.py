"""
attack_logger.py - Utility for logging attack outputs to the /api/attack endpoint

This module provides a simple interface for attack actions to log their outputs
to a centralized attack log system accessible via the web API.
"""

import json
import requests
from datetime import datetime
from logger import Logger
import logging

# Configure logger
logger = Logger(name="attack_logger.py", level=logging.DEBUG)


class AttackLogger:
    """
    Utility class for logging attack outputs to the centralized attack log system.
    """
    
    def __init__(self, api_base_url="http://localhost:8000"):
        """
        Initialize the attack logger.
        
        Args:
            api_base_url: Base URL of the Flask API (default: http://localhost:8000)
        """
        self.api_base_url = api_base_url.rstrip('/')
        self.endpoint = f"{self.api_base_url}/api/attack"
    
    def log_attack(self, attack_type, target_ip, target_port='', status='unknown', 
                   message='', details=None):
        """
        Log an attack output to the centralized system.
        
        Args:
            attack_type: Type of attack (e.g., 'SSHBruteforce', 'FTPBruteforce', 'SQLConnector')
            target_ip: IP address of the target
            target_port: Port number (optional)
            status: Attack status - 'success', 'failed', or 'timeout'
            message: Human-readable message describing the attack result
            details: Dictionary containing additional attack details (credentials, files, etc.)
        
        Returns:
            bool: True if logged successfully, False otherwise
        """
        try:
            # Prepare log data
            log_data = {
                'attack_type': attack_type,
                'target_ip': target_ip,
                'target_port': str(target_port) if target_port else '',
                'status': status,
                'message': message,
                'details': details if details else {},
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Send POST request to API endpoint
            response = requests.post(
                self.endpoint,
                json=log_data,
                timeout=5
            )
            
            if response.status_code == 201:
                logger.debug(f"Attack logged successfully: {attack_type} on {target_ip}")
                return True
            else:
                logger.warning(f"Failed to log attack: HTTP {response.status_code}")
                return False
                
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout while logging attack for {target_ip}")
            return False
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error while logging attack - API may not be running")
            return False
        except Exception as e:
            logger.error(f"Error logging attack: {e}")
            return False
    
    def log_success(self, attack_type, target_ip, target_port='', message='', **details):
        """
        Log a successful attack.
        
        Args:
            attack_type: Type of attack
            target_ip: Target IP address
            target_port: Target port (optional)
            message: Success message
            **details: Additional details as keyword arguments
        """
        return self.log_attack(
            attack_type=attack_type,
            target_ip=target_ip,
            target_port=target_port,
            status='success',
            message=message,
            details=details
        )
    
    def log_failure(self, attack_type, target_ip, target_port='', message='', **details):
        """
        Log a failed attack.
        
        Args:
            attack_type: Type of attack
            target_ip: Target IP address
            target_port: Target port (optional)
            message: Failure message
            **details: Additional details as keyword arguments
        """
        return self.log_attack(
            attack_type=attack_type,
            target_ip=target_ip,
            target_port=target_port,
            status='failed',
            message=message,
            details=details
        )
    
    def log_timeout(self, attack_type, target_ip, target_port='', message='', **details):
        """
        Log an attack timeout.
        
        Args:
            attack_type: Type of attack
            target_ip: Target IP address
            target_port: Target port (optional)
            message: Timeout message
            **details: Additional details as keyword arguments
        """
        return self.log_attack(
            attack_type=attack_type,
            target_ip=target_ip,
            target_port=target_port,
            status='timeout',
            message=message,
            details=details
        )
    
    def get_attack_logs(self, ip=None, attack_type=None, status=None, limit=100, days=7):
        """
        Retrieve attack logs with optional filtering.
        
        Args:
            ip: Filter by target IP (optional)
            attack_type: Filter by attack type (optional)
            status: Filter by status (optional)
            limit: Maximum number of logs to retrieve
            days: Number of days to look back
        
        Returns:
            dict: Response containing attack logs and statistics
        """
        try:
            params = {
                'limit': limit,
                'days': days
            }
            
            if ip:
                params['ip'] = ip
            if attack_type:
                params['type'] = attack_type
            if status:
                params['status'] = status
            
            response = requests.get(
                self.endpoint,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Failed to retrieve attack logs: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error retrieving attack logs: {e}")
            return None


# Example usage in attack actions:
"""
# At the top of your attack action file (e.g., ssh_connector.py):
from attack_logger import AttackLogger

# In your class __init__:
self.attack_logger = AttackLogger()

# When an attack succeeds:
self.attack_logger.log_success(
    attack_type='SSHBruteforce',
    target_ip=ip,
    target_port=port,
    message=f'Successfully authenticated as {username}',
    username=username,
    password=password,
    attempts=attempt_count
)

# When an attack fails:
self.attack_logger.log_failure(
    attack_type='SSHBruteforce',
    target_ip=ip,
    target_port=port,
    message='All credential combinations failed',
    attempts_made=total_attempts
)

# When an attack times out:
self.attack_logger.log_timeout(
    attack_type='SSHBruteforce',
    target_ip=ip,
    target_port=port,
    message='Connection timed out after 300 seconds'
)
"""
