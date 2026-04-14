# orchestrator.py
# Description:
# This file, orchestrator.py, is the heuristic Ragnar brain, and it is responsible for coordinating and executing various network scanning and offensive security actions 
# It manages the loading and execution of actions, handles retries for failed and successful actions, 
# and updates the status of the orchestrator.
#
#
# Key functionalities include:
# - Initializing and loading actions from a configuration file, including network and vulnerability scanners.
# - Managing the execution of actions on network targets, checking for open ports and handling retries based on success or failure.
# - Coordinating the execution of parent and child actions, ensuring actions are executed in a logical order.
# - Running the orchestrator cycle to continuously check for and execute actions on available network targets.
# - Handling and updating the status of the orchestrator, including scanning for new targets and performing vulnerability scans.
# - Implementing threading to manage concurrent execution of actions with a semaphore to limit active threads.
# - Logging events and errors to ensure maintainability and ease of debugging.
# - Handling graceful degradation by managing retries and idle states when no new targets are found.

# VERSION: 11:23:21:00 - PERFORMANCE: Pre-filter hosts by port BEFORE semaphore (eliminates 100s of unnecessary lock acquisitions)
ORCHESTRATOR_VERSION = "11:23:21:00"

import json
import importlib
import os
import time
import logging
import sys
import threading
import re
from datetime import datetime, timedelta
try:
    from actions.nmap_vuln_scanner import NmapVulnScanner
except ImportError:
    NmapVulnScanner = None
from init_shared import shared_data
from logger import Logger
from resource_monitor import resource_monitor

logger = Logger(name="orchestrator.py", level=logging.DEBUG)

class Orchestrator:
    def __init__(self):
        """Initialise the orchestrator"""
        self.shared_data = shared_data
        self.actions = []  # List of actions to be executed
        self.standalone_actions = []  # List of standalone actions to be executed
        self.failed_scans_count = 0  # Count the number of failed scans
        self.network_scanner = None
        self.nmap_vuln_scanner = None
        self.last_vuln_scan_time = datetime.min  # Set the last vulnerability scan time to the minimum datetime value
        
        # Verify critical configuration attributes exist
        self._verify_config_attributes()
        
        self.load_actions()  # Load all actions from the actions file
        actions_loaded = [action.__class__.__name__ for action in self.actions + self.standalone_actions]  # Get the names of the loaded actions
        logger.info(f"Actions loaded: {actions_loaded}")
        
        # CRITICAL: Pi Zero W2 resource management - limit concurrent actions
        # Running too many actions simultaneously causes memory exhaustion and hangs
        # REDUCED to 1 to prevent OOM kills during AI + scanning + display updates
        self.semaphore = threading.Semaphore(1)  # Max 1 concurrent action for Pi Zero W2
        
        # No longer using ThreadPoolExecutor - direct threading is more reliable
        # and avoids "cannot schedule new futures after interpreter shutdown" errors
        
        # Default timeout for action execution (in seconds)
        self.action_timeout = getattr(self.shared_data, 'action_timeout', 300)  # 5 minutes default
        self.vuln_scan_timeout = getattr(self.shared_data, 'vuln_scan_timeout', 1800)  # 30 minutes for vuln scans
    
    def _verify_config_attributes(self):
        """Verify that all required configuration attributes exist on shared_data."""
        required_attrs = {
            'retry_success_actions': True,
            'retry_failed_actions': True,
            'success_retry_delay': 300,
            'failed_retry_delay': 180,
            'scan_vuln_running': True,
            'scan_vuln_no_ports': True,  # Enable scanning hosts without discovered ports
            'enable_attacks': True,
            'scan_vuln_interval': 300,
            'scan_interval': 180,
            'action_timeout': 300,  # 5 minutes default for actions
            'vuln_scan_timeout': 1800  # 30 minutes for vulnerability scans
        }
        
        for attr, default_value in required_attrs.items():
            if not hasattr(self.shared_data, attr):
                logger.warning(f"Missing config attribute '{attr}', setting default value: {default_value}")
                setattr(self.shared_data, attr, default_value)

    def _should_retry(self, action_key, row, status_type='success', custom_delay_seconds=None):
        """
        Check if an action should be retried based on its status and retry configuration.
        
        Args:
            action_key: The action name/key to check
            row: The data row containing action status
            status_type: Either 'success' or 'failed'
            custom_delay_seconds: Optional custom delay in seconds (overrides config values)
                                  Use this for special cases like 24-hour vuln scan delays
            
        Returns:
            tuple: (should_retry: bool, reason: str or None)
                   - (True, None) if action should proceed
                   - (False, reason_string) if action should be skipped with reason
        """
        action_status = row.get(action_key, "")
        
        if status_type == 'success':
            if 'success' not in action_status:
                return (True, None)
            
            retry_enabled = getattr(self.shared_data, 'retry_success_actions', True)
            if not retry_enabled:
                return (False, "success retry disabled")
            
            # Use custom delay if provided, otherwise use config value
            delay = custom_delay_seconds if custom_delay_seconds is not None else getattr(self.shared_data, 'success_retry_delay', 300)
            status_prefix = 'success'
        elif status_type == 'failed':
            if 'failed' not in action_status:
                return (True, None)
            
            retry_enabled = getattr(self.shared_data, 'retry_failed_actions', True)
            if not retry_enabled:
                return (False, "failed retry disabled")
            
            # Use custom delay if provided, otherwise use config value
            delay = custom_delay_seconds if custom_delay_seconds is not None else getattr(self.shared_data, 'failed_retry_delay', 180)
            status_prefix = 'failed'
        else:
            logger.error(f"Invalid status_type: {status_type}")
            return (True, None)
        
        # Parse timestamp from status string (format: status_YYYYMMDD_HHMMSS)
        try:
            parts = action_status.split('_')
            if len(parts) >= 3:
                timestamp_str = f"{parts[1]}_{parts[2]}"
                last_time = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                
                retry_time = last_time + timedelta(seconds=delay)
                if datetime.now() < retry_time:
                    retry_in_seconds = (retry_time - datetime.now()).seconds
                    formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                    return (False, f"{status_prefix} retry delay, retry possible in: {formatted_retry_in}")
        except (ValueError, IndexError) as e:
            logger.warning(f"Error parsing timestamp for {action_key}: {e}")
            # If we can't parse timestamp, allow retry
            return (True, None)
        
        return (True, None)
    
    def _update_action_status(self, row, action_key, result):
        """
        Update action status with timestamp.
        
        Args:
            row: The data row to update
            action_key: The action name/key
            result: 'success' or 'failed'
            
        Returns:
            str: The formatted status string
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        status = f"{result}_{timestamp}"
        row[action_key] = status
        return status
    
    def _execute_with_timeout(self, action_callable, timeout, action_name="unknown"):
        """
        Execute an action with a timeout to prevent hanging.
        Uses direct threading instead of ThreadPoolExecutor to avoid executor shutdown issues.
        
        Args:
            action_callable: Callable that executes the action
            timeout: Maximum execution time in seconds
            action_name: Name of the action for logging
            
        Returns:
            str: 'success', 'failed', or 'timeout'
        """
        result_container = {'result': None, 'exception': None, 'completed': False}
        
        def run_action():
            try:
                result_container['result'] = action_callable()
                result_container['completed'] = True
            except Exception as e:
                result_container['exception'] = e
                result_container['completed'] = True
        
        # Run action in separate thread
        action_thread = threading.Thread(target=run_action, name=f"Action_{action_name}")
        action_thread.daemon = True
        action_thread.start()
        
        # Wait for completion with timeout
        action_thread.join(timeout=timeout)
        
        if not result_container['completed']:
            logger.error(f"Action {action_name} timed out after {timeout} seconds")
            return 'timeout'
        
        if result_container['exception']:
            logger.error(f"Action {action_name} raised exception: {result_container['exception']}")
            return 'failed'
        
        return result_container['result'] if result_container['result'] else 'failed'

    def load_actions(self):
        """Load all actions from the actions file"""
        self.actions_dir = self.shared_data.actions_dir
        
        # Check if actions file exists
        if not os.path.exists(self.shared_data.actions_file):
            logger.error(f"Actions file not found at {self.shared_data.actions_file}")
            logger.error("Cannot load actions. Orchestrator may not function properly.")
            return
            
        try:
            with open(self.shared_data.actions_file, 'r') as file:
                actions_config = json.load(file)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse actions file: {e}")
            return
        except Exception as e:
            logger.error(f"Error reading actions file: {e}")
            return
            
        for action in actions_config:
            module_name = action.get("b_module")
            if not module_name:
                logger.warning(f"Action missing b_module field: {action}")
                continue
                
            try:
                if module_name == 'scanning':
                    self.load_scanner(module_name)
                elif module_name == 'nmap_vuln_scanner':
                    self.load_nmap_vuln_scanner(module_name)
                else:
                    self.load_action(module_name, action)
            except Exception as e:
                logger.error(f"Failed to load action {module_name}: {e}")

    def load_scanner(self, module_name):
        """Load the network scanner"""
        try:
            module = importlib.import_module(f'actions.{module_name}')
            b_class = getattr(module, 'b_class', None)
            if not b_class:
                logger.error(f"Module {module_name} missing 'b_class' attribute")
                return
            self.network_scanner = getattr(module, b_class)(self.shared_data)
            logger.info(f"Network scanner {b_class} loaded successfully")
        except ImportError as e:
            logger.error(f"Failed to import scanner module {module_name}: {e}")
        except Exception as e:
            logger.error(f"Error loading scanner {module_name}: {e}")

    def load_nmap_vuln_scanner(self, module_name):
        """Load the nmap vulnerability scanner"""
        try:
            if NmapVulnScanner is None:
                logger.warning("NmapVulnScanner not available (missing pandas/rich) - skipping")
                return
            self.nmap_vuln_scanner = NmapVulnScanner(self.shared_data)
            logger.info("Nmap vulnerability scanner loaded successfully")
        except Exception as e:
            logger.error(f"Error loading nmap vulnerability scanner: {e}")
            self.nmap_vuln_scanner = None

    def load_action(self, module_name, action):
        """Load an action from the actions file"""
        module = importlib.import_module(f'actions.{module_name}')
        try:
            b_class = action["b_class"]
            action_instance = getattr(module, b_class)(self.shared_data)
            action_instance.action_name = b_class
            action_instance.port = action.get("b_port")
            action_instance.b_parent_action = action.get("b_parent")
            # Standalone actions have port == 0, None, or empty string
            if action_instance.port in (0, None, '', '0'):
                self.standalone_actions.append(action_instance)
                logger.debug(f"Loaded {b_class} as standalone action (port={action_instance.port})")
            else:
                self.actions.append(action_instance)
                logger.debug(f"Loaded {b_class} as regular action (port={action_instance.port})")
        except AttributeError as e:
            logger.error(f"Module {module_name} is missing required attributes: {e}")

    def process_alive_ips(self, current_data):
        """Process all IPs with alive status set to 1"""
        any_action_executed = False
        action_executed_status = None
        
        # Debug: Log what we're processing
        alive_hosts = [row for row in current_data if row.get("Alive") == '1']
        logger.debug(f"Processing {len(alive_hosts)} alive hosts out of {len(current_data)} total hosts")
        logger.debug(f"Available actions: {len(self.actions)} (parent+child actions)")
        
        if not alive_hosts:
            logger.warning("No alive hosts to process - all hosts have Alive != '1'")
            return False
        
        if not self.actions:
            logger.warning("No actions loaded - check actions.json configuration")
            return False

        # Process all parent actions (those without dependencies) across ALL hosts
        for action in self.actions:
            if action.b_parent_action is None:
                action_key = action.action_name
                required_port = getattr(action, 'port', None)
                
                # Pre-filter hosts by port requirement (FAST - no semaphore needed)
                for row in current_data:
                    if row["Alive"] != '1':
                        continue
                    
                    ip = row["IPs"]
                    ports = self._extract_ports(row)
                    
                    # OPTIMIZATION: Check port requirement BEFORE acquiring semaphore
                    # This prevents serializing hundreds of "port not found" checks
                    if required_port not in (None, '', 0, '0'):
                        required_port_str = str(required_port).strip().split('/')[0]
                        ports_normalized = [str(p).strip().split('/')[0] for p in ports]
                        
                        if required_port_str not in ports_normalized:
                            # Skip silently - port not available (no semaphore needed)
                            continue
                    
                    # MEMORY CHECK: Prevent OOM kills
                    if not resource_monitor.can_start_operation(f"action_{action_key}", min_memory_mb=30):
                        logger.warning(f"Insufficient memory to execute {action_key}, skipping to prevent OOM")
                        continue
                    
                    # Only acquire semaphore when we actually need to execute
                    with self.semaphore:
                        if self.execute_action(action, ip, ports, row, action_key, current_data):
                            action_executed_status = action_key
                            any_action_executed = True
                            self.shared_data.ragnarorch_status = action_executed_status
                            
                            # After parent succeeds, immediately try child actions on same host
                            # Note: Already within semaphore context, no need to re-acquire
                            for child_action in self.actions:
                                if child_action.b_parent_action == action_key:
                                    if self.execute_action(child_action, ip, ports, row, child_action.action_name, current_data):
                                        action_executed_status = child_action.action_name
                                        self.shared_data.ragnarorch_status = action_executed_status
                    
                    # Continue processing remaining hosts for this action

        # Process all child actions (those with parent dependencies) across ALL hosts
        for child_action in self.actions:
            if child_action.b_parent_action:
                action_key = child_action.action_name
                required_port = getattr(child_action, 'port', None)
                
                for row in current_data:
                    if row["Alive"] != '1':
                        continue
                    
                    ip = row["IPs"]
                    ports = self._extract_ports(row)
                    
                    # OPTIMIZATION: Check port requirement BEFORE acquiring semaphore
                    # This prevents serializing hundreds of "port not found" checks
                    if required_port not in (None, '', 0, '0'):
                        required_port_str = str(required_port).strip().split('/')[0]
                        ports_normalized = [str(p).strip().split('/')[0] for p in ports]
                        
                        if required_port_str not in ports_normalized:
                            # Skip silently - port not available (no semaphore/logging overhead)
                            continue
                    
                    # MEMORY CHECK: Prevent OOM kills
                    if not resource_monitor.can_start_operation(f"child_action_{action_key}", min_memory_mb=30):
                        logger.warning(f"Insufficient memory to execute child {action_key}, skipping to prevent OOM")
                        continue
                    
                    # Only acquire semaphore when we actually need to execute
                    with self.semaphore:
                        if self.execute_action(child_action, ip, ports, row, action_key, current_data):
                            action_executed_status = child_action.action_name
                            any_action_executed = True
                            self.shared_data.ragnarorch_status = action_executed_status
                    
                    # Continue processing remaining hosts for this child action
        
        # Debug: Log summary if nothing executed
        if not any_action_executed:
            logger.debug(f"No actions executed on {len(alive_hosts)} alive hosts - all actions skipped (likely due to retry delays, missing ports, or disabled attacks)")

        return any_action_executed

    def _execute_network_scans(self, reason="cycle"):
        if not self.network_scanner:
            return
        multi_state = getattr(self.shared_data, 'multi_interface_state', None)
        if not multi_state:
            self.network_scanner.scan()
            return

        try:
            multi_state.refresh_from_system()
        except Exception as exc:
            logger.warning(f"Unable to refresh multi-interface state: {exc}")

        is_multi = multi_state.is_multi_mode_enabled()
        logger.info(f"[MULTI-SCAN] Mode check: is_multi={is_multi}, scan_mode={multi_state.get_scan_mode()}")
        
        if is_multi:
            jobs = multi_state.get_scan_jobs()
            logger.info(f"Multi-scan mode enabled, got {len(jobs)} scan jobs from {len(multi_state.interfaces)} interfaces")
            if not jobs:
                logger.info("Multi-network scanning enabled but no eligible interfaces detected - running default scan")
                self.network_scanner.scan()
                return

            for job in jobs:
                context_ssid = getattr(job, 'ssid', None)
                label = context_ssid or 'unknown'
                with self.shared_data.context_registry.activate(context_ssid):
                    self.shared_data.ragnarstatustext2 = f"{reason}: {label}"
                    logger.info(f"→ Running network scan on {job.interface} ({label})")
                    self.network_scanner.scan(job=job)
            self.shared_data.ragnarstatustext2 = ""
            return

        focus_job = multi_state.get_focus_job()
        if focus_job:
            focus_label = focus_job.ssid or focus_job.interface
            with self.shared_data.context_registry.activate(focus_job.ssid):
                self.shared_data.ragnarstatustext2 = f"{reason}: {focus_label}"
                logger.info(f"→ Running focused scan on {focus_job.interface} ({focus_label})")
                self.network_scanner.scan(job=focus_job)
            self.shared_data.ragnarstatustext2 = ""
            return

        # Check if ethernet should be the default scan interface
        preferred = multi_state.get_preferred_scan_interface()
        if preferred and preferred.get('type') == 'ethernet' and preferred.get('ip_address'):
            from multi_interface import ScanJob
            eth_job = ScanJob(
                interface=preferred['name'],
                ssid='LAN',
                role='ethernet',
                ip_address=preferred.get('ip_address'),
                cidr=preferred.get('cidr'),
                network_cidr=preferred.get('network_cidr'),
                interface_type='ethernet',
            )
            logger.info(f"→ Default scan using preferred ethernet: {preferred['name']}")
            self.network_scanner.scan(job=eth_job)
            return

        self.network_scanner.scan()

    def _iter_action_contexts(self):
        multi_state = getattr(self.shared_data, 'multi_interface_state', None)
        if not multi_state:
            yield self.shared_data.active_network_ssid
            return

        if multi_state.is_multi_mode_enabled():
            jobs = multi_state.get_scan_jobs()
            seen = set()
            if not jobs:
                yield self.shared_data.active_network_ssid
                return
            for job in jobs:
                ssid = getattr(job, 'ssid', None)
                if not ssid or ssid in seen:
                    continue
                seen.add(ssid)
                yield ssid
            return

        focus_job = multi_state.get_focus_job()
        if focus_job and focus_job.ssid:
            yield focus_job.ssid
            return

        yield self.shared_data.active_network_ssid


    def execute_action(self, action, ip, ports, row, action_key, current_data):
        """Execute an action on a target with timeout protection"""
        # NOTE: Port checking is now done BEFORE calling this method (performance optimization)
        # The caller pre-filters by port to avoid unnecessary semaphore acquisitions

        # Check if attacks are enabled (skip attack actions if disabled, but allow scanning)
        enable_attacks = getattr(self.shared_data, 'enable_attacks', True)
        attack_action_names = [
            'SSHBruteforce', 'FTPBruteforce', 'TelnetBruteforce', 
            'RDPBruteforce', 'SMBBruteforce', 'SQLBruteforce',
            'SSHConnector', 'FTPConnector', 'TelnetConnector', 
            'RDPConnector', 'SMBConnector', 'SQLConnector',
            'StealDataSQL', 'StealFilesFTP', 'StealFilesRDP', 
            'StealFilesSMB', 'StealFilesSSH', 'StealFilesTelnet'
        ]
        if not enable_attacks and action.action_name in attack_action_names:
            logger.debug(f"Skipping attack action {action.action_name} for {ip}:{action.port} - attacks are disabled")
            return False

        # Check parent action status
        if action.b_parent_action:
            parent_status = row.get(action.b_parent_action, "")
            if 'success' not in parent_status:
                return False  # Skip child action if parent action has not succeeded

        # Check success retry logic using helper
        should_retry, reason = self._should_retry(action_key, row, 'success')
        if not should_retry:
            logger.warning(f"Skipping action {action.action_name} for {ip}:{action.port} due to {reason}")
            return False

        # Check failed retry logic using helper
        should_retry, reason = self._should_retry(action_key, row, 'failed')
        if not should_retry:
            logger.warning(f"Skipping action {action.action_name} for {ip}:{action.port} due to {reason}")
            return False

        # CRITICAL: Check system resources before executing action (Pi Zero W2 protection)
        if not resource_monitor.can_start_operation(
            operation_name=f"action_{action.action_name}",
            min_memory_mb=30  # Require at least 30MB free memory
        ):
            logger.warning(
                f"Skipping action {action.action_name} for {ip}:{action.port} - "
                f"Insufficient system resources (preventing hang)"
            )
            return False

        try:
            logger.info(f"Executing action {action.action_name} for {ip}:{action.port}")
            self.shared_data.ragnarstatustext2 = ip
            
            # Execute action with timeout protection
            action_callable = lambda: action.execute(ip, str(action.port), row, action_key)
            result = self._execute_with_timeout(
                action_callable,
                timeout=self.action_timeout,
                action_name=f"{action.action_name}@{ip}:{action.port}"
            )
            
            # Update status using helper (timeout is treated as failed)
            if result == 'timeout':
                result_status = 'failed'
                logger.error(f"Action {action.action_name} for {ip}:{action.port} timed out")
            else:
                result_status = 'success' if result == 'success' else 'failed'
            
            self._update_action_status(row, action_key, result_status)
            
            if result == 'success':
                # Update stats immediately after successful action
                try:
                    self.shared_data.update_stats()
                    logger.debug(f"Updated stats after successful {action.action_name}")
                except Exception as stats_error:
                    logger.warning(f"Could not update stats: {stats_error}")
            
            # SQLite writes happen automatically in action modules - no CSV write needed
            # self.shared_data.write_data(current_data)
            return result == 'success'
        except Exception as e:
            logger.error(f"Action {action.action_name} failed: {e}")
            self._update_action_status(row, action_key, 'failed')
            # SQLite writes happen automatically in action modules - no CSV write needed
            # self.shared_data.write_data(current_data)
            return False

    @staticmethod
    def _extract_ports(row):
        """Return a sanitized list of ports extracted from a data row."""
        ports_field = row.get("Ports") or ""

        # Support multiple storage formats (list, tuple, CSV string, etc.)
        if isinstance(ports_field, (list, tuple, set)):
            raw_ports = ports_field
        else:
            normalized = str(ports_field).strip()
            if not normalized:
                return []

            # Remove artifacts like brackets and quotes produced by JSON/CSV dumps
            normalized = normalized.strip('[]')
            normalized = normalized.replace('"', '').replace("'", "")

            # Split on commas, semicolons, or whitespace
            raw_ports = re.split(r"[;,\s]+", normalized)

        sanitized_ports = []
        for port in raw_ports:
            if port is None:
                continue

            port_str = str(port).strip()
            if not port_str:
                continue

            # Remove protocol suffixes such as 22/tcp
            port_str = port_str.split('/')[0]

            try:
                port_num = int(port_str)
            except ValueError:
                continue

            if 0 < port_num <= 65535:
                sanitized_ports.append(str(port_num))

        return sanitized_ports

    def execute_standalone_action(self, action, current_data):
        """Execute a standalone action with timeout protection"""
        row = next((r for r in current_data if r["MAC Address"] == "STANDALONE"), None)
        if not row:
            row = {
                "MAC Address": "STANDALONE",
                "IPs": "STANDALONE",
                "Hostnames": "STANDALONE",
                "Ports": "0",
                "Alive": "0"
            }
            current_data.append(row)

        action_key = action.action_name
        if action_key not in row:
            row[action_key] = ""

        # Check success retry logic using helper
        should_retry, reason = self._should_retry(action_key, row, 'success')
        if not should_retry:
            logger.warning(f"Skipping standalone action {action.action_name} due to {reason}")
            return False

        # Check failed retry logic using helper
        should_retry, reason = self._should_retry(action_key, row, 'failed')
        if not should_retry:
            logger.warning(f"Skipping standalone action {action.action_name} due to {reason}")
            return False

        try:
            logger.info(f"Executing standalone action {action.action_name}")
            
            # Execute action with timeout protection
            action_callable = lambda: action.execute()
            result = self._execute_with_timeout(
                action_callable,
                timeout=self.action_timeout,
                action_name=f"standalone_{action.action_name}"
            )
            
            # Update status using helper (timeout is treated as failed)
            if result == 'timeout':
                result_status = 'failed'
                logger.error(f"Standalone action {action.action_name} timed out")
            else:
                result_status = 'success' if result == 'success' else 'failed'
            
            self._update_action_status(row, action_key, result_status)
            
            if result == 'success':
                logger.info(f"Standalone action {action.action_name} executed successfully")
                # Update stats immediately after successful standalone action
                try:
                    self.shared_data.update_stats()
                    logger.debug(f"Updated stats after successful standalone {action.action_name}")
                except Exception as stats_error:
                    logger.warning(f"Could not update stats: {stats_error}")
            else:
                logger.error(f"Standalone action {action.action_name} failed")
            
            # SQLite writes happen automatically in action modules - no CSV write needed
            # self.shared_data.write_data(current_data)
            return result == 'success'
        except Exception as e:
            logger.error(f"Standalone action {action.action_name} failed: {e}")
            self._update_action_status(row, action_key, 'failed')
            # SQLite writes happen automatically in action modules - no CSV write needed
            # self.shared_data.write_data(current_data)
            return False

    def run_vulnerability_scans(self, force=False):
        """
        Run vulnerability scans on all alive hosts with timeout protection.
        
        Implements 24-hour timestamp tracking to avoid re-scanning hosts within 24 hours.
        Each successful scan updates the timestamp, and subsequent scans check if 24 hours
        have elapsed before scanning again.
        
        Args:
            force: If True, bypass all retry delay checks including 24-hour window
                   (used for scheduled/startup scans)
        """
        scan_vuln_running = getattr(self.shared_data, 'scan_vuln_running', True)
        
        if not scan_vuln_running or not self.nmap_vuln_scanner:
            logger.warning("Vulnerability scanning disabled or scanner not available")
            return
            
        try:
            current_data = self.shared_data.read_data()
            alive_hosts = [row for row in current_data if row.get("Alive") == '1']
            
            if not alive_hosts:
                logger.warning("No alive hosts found for vulnerability scanning")
                return
                
            logger.info(f"🔍 Starting vulnerability scans on {len(alive_hosts)} alive hosts (force={force})...")
            scans_performed = 0
            scans_skipped = 0
            
            for row in alive_hosts:
                ip = row.get("IPs", "")
                if not ip or ip == "STANDALONE":
                    logger.debug(f"Skipping host with invalid IP: {ip!r}")
                    scans_skipped += 1
                    continue
                
                action_key = "NmapVulnScanner"
                hostname = row.get("Hostnames", "Unknown")
                
                # Initialize action_key if not present
                if action_key not in row:
                    row[action_key] = ""
                
                # CRITICAL: When force=True, SKIP ALL retry logic and scan everything
                if force:
                    logger.info(f"🎯 Force scan enabled - scanning {ip} ({hostname})")
                else:
                    # Only check retry logic if this is NOT a forced/scheduled scan
                    # For vulnerability scans, enforce 24-hour delay (86400 seconds) between successful scans
                    vuln_scan_delay_24h = 86400  # 24 hours in seconds
                    
                    # Check success retry logic with 24-hour delay
                    should_retry, reason = self._should_retry(action_key, row, 'success', custom_delay_seconds=vuln_scan_delay_24h)
                    if not should_retry:
                        logger.debug(f"Skipping {ip} ({hostname}): {reason}")
                        scans_skipped += 1
                        continue
                    
                    # Check failed retry logic using helper (use default failed_retry_delay for failures)
                    should_retry, reason = self._should_retry(action_key, row, 'failed')
                    if not should_retry:
                        logger.debug(f"Skipping {ip} ({hostname}): {reason}")
                        scans_skipped += 1
                        continue
                
                # Check system resources
                if not resource_monitor.can_start_operation(
                    operation_name=f"vuln_scan_{ip}",
                    min_memory_mb=30
                ):
                    logger.warning(f"Insufficient resources to scan {ip} ({hostname}) - skipping")
                    scans_skipped += 1
                    continue
                
                try:
                    logger.info(f"🔍 Vulnerability scanning {ip} ({hostname})...")
                    
                    # Execute vulnerability scan DIRECTLY without ThreadPoolExecutor
                    # ThreadPoolExecutor causes "interpreter shutdown" errors on Windows
                    # Vulnerability scans are already long-running, so timeout isn't critical here
                    if self.nmap_vuln_scanner is None:
                        logger.error("Vulnerability scanner became unavailable")
                        continue
                    
                    # Run scan directly - no executor needed
                    result = self.nmap_vuln_scanner.execute(ip, row, action_key)
                    
                    # Handle different result types
                    if result == 'skipped':
                        # Host was skipped (already scanned via incremental scanning)
                        logger.debug(f"⏭️  Vulnerability scan skipped for {ip} ({hostname}) - already scanned")
                        scans_skipped += 1
                        # Don't update action status for skipped scans - keep existing status
                    elif result == 'success':
                        # Scan completed successfully
                        logger.info(f"✅ Vulnerability scan successful for {ip} ({hostname})")
                        self._update_action_status(row, action_key, 'success')
                        scans_performed += 1
                    else:
                        # Scan failed
                        logger.warning(f"❌ Vulnerability scan failed for {ip} ({hostname})")
                        self._update_action_status(row, action_key, 'failed')
                        scans_performed += 1  # Still count as attempted
                    
                    # SQLite writes happen automatically in vuln scanner - no CSV write needed
                    # self.shared_data.write_data(current_data)
                except Exception as e:
                    logger.error(f"Error scanning {ip} ({hostname}): {e}")
                    self._update_action_status(row, action_key, 'failed')
                    scans_performed += 1  # Count failed attempts
                    # SQLite writes happen automatically in vuln scanner - no CSV write needed
                    # self.shared_data.write_data(current_data)
            
            self.last_vuln_scan_time = datetime.now()
            if scans_performed > 0 or scans_skipped > 0:
                logger.info(f"📊 Vulnerability scan complete: {scans_performed} scanned, {scans_skipped} skipped")
            else:
                logger.warning("⚠️  No vulnerability scans performed or skipped")
                
        except Exception as e:
            logger.error(f"Error during vulnerability scanning cycle: {e}")

    def run(self):
        """
        Run the orchestrator cycle with proper scan order:
        1. ARP Ping Scan (fast host discovery)
        2. Nmap Port Scan (discover open ports)
        3. Nmap Vulnerability Scan (scan for vulnerabilities)
        4. Attacks (if enabled)
        5. Loop
        
        Scans ALWAYS run regardless of enable_attacks setting.
        Only attack actions respect the enable_attacks flag.
        """
        # Use getattr for safe config access
        scan_vuln_running = getattr(self.shared_data, 'scan_vuln_running', True)
        scan_vuln_interval = getattr(self.shared_data, 'scan_vuln_interval', 300)
        scan_interval = getattr(self.shared_data, 'scan_interval', 180)
        enable_attacks = getattr(self.shared_data, 'enable_attacks', True)
        
        # ====================================================================
        # PHASE 1: Initial ARP + Port Scan
        # ====================================================================
        logger.info("=" * 70)
        logger.info("ORCHESTRATOR STARTUP - PHASE 1: ARP + Port Scan")
        logger.info("=" * 70)
        
        if self.network_scanner:
            self.shared_data.ragnarorch_status = "NetworkScanner"
            self.shared_data.ragnarstatustext2 = "Initial scan..."
            self._execute_network_scans(reason="startup")
            self.shared_data.ragnarstatustext2 = ""
            logger.info("✓ Phase 1 complete: Network hosts and ports discovered")
        else:
            logger.error("Network scanner not initialized. Cannot start orchestrator.")
            return
        
        # ====================================================================
        # PHASE 2: Initial Vulnerability Scan
        # ====================================================================
        logger.info("=" * 70)
        logger.info("ORCHESTRATOR STARTUP - PHASE 2: Vulnerability Scan")
        logger.info("=" * 70)
        
        if scan_vuln_running and self.nmap_vuln_scanner:
            logger.info("Running initial vulnerability scan on all discovered hosts...")
            # Set orchestrator status to show vulnerability scanning in web UI
            self.shared_data.ragnarorch_status = "NmapVulnScanner"
            self.run_vulnerability_scans(force=True)  # Force scan at startup
            logger.info("✓ Phase 2 complete: Vulnerability scan finished")
        else:
            logger.info("⊘ Phase 2 skipped: Vulnerability scanning disabled")
        
        # ====================================================================
        # PHASE 3: Attack Phase (if enabled)
        # ====================================================================
        logger.info("=" * 70)
        logger.info(f"🔥 ORCHESTRATOR VERSION: {ORCHESTRATOR_VERSION} 🔥")
        logger.info("=" * 70)
        logger.info(f"ORCHESTRATOR STARTUP - PHASE 3: Attack Phase (enabled={enable_attacks})")
        logger.info("=" * 70)
        
        if enable_attacks:
            logger.info("Attack phase enabled - will execute attack actions in main loop")
        else:
            logger.info("⊘ Attack phase disabled - will skip attack actions")
        
        # Log initial system status
        resource_monitor.log_system_status()
        last_resource_log_time = time.time()
        last_vuln_scan_check = time.time()  # Already scanned in Phase 2
        last_network_scan_time = time.time()
        cycle_count = 0
        
        # Track discovered IPs to detect new hosts
        current_data = self.shared_data.read_data()
        known_ips = set(row.get("IPs", "") for row in current_data if row.get("IPs"))
        logger.info(f"Initial IP count: {len(known_ips)} IPs discovered")
        
        logger.info("=" * 70)
        logger.info("ENTERING MAIN ORCHESTRATOR LOOP")
        logger.info("=" * 70)
        
        while not self.shared_data.orchestrator_should_exit:
            cycle_count += 1
            logger.info(f"\n{'=' * 70}")
            logger.info(f"ORCHESTRATOR CYCLE #{cycle_count}")
            logger.info(f"{'=' * 70}")
            
            # Periodically log resource status (every 3 minutes - reduced for Pi Zero W2)
            if time.time() - last_resource_log_time > 180:
                resource_monitor.log_system_status()
                last_resource_log_time = time.time()
                
                # CRITICAL: Ultra-aggressive GC for Pi Zero W2 (416MB usable RAM)
                # Force GC if memory usage exceeds 55% to prevent OOM kills
                mem_usage = resource_monitor.get_memory_usage()
                if mem_usage > 55:
                    logger.warning(f"Memory usage at {mem_usage:.1f}% - forcing garbage collection to prevent OOM")
                    resource_monitor.force_garbage_collection()
                    # Log again after GC to confirm memory freed
                    new_mem = resource_monitor.get_memory_usage()
                    logger.info(f"After GC: Memory usage now {new_mem:.1f}% (freed {mem_usage - new_mem:.1f}%)")
            
            # ================================================================
            # CYCLE PHASE 1: Periodic Network Scan (ARP + Port Scan)
            # ================================================================
            current_time = time.time()
            scan_interval = getattr(self.shared_data, 'scan_interval', scan_interval)
            new_ips_detected = False
            
            if current_time - last_network_scan_time >= scan_interval:
                logger.info(f"→ Cycle Phase 1: ARP + Port Scan (interval: {scan_interval}s)")
                if self.network_scanner:
                    self.shared_data.ragnarorch_status = "NetworkScanner"
                    
                    # Get current IPs before scan
                    pre_scan_data = self.shared_data.read_data()
                    pre_scan_ips = set(row.get("IPs", "") for row in pre_scan_data if row.get("IPs"))
                    
                    # Run the network scan
                    self._execute_network_scans(reason="cycle")
                    last_network_scan_time = current_time
                    
                    # Check for new IPs after scan
                    post_scan_data = self.shared_data.read_data()
                    post_scan_ips = set(row.get("IPs", "") for row in post_scan_data if row.get("IPs"))
                    new_ips = post_scan_ips - pre_scan_ips
                    
                    if new_ips:
                        new_ips_detected = True
                        logger.info(f"✓ Network scan complete - {len(new_ips)} NEW IP(s) discovered: {', '.join(sorted(new_ips))}")
                        known_ips.update(new_ips)
                    else:
                        logger.info("✓ Network scan complete - no new IPs")
                else:
                    logger.warning("Network scanner not available")
            else:
                remaining = int(scan_interval - (current_time - last_network_scan_time))
                logger.debug(f"⊘ Network scan skipped (next in {remaining}s)")
            
            # ================================================================
            # CYCLE PHASE 2: Periodic Vulnerability Scan
            # Triggers on:
            #   - Every 15 minutes (900 seconds)
            #   - When new IPs are discovered
            # ================================================================
            scan_vuln_running = getattr(self.shared_data, 'scan_vuln_running', scan_vuln_running)
            scan_vuln_interval = 900  # 15 minutes = 900 seconds (CHANGED FROM 3600)
            vuln_scan_triggered = False
            
            if scan_vuln_running:
                time_since_last_vuln = time.time() - last_vuln_scan_check
                
                # Trigger conditions
                interval_trigger = time_since_last_vuln >= scan_vuln_interval
                new_ip_trigger = new_ips_detected
                
                if interval_trigger or new_ip_trigger:
                    if interval_trigger:
                        logger.info(f"→ Cycle Phase 2: Vulnerability Scan (15-minute interval trigger)")
                    if new_ip_trigger:
                        logger.info(f"→ Cycle Phase 2: Vulnerability Scan (NEW IP trigger - {len(new_ips)} new hosts)")
                    
                    # Set orchestrator status to show vulnerability scanning in web UI
                    self.shared_data.ragnarorch_status = "NmapVulnScanner"
                    self.run_vulnerability_scans(force=True)  # Force scan on schedule/new IPs
                    last_vuln_scan_check = time.time()
                    vuln_scan_triggered = True
                    logger.info("✓ Vulnerability scan complete")
                else:
                    remaining = int(scan_vuln_interval - time_since_last_vuln)
                    remaining_minutes = remaining // 60
                    logger.debug(f"⊘ Vulnerability scan skipped (next in {remaining_minutes} minutes)")
            else:
                logger.debug("⊘ Vulnerability scanning disabled")
            
            # ================================================================
            # CYCLE PHASE 3: Attack Phase (only if enabled)
            # ================================================================
            enable_attacks = getattr(self.shared_data, 'enable_attacks', enable_attacks)
            if enable_attacks:
                logger.info("→ Cycle Phase 3: Attack Phase (executing attack actions)")
            else:
                logger.debug("⊘ Cycle Phase 3: Attack Phase (disabled - skipping all attacks)")
            
            # CRITICAL: Check system health before processing actions
            if not resource_monitor.is_system_healthy():
                logger.warning("System resources critical - pausing orchestrator for 30 seconds")
                resource_monitor.log_system_status()
                time.sleep(30)
                continue
            
            # EMERGENCY: Check for critical memory pressure (<80MB free)
            if resource_monitor.is_memory_pressure_critical():
                logger.critical("EMERGENCY: Critical memory pressure - forcing GC and pausing 60 seconds")
                resource_monitor.force_garbage_collection()
                time.sleep(60)
                continue
            
            # Prefer fresh in-memory scan results over CSV file reads
            # This eliminates race conditions and provides instant access to live hosts
            any_action_executed = False
            action_retry_pending = False

            for ssid in self._iter_action_contexts():
                with self.shared_data.context_registry.activate(ssid):
                    current_data = self.shared_data.get_latest_scan_results(ssid)
                    if current_data is not None:
                        logger.debug(
                            f"✅ Using fresh scan results from memory for {ssid or 'default'}"
                        )
                    else:
                        logger.debug(
                            f"📄 No in-memory results for {ssid or 'default'} - reading from database"
                        )
                        current_data = self.shared_data.read_data()
                    if not current_data:
                        continue
                    if self.process_alive_ips(current_data):
                        any_action_executed = True

            # SQLite writes happen automatically in action modules - no CSV write needed
            # self.shared_data.write_data(current_data)

            if not any_action_executed:
                if enable_attacks:
                    logger.info("✓ No attack actions to execute at this time")
                else:
                    logger.debug("⊘ Attack actions skipped (disabled)")
                    
                self.shared_data.ragnarorch_status = "IDLE"
                self.shared_data.ragnarstatustext2 = ""
                
                # Check if we should run a network scan
                if current_time - last_network_scan_time >= scan_interval:
                    logger.info("No targets available - running network scan...")
                    if self.network_scanner:
                        self.shared_data.ragnarorch_status = "NetworkScanner"
                        self._execute_network_scans(reason="idle-refresh")
                        last_network_scan_time = time.time()
                        # Get fresh results from memory (scanner hands them off immediately)
                        current_data = self.shared_data.get_latest_scan_results()
                        if current_data is None:
                            logger.debug("No in-memory results after scan - reading from CSV")
                            current_data = self.shared_data.read_data()
                        if enable_attacks:
                            any_action_executed = self.process_alive_ips(current_data)
                    else:
                        logger.warning("No network scanner available.")
                
                self.failed_scans_count += 1
                if self.failed_scans_count >= 1:
                    for action in self.standalone_actions:
                        with self.semaphore:
                            if self.execute_standalone_action(action, current_data):
                                self.failed_scans_count = 0
                                break
                    
                    # Idle period before next cycle
                    idle_start_time = datetime.now()
                    idle_end_time = idle_start_time + timedelta(seconds=scan_interval)
                    while datetime.now() < idle_end_time:
                        if self.shared_data.orchestrator_should_exit:
                            break
                        remaining_time = (idle_end_time - datetime.now()).seconds
                        self.shared_data.ragnarorch_status = "IDLE"
                        self.shared_data.ragnarstatustext2 = ""
                        sys.stdout.write('\x1b[1A\x1b[2K')
                        logger.warning(f"Idle - Next cycle in: {remaining_time} seconds")
                        time.sleep(1)
                    self.failed_scans_count = 0
                    continue
            else:
                if enable_attacks:
                    logger.info("✓ Attack actions executed successfully")
                self.failed_scans_count = 0
                action_retry_pending = True

            if action_retry_pending:
                self.failed_scans_count = 0
            
            logger.info(f"{'=' * 70}")
            logger.info(f"END OF CYCLE #{cycle_count}")
            logger.info(f"{'=' * 70}\n")
    
    def shutdown(self):
        """Gracefully shutdown the orchestrator and cleanup resources"""
        logger.info("Shutting down orchestrator...")
        logger.info("Orchestrator shutdown complete")

if __name__ == "__main__":
    orchestrator = Orchestrator()
    try:
        orchestrator.run()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        orchestrator.shutdown()
