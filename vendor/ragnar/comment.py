# comment.py
# This module defines the `Commentaireia` class, which provides context-based random comments.
# The comments are based on various themes such as "IDLE", "SCANNER", and others, to simulate
# different states or actions within a network scanning and security context. The class uses a 
# shared data object to determine delays between comments and switches themes based on the current 
# state. The `get_commentaire` method returns a random comment from the specified theme, ensuring 
# comments are not repeated too frequently.

import random
import time
import logging
import json
from init_shared import shared_data  
from logger import Logger
import os

logger = Logger(name="comment.py", level=logging.DEBUG)

class Commentaireia:
    """Provides context-based random comments for ragnar."""
    def __init__(self):
        self.shared_data = shared_data
        self.last_comment_time = 0  # Initialize last_comment_time
        self.comment_delay = random.randint(self.shared_data.config['comment_delaymin'], self.shared_data.config['comment_delaymax'])  # Initialize comment_delay
        self.last_theme = None  # Initialize last_theme
        self.themes = self.load_comments(self.shared_data.commentsfile)  # Load themes from JSON file

    def load_comments(self, commentsfile):
        """Load comments from a JSON file."""
        cache_file = commentsfile + '.cache'

        # Check if a cached version exists and is newer than the original file
        if os.path.exists(cache_file) and os.path.exists(commentsfile) and os.path.getmtime(cache_file) >= os.path.getmtime(commentsfile):
            try:
                with open(cache_file, 'r') as file:
                    comments_data = json.load(file)
                    logger.info("Comments loaded successfully from cache.")
                    return comments_data
            except (FileNotFoundError, json.JSONDecodeError) as e:
                logger.warning(f"Cache file is corrupted or not found: {e}. Loading from the original file.")

        # Load from the original file if cache is not used or corrupted
        try:
            if not os.path.exists(commentsfile):
                logger.error(f"Comments file not found: {commentsfile}")
                return {"IDLE": ["No comments available"]}
                
            with open(commentsfile, 'r', encoding='utf-8') as file:
                comments_data = json.load(file)
                logger.info("Comments loaded successfully from JSON file.")
                
                # Validate that all required themes exist
                # These are all the possible status values that can be set in the system
                required_themes = [
                    "IDLE", "NetworkScanner", "NmapVulnScanner", "FTPBruteforce", 
                    "TelnetBruteforce", "StealFilesRDP", "StealFilesTelnet", 
                    "StealFilesSMB", "StealFilesFTP", "StealDataSQL", 
                    "StealFilesSSH", "SSHBruteforce", "SMBBruteforce", 
                    "RDPBruteforce", "LogStandalone", "LogStandalone2",
                    "SQLBruteforce", "ZombifySSH", "LynisPentestSSH"
                ]
                
                for theme in required_themes:
                    if theme not in comments_data:
                        logger.warning(f"Required theme '{theme}' not found in comments file, adding fallback")
                        # Provide contextual fallback comments based on theme type
                        if "Bruteforce" in theme:
                            comments_data[theme] = [f"Attempting {theme.replace('Bruteforce', '')} authentication...", 
                                                   f"Testing {theme.replace('Bruteforce', '')} credentials...",
                                                   f"{theme.replace('Bruteforce', '')} attack in progress..."]
                        elif "StealFiles" in theme:
                            service = theme.replace('StealFiles', '')
                            comments_data[theme] = [f"Extracting files via {service}...", 
                                                   f"Downloading data from {service}...",
                                                   f"File theft in progress via {service}..."]
                        elif "StealData" in theme:
                            comments_data[theme] = ["Extracting database contents...", 
                                                   "Downloading sensitive data...",
                                                   "SQL data theft in progress..."]
                        elif "Scanner" in theme:
                            comments_data[theme] = ["Scanning for vulnerabilities...", 
                                                   "Analyzing network...",
                                                   "Reconnaissance in progress..."]
                        elif "Log" in theme:
                            comments_data[theme] = ["Monitoring logs...", 
                                                   "Analyzing system activity...",
                                                   "Log analysis in progress..."]
                        else:
                            comments_data[theme] = [f"{theme} operation in progress...", 
                                                   f"Executing {theme}...",
                                                   f"{theme} activity detected..."]
                
                # Save to cache
                try:
                    with open(cache_file, 'w', encoding='utf-8') as cache:
                        json.dump(comments_data, cache)
                except Exception as e:
                    logger.warning(f"Could not save comments cache: {e}")
                    
                return comments_data
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Error loading comments from JSON file: {e}")
            # Provide comprehensive fallback themes for all possible statuses
            return {
                "IDLE": ["No comments available", "System waiting...", "Ready for action..."],
                "NetworkScanner": ["Scanning networks...", "Network reconnaissance...", "Mapping network..."],
                "NmapVulnScanner": ["Vulnerability scanning...", "Security assessment...", "Finding weaknesses..."],
                "FTPBruteforce": ["FTP authentication testing...", "FTP credential attack...", "FTP brute force..."],
                "SSHBruteforce": ["SSH authentication testing...", "SSH credential attack...", "SSH brute force..."],
                "RDPBruteforce": ["RDP authentication testing...", "RDP credential attack...", "RDP brute force..."],
                "SMBBruteforce": ["SMB authentication testing...", "SMB credential attack...", "SMB brute force..."],
                "TelnetBruteforce": ["Telnet authentication testing...", "Telnet credential attack...", "Telnet brute force..."],
                "SQLBruteforce": ["SQL authentication testing...", "SQL credential attack...", "SQL brute force..."],
                "StealFilesSSH": ["Extracting files via SSH...", "SSH file theft...", "Downloading via SSH..."],
                "StealFilesRDP": ["Extracting files via RDP...", "RDP file theft...", "Downloading via RDP..."],
                "StealFilesFTP": ["Extracting files via FTP...", "FTP file theft...", "Downloading via FTP..."],
                "StealFilesSMB": ["Extracting files via SMB...", "SMB file theft...", "Downloading via SMB..."],
                "StealFilesTelnet": ["Extracting files via Telnet...", "Telnet file theft...", "Downloading via Telnet..."],
                "StealDataSQL": ["SQL data extraction...", "Database theft...", "Exfiltrating SQL data..."],
                "LogStandalone": ["Log monitoring...", "System analysis...", "Log surveillance..."],
                "LogStandalone2": ["Extended log analysis...", "Deep log monitoring...", "Comprehensive surveillance..."],
                "ZombifySSH": ["SSH backdoor installation...", "Creating SSH persistence...", "SSH zombie creation..."]
            }
        except Exception as e:
            logger.error(f"Unexpected error loading comments: {e}")
            # Minimal fallback for critical error
            return {
                "IDLE": ["System error - minimal mode", "Error loading comments", "Fallback mode active"],
                "NetworkScanner": ["Network scan error", "Scanner fallback", "Minimal scanning mode"]
            }

    def get_commentaire(self, theme):
        """ This method returns a random comment based on the specified theme."""
        current_time = time.time()  # Get the current time in seconds
        if theme != self.last_theme or current_time - self.last_comment_time >= self.comment_delay:  # Check if the theme has changed or if the delay has expired
            self.last_comment_time = current_time   # Update the last comment time
            self.last_theme = theme   # Update the last theme

            # Handle theme case variations and missing themes
            original_theme = theme
            if theme not in self.themes:
                # Try case-insensitive lookup
                theme_lower = theme.lower()
                matching_themes = [t for t in self.themes.keys() if t.lower() == theme_lower]
                
                if matching_themes:
                    theme = matching_themes[0]
                    logger.debug(f"Theme '{original_theme}' matched to '{theme}' (case variation)")
                else:
                    logger.warning(f"Theme '{original_theme}' is not defined, using fallback to IDLE.")
                    theme = "IDLE"
                    
                    # If even IDLE is missing, create emergency fallback
                    if theme not in self.themes:
                        logger.error(f"Critical: IDLE theme missing! Using emergency fallback.")
                        return "System operational..."

            # Return random comment from the theme
            try:
                return random.choice(self.themes[theme])
            except (KeyError, IndexError) as e:
                logger.error(f"Error getting comment for theme '{theme}': {e}")
                return "System operational..."
        else:
            return None
