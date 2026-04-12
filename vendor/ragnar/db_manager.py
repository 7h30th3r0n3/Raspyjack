# db_manager.py
# SQLite Database Manager for Ragnar - Replaces netkb.csv
#
# ARCHITECTURE:
# ============
# This module provides the single source of truth for all host/network data in Ragnar.
# It replaces the CSV-based netkb.csv with a robust SQLite database that supports:
# - Thread-safe concurrent read/write operations
# - Complex queries and filtering
# - Efficient indexing for fast lookups
# - Data integrity with foreign keys and constraints
# - Automatic migration from legacy CSV files
#
# DATA LIFECYCLE:
# ==============
# 1. Host Discovery: ARP scan, ping sweep, nmap → insert/update hosts
# 2. Port Scanning: Nmap port scans → update ports column
# 3. Vulnerability Scanning: Nmap vuln scanner → update vulnerabilities column
# 4. Attack Execution: Various actions → update action status columns
# 5. Ping Tracking: Continuous monitoring → update failed_ping_count, status
# 6. Cleanup: Remove hosts with last_seen > 24 hours ago
#
# STATUS STATES:
# =============
# - 'alive': Host responding to pings (failed_ping_count < 30)
# - 'degraded': Host failed 30 consecutive pings but seen within 24h
# - 'dead': Host not seen for 24+ hours (auto-deleted)
#
# MIGRATION:
# =========
# On first run, automatically migrates data from netkb.csv to SQLite.
# CSV file is kept for backward compatibility but becomes read-only.

import os
import sys
import sqlite3
import json
import csv
import logging
import threading
import re
import unicodedata
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from contextlib import contextmanager

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.abspath(__file__))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from logger import Logger

logger = Logger(name="db_manager.py", level=logging.INFO)

class DatabaseManager:
    """
    Thread-safe SQLite database manager for Ragnar host/network data.
    ACTION_STATUS_COLUMNS = {
        'ssh_connector',
        'rdp_connector',
        'ftp_connector',
        'smb_connector',
        'telnet_connector',
        'sql_connector',
        'steal_files_ssh',
        'steal_files_rdp',
        'steal_files_ftp',
        'steal_files_smb',
        'steal_files_telnet',
        'steal_data_sql',
        'nmap_vuln_scanner',
        'scanner_status'
    }

    This class handles all database operations including:
    - Schema creation and migrations
    - CRUD operations for hosts
    - Ping failure tracking
    - Status management (alive/degraded/dead)
    - CSV migration and backward compatibility
    """
    
    def __init__(self, db_path: str = None, currentdir: str = None, data_root: str = None):
        """
        Initialize the database manager.
        
        Args:
            db_path: Path to SQLite database file (default: data/ragnar.db)
            currentdir: Root directory of Ragnar installation
        """
        self.currentdir = currentdir or os.path.dirname(os.path.abspath(__file__))
        self.datadir = data_root or os.path.join(self.currentdir, 'data')

        # Database file location
        if db_path is None:
            db_path = os.path.join(self.datadir, 'ragnar.db')
        
        self.db_path = db_path
        self.lock = threading.RLock()  # Reentrant lock for nested calls
        
        # Legacy CSV paths for migration
        self.netkb_csv = os.path.join(self.datadir, 'netkb.csv')
        
        # Initialize database
        self._init_database()
        
        logger.info(f"DatabaseManager initialized: {self.db_path}")

    def configure_storage(self, data_root: Optional[str], db_path: Optional[str]):
        """Update the storage root and database path when network context changes."""
        updated = False
        with self.lock:
            if data_root and data_root != self.datadir:
                self.datadir = data_root
                updated = True
            if db_path and db_path != self.db_path:
                self.db_path = db_path
                updated = True
            self.netkb_csv = os.path.join(self.datadir, 'netkb.csv')
            if updated:
                os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        if updated:
            self._init_database()
            logger.info(f"Database storage configured: root={self.datadir}, db={self.db_path}")
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        Ensures thread-safe access and automatic cleanup.
        
        Usage:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM hosts")
        """
        conn = None
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path, check_same_thread=False)
                conn.row_factory = sqlite3.Row  # Enable dict-like access
                conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign keys
                yield conn
                conn.commit()
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def _init_database(self):
        """
        Initialize database schema and perform migrations.
        Creates tables if they don't exist and migrates CSV data if needed.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Create hosts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    mac TEXT PRIMARY KEY,
                    ip TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    ports TEXT,
                    services TEXT,
                    vulnerabilities TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_ping_success TIMESTAMP,
                    failed_ping_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'alive',
                    alive_count INTEGER DEFAULT 0,
                    network_profile TEXT,
                    scanner_status TEXT,
                    ssh_connector TEXT,
                    rdp_connector TEXT,
                    ftp_connector TEXT,
                    smb_connector TEXT,
                    telnet_connector TEXT,
                    sql_connector TEXT,
                    steal_files_ssh TEXT,
                    steal_files_rdp TEXT,
                    steal_files_ftp TEXT,
                    steal_files_smb TEXT,
                    steal_files_telnet TEXT,
                    steal_data_sql TEXT,
                    nmap_vuln_scanner TEXT,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for fast lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac)
            """)
            
            # Create scan_history table for audit trail
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT,
                    ip TEXT,
                    scan_type TEXT,
                    ports_found TEXT,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (mac) REFERENCES hosts(mac) ON DELETE CASCADE
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_history_mac ON scan_history(mac)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(timestamp)
            """)
            
            # Create WiFi scan cache table for optimized network scanning
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS wifi_scan_cache (
                    ssid TEXT PRIMARY KEY,
                    signal INTEGER,
                    security TEXT,
                    frequency TEXT,
                    channel INTEGER,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    scan_count INTEGER DEFAULT 1,
                    is_known BOOLEAN DEFAULT 0,
                    has_system_profile BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_wifi_scan_cache_last_seen ON wifi_scan_cache(last_seen)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_wifi_scan_cache_signal ON wifi_scan_cache(signal)
            """)
            
            # Create WiFi connection history table for tracking all attempts
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS wifi_connection_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ssid TEXT NOT NULL,
                    connection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    disconnection_time TIMESTAMP,
                    success BOOLEAN NOT NULL,
                    failure_reason TEXT,
                    signal_strength INTEGER,
                    duration_seconds INTEGER,
                    was_auto_connect BOOLEAN DEFAULT 0,
                    network_profile_existed BOOLEAN DEFAULT 0,
                    from_ap_mode BOOLEAN DEFAULT 0
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_wifi_conn_history_ssid ON wifi_connection_history(ssid)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_wifi_conn_history_time ON wifi_connection_history(connection_time)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_wifi_conn_history_success ON wifi_connection_history(success)
            """)
            
            # Create WiFi network analytics table for performance metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS wifi_network_analytics (
                    ssid TEXT PRIMARY KEY,
                    total_connections INTEGER DEFAULT 0,
                    successful_connections INTEGER DEFAULT 0,
                    failed_connections INTEGER DEFAULT 0,
                    total_connection_time_seconds INTEGER DEFAULT 0,
                    average_signal INTEGER,
                    min_signal INTEGER,
                    max_signal INTEGER,
                    last_connection_attempt TIMESTAMP,
                    last_successful_connection TIMESTAMP,
                    last_failure_reason TEXT,
                    success_rate REAL DEFAULT 0.0,
                    average_connection_duration REAL DEFAULT 0.0,
                    priority_score REAL DEFAULT 50.0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_wifi_analytics_success_rate ON wifi_network_analytics(success_rate)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_wifi_analytics_priority ON wifi_network_analytics(priority_score)
            """)

            # ================================================================
            # Advanced Vulnerability Scanner Tables (for scan persistence)
            # ================================================================

            # Create scan_jobs table for persisting scan state
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    scan_id TEXT PRIMARY KEY,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    progress_percent INTEGER DEFAULT 0,
                    findings_count INTEGER DEFAULT 0,
                    current_check TEXT,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    error_message TEXT,
                    options TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_jobs_target ON scan_jobs(target)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_jobs_created ON scan_jobs(created_at)
            """)

            # Create scan_findings table for persisting vulnerability findings
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT UNIQUE NOT NULL,
                    scan_id TEXT NOT NULL,
                    scanner TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    cve_ids TEXT,
                    cwe_ids TEXT,
                    cvss_score REAL,
                    evidence TEXT,
                    remediation TEXT,
                    reference_urls TEXT,
                    tags TEXT,
                    matched_at TEXT,
                    template_id TEXT,
                    raw_output TEXT,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_jobs(scan_id) ON DELETE CASCADE
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_id ON scan_findings(scan_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_findings_host ON scan_findings(host)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_findings_severity ON scan_findings(severity)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_findings_scanner ON scan_findings(scanner)
            """)

            # ================================================================
            # ZAP Target Credentials Table (for persistent auth per target)
            # ================================================================

            # Create zap_target_credentials table for storing auth per target
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS zap_target_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_host TEXT NOT NULL UNIQUE,
                    auth_type TEXT NOT NULL,
                    login_url TEXT,
                    username TEXT,
                    password_encrypted TEXT,
                    login_request_data TEXT,
                    username_field TEXT DEFAULT 'username',
                    password_field TEXT DEFAULT 'password',
                    http_realm TEXT,
                    notes TEXT,
                    bearer_token_encrypted TEXT,
                    api_key_encrypted TEXT,
                    api_key_header TEXT DEFAULT 'X-API-Key',
                    cookie_value_encrypted TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_zap_creds_target ON zap_target_credentials(target_host)
            """)

            # Migrate: Add new auth columns if they don't exist (for existing databases)
            try:
                cursor.execute("SELECT bearer_token_encrypted FROM zap_target_credentials LIMIT 1")
            except Exception:
                cursor.execute("ALTER TABLE zap_target_credentials ADD COLUMN bearer_token_encrypted TEXT")
                cursor.execute("ALTER TABLE zap_target_credentials ADD COLUMN api_key_encrypted TEXT")
                cursor.execute("ALTER TABLE zap_target_credentials ADD COLUMN api_key_header TEXT DEFAULT 'X-API-Key'")
                cursor.execute("ALTER TABLE zap_target_credentials ADD COLUMN cookie_value_encrypted TEXT")
                logger.info("Migrated zap_target_credentials table with new auth columns")

            conn.commit()
            logger.info("Database schema initialized successfully (includes WiFi, Scan, and ZAP Credentials tables)")
        
        # Perform CSV migration if needed (non-fatal if it fails)
        try:
            self._migrate_from_csv()
        except Exception as e:
            logger.warning(f"CSV migration skipped: {e}")

        # Clean up any duplicate entries (non-fatal if it fails)
        try:
            self.cleanup_duplicate_hosts()
        except Exception as e:
            logger.warning(f"Duplicate cleanup skipped: {e}")

        # Ensure legacy hostnames are cleaned up once on startup (non-fatal)
        try:
            self.sanitize_all_hostnames()
        except Exception as e:
            logger.warning(f"Hostname sanitization skipped: {e}")
    
    def _migrate_from_csv(self):
        """
        Migrate data from legacy netkb.csv to SQLite database.
        Only runs if CSV exists and database is empty.
        """
        if not os.path.exists(self.netkb_csv):
            logger.debug("No netkb.csv found - skipping migration")
            return

        # Check if database already has data
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Verify hosts table exists before querying
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hosts'")
            if not cursor.fetchone():
                logger.warning("hosts table not found - skipping CSV migration")
                return

            cursor.execute("SELECT COUNT(*) FROM hosts")
            count = cursor.fetchone()[0]

            if count > 0:
                logger.debug(f"Database already contains {count} hosts - skipping CSV migration")
                return
        
        logger.info(f"Migrating data from {self.netkb_csv} to SQLite...")
        
        try:
            with open(self.netkb_csv, 'r', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                migrated_count = 0
                
                for row in reader:
                    try:
                        mac = row.get('MAC', '').strip()
                        if not mac or mac.upper() == 'UNKNOWN':
                            continue
                        
                        # Convert CSV row to database format
                        host_data = {
                            'mac': mac,
                            'ip': row.get('IP', '').strip(),
                            'hostname': row.get('Hostname', '').strip(),
                            'vendor': row.get('Vendor', '').strip(),
                            'ports': row.get('Ports', '').strip(),
                            'services': row.get('Services', '').strip() or row.get('Service', '').strip(),
                            'vulnerabilities': row.get('Nmap Vulnerabilities', '').strip(),
                            'alive_count': self._safe_int(row.get('Alive Count', 0)),
                            'network_profile': row.get('Network Profile', '').strip(),
                            'scanner_status': row.get('Scanner', '').strip(),
                            'ssh_connector': row.get('ssh_connector', '').strip(),
                            'rdp_connector': row.get('rdp_connector', '').strip(),
                            'ftp_connector': row.get('ftp_connector', '').strip(),
                            'smb_connector': row.get('smb_connector', '').strip(),
                            'telnet_connector': row.get('telnet_connector', '').strip(),
                            'sql_connector': row.get('sql_connector', '').strip(),
                            'steal_files_ssh': row.get('steal_files_ssh', '').strip(),
                            'steal_files_rdp': row.get('steal_files_rdp', '').strip(),
                            'steal_files_ftp': row.get('steal_files_ftp', '').strip(),
                            'steal_files_smb': row.get('steal_files_smb', '').strip(),
                            'steal_files_telnet': row.get('steal_files_telnet', '').strip(),
                            'steal_data_sql': row.get('steal_data_sql', '').strip(),
                            'nmap_vuln_scanner': row.get('nmap_vuln_scanner', '').strip(),
                            'notes': row.get('Notes', '').strip(),
                        }
                        
                        self.upsert_host(**host_data)
                        migrated_count += 1
                        
                    except Exception as e:
                        logger.warning(f"Failed to migrate row for MAC {mac}: {e}")
                        continue
                
                logger.info(f"✅ Successfully migrated {migrated_count} hosts from CSV to SQLite")
                
                # Backup CSV after successful migration
                backup_path = self.netkb_csv + '.migrated_backup'
                if not os.path.exists(backup_path):
                    import shutil
                    shutil.copy2(self.netkb_csv, backup_path)
                    logger.info(f"CSV backed up to: {backup_path}")
                    
        except Exception as e:
            logger.error(f"CSV migration failed: {e}")
    
    def _safe_int(self, value, default=0):
        """Safely convert value to integer."""
        try:
            return int(value) if value else default
        except (ValueError, TypeError):
            return default
    
    def _is_pseudo_mac(self, mac: str) -> bool:
        """Check if MAC is a pseudo-MAC (format: 00:00:c0:a8:xx:xx or similar)."""
        if not mac:
            return False
        return mac.lower().startswith('00:00:')

    def sanitize_hostname(self, hostname: Optional[str]) -> str:
        """Normalize hostnames by removing control chars, collapsing duplicates, and limiting length."""
        if hostname is None:
            return ''

        # Normalize unicode and drop non-printable characters
        normalized = unicodedata.normalize('NFKC', str(hostname))
        normalized = ''.join(ch for ch in normalized if ch.isprintable())
        normalized = normalized.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ')

        # Split on known separators and collapse whitespace
        raw_tokens = re.split(r'[;,\|]+', normalized)
        cleaned_tokens = []
        seen = set()

        for token in raw_tokens:
            token = re.sub(r'\s+', ' ', token).strip(" _-.")
            if not token:
                continue
            token_key = token.lower()
            if token_key in seen:
                continue
            seen.add(token_key)
            cleaned_tokens.append(token)
            if len(cleaned_tokens) >= 4:
                break  # Prevent very long alias lists

        sanitized = ' / '.join(cleaned_tokens)
        if not sanitized:
            return ''

        # Enforce max length to keep DB rows tidy
        return sanitized[:128]

    def sanitize_all_hostnames(self) -> int:
        """Retroactively sanitize hostnames already stored in the database."""
        try:
            updated = 0
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT mac, hostname FROM hosts")
                rows = cursor.fetchall()
                now = datetime.now().isoformat()

                for row in rows:
                    mac = row['mac'] if isinstance(row, sqlite3.Row) else row[0]
                    current_hostname = row['hostname'] if isinstance(row, sqlite3.Row) else row[1]
                    sanitized = self.sanitize_hostname(current_hostname)

                    if sanitized != (current_hostname or ''):
                        cursor.execute(
                            "UPDATE hosts SET hostname = ?, updated_at = ? WHERE mac = ?",
                            (sanitized, now, mac)
                        )
                        updated += 1

            if updated:
                logger.info(f"Sanitized {updated} hostnames with invalid formatting")
            return updated
        except Exception as e:
            logger.error(f"Failed to sanitize existing hostnames: {e}")
            return 0
    
    def upsert_host(self, mac: str, ip: str = None, hostname: str = None, 
                   vendor: str = None, ports: str = None, services: str = None,
                   vulnerabilities: str = None, **kwargs):
        """
        Insert or update a host record.
        
        DUPLICATE PREVENTION:
        - If adding a real MAC for an IP that has a pseudo-MAC, migrates data and deletes pseudo-MAC
        - If adding a pseudo-MAC for an IP that has a real MAC, uses the real MAC instead
        - Prevents duplicate entries for the same IP with different MACs
        
        Args:
            mac: MAC address (primary key)
            ip: IP address
            hostname: Hostname
            vendor: Vendor/manufacturer
            ports: Comma-separated list of open ports
            services: JSON string or dict of port->service mappings
            vulnerabilities: JSON string or dict of vulnerabilities
            **kwargs: Additional columns (action statuses, notes, etc.)
        
        Returns:
            bool: True if successful
        """
        if not mac:
            logger.warning("Cannot upsert host without MAC address")
            return False
        
        # Normalize MAC address
        mac = mac.lower().strip()
        
        # DUPLICATE PREVENTION: Check for existing entry with same IP but different MAC
        if ip:
            existing_host = self.get_host_by_ip(ip)
            if existing_host and existing_host['mac'] != mac:
                existing_mac = existing_host['mac']
                is_new_mac_pseudo = self._is_pseudo_mac(mac)
                is_existing_mac_pseudo = self._is_pseudo_mac(existing_mac)
                
                if is_new_mac_pseudo and not is_existing_mac_pseudo:
                    # Trying to add pseudo-MAC when real MAC exists - use real MAC instead
                    logger.info(f"🔄 Real MAC {existing_mac} already exists for IP {ip}, ignoring pseudo-MAC {mac}")
                    mac = existing_mac
                elif not is_new_mac_pseudo and is_existing_mac_pseudo:
                    # Upgrading from pseudo-MAC to real MAC - migrate data
                    logger.info(f"🔄 Upgrading IP {ip} from pseudo-MAC {existing_mac} to real MAC {mac}")
                    
                    # Merge data from old entry with new data, preserving valuable info
                    # Ports: merge instead of replace to preserve scan history
                    existing_ports = set(existing_host.get('ports', '').split(',')) if existing_host.get('ports') else set()
                    new_ports = set(ports.split(',')) if ports else set()
                    merged_ports = ','.join(sorted(existing_ports.union(new_ports), key=lambda x: int(x) if x.isdigit() else 0))
                    
                    # Use new data if provided, otherwise keep existing
                    hostname = hostname or existing_host.get('hostname', '')
                    vendor = vendor or existing_host.get('vendor', '')
                    ports = merged_ports
                    services = services or existing_host.get('services', '')
                    vulnerabilities = vulnerabilities or existing_host.get('vulnerabilities', '')
                    
                    # Preserve action statuses and other metadata from pseudo-MAC entry
                    for field in ['alive_count', 'network_profile', 'scanner_status',
                                'ssh_connector', 'rdp_connector', 'ftp_connector',
                                'smb_connector', 'telnet_connector', 'sql_connector',
                                'steal_files_ssh', 'steal_files_rdp', 'steal_files_ftp',
                                'steal_files_smb', 'steal_files_telnet', 'steal_data_sql',
                                'nmap_vuln_scanner', 'notes', 'failed_ping_count']:
                        if field not in kwargs and existing_host.get(field):
                            kwargs[field] = existing_host[field]
                    
                    # Delete the old pseudo-MAC entry
                    self.delete_host(existing_mac)
                    logger.info(f"🗑️ Deleted old pseudo-MAC entry {existing_mac}")
                elif is_new_mac_pseudo and is_existing_mac_pseudo:
                    # Both are pseudo-MACs - keep the existing one
                    logger.debug(f"Both MACs are pseudo for IP {ip}, keeping existing {existing_mac}")
                    mac = existing_mac
                else:
                    # Both are real MACs but different - this is IP reassignment
                    logger.warning(f"⚠️ IP {ip} reassigned from MAC {existing_mac} to {mac} (both real MACs)")
                    # Continue with the new MAC, existing entry will be marked as failed ping
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if host exists
                cursor.execute("SELECT mac FROM hosts WHERE mac = ?", (mac,))
                exists = cursor.fetchone() is not None
                
                # Prepare data
                now = datetime.now().isoformat()
                
                if exists:
                    # Update existing host
                    update_fields = []
                    update_values = []
                    
                    if ip is not None:
                        update_fields.append("ip = ?")
                        update_values.append(ip)
                    
                    if hostname is not None:
                        cleaned_hostname = self.sanitize_hostname(hostname)
                        update_fields.append("hostname = ?")
                        update_values.append(cleaned_hostname)
                    
                    if vendor is not None:
                        update_fields.append("vendor = ?")
                        update_values.append(vendor)
                    
                    if ports is not None:
                        update_fields.append("ports = ?")
                        update_values.append(ports)
                    
                    if services is not None:
                        if isinstance(services, dict):
                            services = json.dumps(services)
                        update_fields.append("services = ?")
                        update_values.append(services)
                    
                    if vulnerabilities is not None:
                        if isinstance(vulnerabilities, dict):
                            vulnerabilities = json.dumps(vulnerabilities)
                        update_fields.append("vulnerabilities = ?")
                        update_values.append(vulnerabilities)
                    
                    # Handle additional kwargs
                    for key, value in kwargs.items():
                        if key in ['alive_count', 'network_profile', 'scanner_status',
                                  'ssh_connector', 'rdp_connector', 'ftp_connector',
                                  'smb_connector', 'telnet_connector', 'sql_connector',
                                  'steal_files_ssh', 'steal_files_rdp', 'steal_files_ftp',
                                  'steal_files_smb', 'steal_files_telnet', 'steal_data_sql',
                                  'nmap_vuln_scanner', 'notes', 'status', 'failed_ping_count']:
                            update_fields.append(f"{key} = ?")
                            update_values.append(value)
                    
                    # Always update last_seen and updated_at
                    update_fields.append("last_seen = ?")
                    update_values.append(now)
                    update_fields.append("updated_at = ?")
                    update_values.append(now)
                    
                    # Add MAC to end of values for WHERE clause
                    update_values.append(mac)
                    
                    if update_fields:
                        sql = f"UPDATE hosts SET {', '.join(update_fields)} WHERE mac = ?"
                        cursor.execute(sql, update_values)
                        logger.debug(f"Updated host: {mac} ({ip})")
                else:
                    # Insert new host
                    insert_data = {
                        'mac': mac,
                        'ip': ip or '',
                        'hostname': self.sanitize_hostname(hostname) if hostname is not None else '',
                        'vendor': vendor or '',
                        'ports': ports or '',
                        'services': json.dumps(services) if isinstance(services, dict) else (services or ''),
                        'vulnerabilities': json.dumps(vulnerabilities) if isinstance(vulnerabilities, dict) else (vulnerabilities or ''),
                        'first_seen': now,
                        'last_seen': now,
                        'last_ping_success': now,
                        'failed_ping_count': 0,
                        'status': 'alive',
                        'alive_count': kwargs.get('alive_count', 0),
                        'network_profile': kwargs.get('network_profile', ''),
                        'scanner_status': kwargs.get('scanner_status', ''),
                        'ssh_connector': kwargs.get('ssh_connector', ''),
                        'rdp_connector': kwargs.get('rdp_connector', ''),
                        'ftp_connector': kwargs.get('ftp_connector', ''),
                        'smb_connector': kwargs.get('smb_connector', ''),
                        'telnet_connector': kwargs.get('telnet_connector', ''),
                        'sql_connector': kwargs.get('sql_connector', ''),
                        'steal_files_ssh': kwargs.get('steal_files_ssh', ''),
                        'steal_files_rdp': kwargs.get('steal_files_rdp', ''),
                        'steal_files_ftp': kwargs.get('steal_files_ftp', ''),
                        'steal_files_smb': kwargs.get('steal_files_smb', ''),
                        'steal_files_telnet': kwargs.get('steal_files_telnet', ''),
                        'steal_data_sql': kwargs.get('steal_data_sql', ''),
                        'nmap_vuln_scanner': kwargs.get('nmap_vuln_scanner', ''),
                        'notes': kwargs.get('notes', ''),
                    }
                    
                    columns = ', '.join(insert_data.keys())
                    placeholders = ', '.join(['?' for _ in insert_data])
                    sql = f"INSERT INTO hosts ({columns}) VALUES ({placeholders})"
                    
                    cursor.execute(sql, list(insert_data.values()))
                    logger.info(f"Inserted new host: {mac} ({ip})")
                
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to upsert host {mac}: {e}")
            return False

    def _normalize_action_column(self, action_name: Optional[str]) -> Optional[str]:
        """Map user-facing action names to database columns."""
        if not action_name:
            return None

        normalized = action_name.strip().lower()
        alias_map = {
            'nmapvulnscanner': 'nmap_vuln_scanner',
            'nmap_vulnscanner': 'nmap_vuln_scanner',
            'nmap_vuln_scanner': 'nmap_vuln_scanner',
            'scanner': 'scanner_status'
        }

        if normalized in alias_map:
            return alias_map[normalized]

        if normalized in self.ACTION_STATUS_COLUMNS:
            return normalized

        lower_columns = {col.lower(): col for col in self.ACTION_STATUS_COLUMNS}
        return lower_columns.get(normalized)

    def update_host_action_status(self, mac: str, action_name: str, status: str) -> bool:
        """Update a host action status column in the database."""
        if not mac:
            logger.warning("Cannot update action status without MAC address")
            return False

        column = self._normalize_action_column(action_name)
        if not column:
            logger.warning(f"Unknown action column for '{action_name}'")
            return False

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"UPDATE hosts SET {column} = ?, updated_at = CURRENT_TIMESTAMP WHERE lower(mac) = lower(?)",
                    (status, mac)
                )
                updated = cursor.rowcount > 0
                if not updated:
                    logger.debug(f"No host updated for MAC {mac} when setting {column}")
                return updated
        except Exception as exc:
            logger.error(f"Failed to update action status for {mac}: {exc}")
            return False
    
    def delete_host(self, mac: str) -> bool:
        """
        Delete a host record by MAC address.
        
        Args:
            mac: MAC address to delete
            
        Returns:
            bool: True if successful
        """
        if not mac:
            logger.warning("Cannot delete host without MAC address")
            return False
        
        # Normalize MAC address
        mac = mac.lower().strip()
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM hosts WHERE mac = ?", (mac,))
                conn.commit()
                
                if cursor.rowcount > 0:
                    logger.info(f"Deleted host: {mac}")
                    return True
                else:
                    logger.debug(f"No host found to delete: {mac}")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to delete host {mac}: {e}")
            return False
    
    def get_host_by_mac(self, mac: str) -> Optional[Dict]:
        """Get host record by MAC address."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM hosts WHERE mac = ?", (mac.lower().strip(),))
                row = cursor.fetchone()
                
                if row:
                    return dict(row)
                return None
        except Exception as e:
            logger.error(f"Failed to get host by MAC {mac}: {e}")
            return None
    
    def get_host_by_ip(self, ip: str) -> Optional[Dict]:
        """Get host record by IP address. If multiple exist, prefers real MAC over pseudo-MAC."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM hosts WHERE ip = ? ORDER BY mac", (ip.strip(),))
                rows = cursor.fetchall()
                
                if not rows:
                    return None
                
                # If multiple entries exist for same IP, prefer real MAC over pseudo-MAC
                if len(rows) > 1:
                    logger.warning(f"Found {len(rows)} entries for IP {ip} - preferring real MAC")
                    for row in rows:
                        if not self._is_pseudo_mac(row['mac']):
                            return dict(row)
                
                return dict(rows[0])
        except Exception as e:
            logger.error(f"Failed to get host by IP {ip}: {e}")
            return None
    
    def get_all_hosts(self, status: str = None) -> List[Dict]:
        """
        Get all hosts, optionally filtered by status.
        
        Args:
            status: Filter by status ('alive', 'degraded', None for all)
        
        Returns:
            List of host dictionaries
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if status:
                    cursor.execute("SELECT * FROM hosts WHERE status = ? ORDER BY ip", (status,))
                else:
                    cursor.execute("SELECT * FROM hosts ORDER BY ip")
                
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get all hosts: {e}")
            return []
    
    def update_ping_status(self, mac: str, success: bool):
        """
        Update ping tracking for a host.
        
        Args:
            mac: MAC address
            success: True if ping succeeded, False if failed
        
        This implements the ping failure tracking logic:
        - Success: Reset failed_ping_count to 0, update last_ping_success, status='alive'
        - Failure: Increment failed_ping_count, check if >= 30 → status='degraded'
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.now().isoformat()
                
                if success:
                    # Ping succeeded - reset failure count and mark alive
                    cursor.execute("""
                        UPDATE hosts 
                        SET failed_ping_count = 0,
                            last_ping_success = ?,
                            last_seen = ?,
                            status = 'alive',
                            updated_at = ?
                        WHERE mac = ?
                    """, (now, now, now, mac.lower().strip()))
                    logger.debug(f"Ping success: {mac} - status=alive")
                else:
                    # Ping failed - increment failure count
                    cursor.execute("""
                        UPDATE hosts 
                        SET failed_ping_count = failed_ping_count + 1,
                            updated_at = ?
                        WHERE mac = ?
                    """, (now, mac.lower().strip()))
                    
                    # Check if we've hit the degraded threshold (30 failed pings)
                    cursor.execute("SELECT failed_ping_count FROM hosts WHERE mac = ?", (mac.lower().strip(),))
                    row = cursor.fetchone()
                    
                    if row and row[0] >= 30:
                        cursor.execute("""
                            UPDATE hosts 
                            SET status = 'degraded'
                            WHERE mac = ?
                        """, (mac.lower().strip(),))
                        logger.warning(f"Host {mac} marked as degraded (30+ failed pings)")
                
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to update ping status for {mac}: {e}")
            return False
    
    def mark_all_hosts_degraded(self):
        """
        Mark every alive host in the current database as degraded.

        Called when the active network changes so that hosts from the
        outgoing network do not linger as 'alive' if they were
        accidentally written here before the database switch completed.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.now().isoformat()
                cursor.execute("""
                    UPDATE hosts
                    SET status = 'degraded',
                        failed_ping_count = MAX(failed_ping_count, 30),
                        updated_at = ?
                    WHERE status = 'alive'
                """, (now,))
                affected = cursor.rowcount
                conn.commit()
                if affected:
                    logger.info(
                        f"Network switch: marked {affected} hosts as degraded in {self.db_path}"
                    )
                return affected
        except Exception as e:
            logger.error(f"Failed to mark all hosts degraded: {e}")
            return 0

    def cleanup_duplicate_hosts(self):
        """
        Remove duplicate host entries where the same IP exists with both:
        - A real MAC address (from ARP discovery)
        - A pseudo-MAC address (format 00:00:xx:xx:xx:xx)
        
        Priority: Real MAC addresses are kept, pseudo-MACs are deleted.
        Data from pseudo-MAC entries is migrated to real MAC entries.
        
        Returns:
            int: Number of duplicate entries removed
        """
        try:
            deleted_count = 0
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Find all IPs that have multiple MAC addresses
                cursor.execute("""
                    SELECT ip, COUNT(*) as count 
                    FROM hosts 
                    GROUP BY ip 
                    HAVING COUNT(*) > 1
                """)
                
                duplicate_ips = cursor.fetchall()
                
                if not duplicate_ips:
                    logger.debug("No duplicate IP entries found")
                    return 0
                
                logger.info(f"Found {len(duplicate_ips)} IPs with duplicate entries")
                
                for ip_row in duplicate_ips:
                    ip = ip_row['ip'] if isinstance(ip_row, sqlite3.Row) else ip_row[0]
                    
                    # Get all entries for this IP
                    cursor.execute("""
                        SELECT mac, hostname, vendor, ports, services, vulnerabilities,
                               last_seen, failed_ping_count, status, alive_count,
                               network_profile, scanner_status, ssh_connector, rdp_connector,
                               ftp_connector, smb_connector, telnet_connector, sql_connector,
                               steal_files_ssh, steal_files_rdp, steal_files_ftp,
                               steal_files_smb, steal_files_telnet, steal_data_sql,
                               nmap_vuln_scanner, notes
                        FROM hosts 
                        WHERE ip = ?
                        ORDER BY last_seen DESC
                    """, (ip,))
                    
                    entries = cursor.fetchall()
                    
                    if len(entries) < 2:
                        continue
                    
                    logger.debug(f"IP {ip} has {len(entries)} entries:")
                    
                    real_mac_entry = None
                    pseudo_mac_entries = []
                    
                    for entry in entries:
                        mac = entry['mac'] if isinstance(entry, sqlite3.Row) else entry[0]
                        logger.debug(f"  - MAC: {mac}, Status: {entry['status'] if isinstance(entry, sqlite3.Row) else entry[9]}")
                        
                        if self._is_pseudo_mac(mac):
                            pseudo_mac_entries.append(entry)
                        else:
                            if real_mac_entry is None:
                                real_mac_entry = entry
                            else:
                                # Multiple real MACs - keep the most recently seen
                                logger.warning(f"  Multiple real MACs for {ip}, keeping most recent")
                    
                    # Delete pseudo-MAC entries if we have a real MAC
                    if real_mac_entry and pseudo_mac_entries:
                        real_mac = real_mac_entry['mac'] if isinstance(real_mac_entry, sqlite3.Row) else real_mac_entry[0]
                        logger.info(f"  → Keeping real MAC: {real_mac}")
                        
                        # Merge ports from pseudo-MAC entries into real MAC
                        real_ports = set(real_mac_entry['ports'].split(',')) if real_mac_entry['ports'] else set()
                        for pseudo_entry in pseudo_mac_entries:
                            pseudo_mac = pseudo_entry['mac'] if isinstance(pseudo_entry, sqlite3.Row) else pseudo_entry[0]
                            pseudo_ports = set(pseudo_entry['ports'].split(',')) if pseudo_entry['ports'] else set()
                            real_ports.update(pseudo_ports)
                            
                            cursor.execute("DELETE FROM hosts WHERE mac = ?", (pseudo_mac,))
                            deleted_count += 1
                            logger.info(f"  → Deleted pseudo-MAC: {pseudo_mac}")
                        
                        # Update real MAC with merged ports
                        if real_ports:
                            merged_ports = ','.join(sorted([p for p in real_ports if p], key=lambda x: int(x) if x.isdigit() else 0))
                            cursor.execute("UPDATE hosts SET ports = ? WHERE mac = ?", (merged_ports, real_mac))
                    
                    elif len(pseudo_mac_entries) > 1:
                        # Multiple pseudo-MACs but no real MAC - keep newest, delete rest
                        keep_entry = pseudo_mac_entries[0]
                        keep_mac = keep_entry['mac'] if isinstance(keep_entry, sqlite3.Row) else keep_entry[0]
                        logger.info(f"  → No real MAC found, keeping newest pseudo-MAC: {keep_mac}")
                        
                        for pseudo_entry in pseudo_mac_entries[1:]:
                            pseudo_mac = pseudo_entry['mac'] if isinstance(pseudo_entry, sqlite3.Row) else pseudo_entry[0]
                            cursor.execute("DELETE FROM hosts WHERE mac = ?", (pseudo_mac,))
                            deleted_count += 1
                            logger.info(f"  → Deleted older pseudo-MAC: {pseudo_mac}")
                    
                    elif len(entries) > 1 and not real_mac_entry and not pseudo_mac_entries:
                        # Multiple real MACs - keep most recently seen
                        keep_entry = entries[0]
                        keep_mac = keep_entry['mac'] if isinstance(keep_entry, sqlite3.Row) else keep_entry[0]
                        logger.warning(f"  → Multiple real MACs, keeping most recent: {keep_mac}")
                        
                        for entry in entries[1:]:
                            old_mac = entry['mac'] if isinstance(entry, sqlite3.Row) else entry[0]
                            cursor.execute("DELETE FROM hosts WHERE mac = ?", (old_mac,))
                            deleted_count += 1
                            logger.info(f"  → Deleted older entry: {old_mac}")
                
                conn.commit()
                
                if deleted_count > 0:
                    logger.info(f"✅ Cleanup complete! Deleted {deleted_count} duplicate entries.")
                else:
                    logger.debug("No duplicates needed to be removed")
                
                return deleted_count
                
        except Exception as e:
            logger.error(f"Error during duplicate cleanup: {e}")
            return 0
    
    def cleanup_old_hosts(self, hours: int = 24):
        """
        Remove hosts that haven't been seen in the specified number of hours.
        
        Args:
            hours: Number of hours after which to remove hosts (default: 24)
        
        Returns:
            int: Number of hosts removed
        """
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            cutoff_iso = cutoff_time.isoformat()
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get hosts to be removed for logging
                cursor.execute("""
                    SELECT mac, ip, hostname, last_seen 
                    FROM hosts 
                    WHERE last_seen < ?
                """, (cutoff_iso,))
                
                to_remove = cursor.fetchall()
                
                # Delete old hosts
                cursor.execute("DELETE FROM hosts WHERE last_seen < ?", (cutoff_iso,))
                
                removed_count = cursor.rowcount
                conn.commit()
                
                if removed_count > 0:
                    logger.info(f"Cleaned up {removed_count} hosts not seen in {hours} hours")
                    for row in to_remove:
                        logger.debug(f"  Removed: {row['mac']} ({row['ip']}) last seen {row['last_seen']}")
                
                return removed_count
                
        except Exception as e:
            logger.error(f"Failed to cleanup old hosts: {e}")
            return 0
    
    def add_scan_history(self, mac: str, ip: str, scan_type: str, 
                        ports_found: str = None, vulnerabilities_found: int = 0):
        """
        Add a scan history entry for audit trail.
        
        Args:
            mac: MAC address
            ip: IP address
            scan_type: Type of scan (e.g., 'arp', 'nmap', 'vuln_scan')
            ports_found: Comma-separated list of ports found
            vulnerabilities_found: Number of vulnerabilities found
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO scan_history (mac, ip, scan_type, ports_found, vulnerabilities_found)
                    VALUES (?, ?, ?, ?, ?)
                """, (mac.lower().strip(), ip, scan_type, ports_found or '', vulnerabilities_found))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to add scan history: {e}")
            return False
    
    def get_scan_history(self, mac: str = None, limit: int = 100) -> List[Dict]:
        """
        Get scan history, optionally filtered by MAC address.
        
        Args:
            mac: MAC address to filter by (None for all)
            limit: Maximum number of records to return
        
        Returns:
            List of scan history dictionaries
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if mac:
                    cursor.execute("""
                        SELECT * FROM scan_history 
                        WHERE mac = ? 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    """, (mac.lower().strip(), limit))
                else:
                    cursor.execute("""
                        SELECT * FROM scan_history 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    """, (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get scan history: {e}")
            return []
    
    def get_stats(self) -> Dict:
        """
        Get database statistics.
        
        Returns:
            Dictionary with statistics like total hosts, alive hosts, etc.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Total hosts
                cursor.execute("SELECT COUNT(*) FROM hosts")
                stats['total_hosts'] = cursor.fetchone()[0]
                
                # Alive hosts
                cursor.execute("SELECT COUNT(*) FROM hosts WHERE status = 'alive'")
                stats['alive_hosts'] = cursor.fetchone()[0]
                
                # Degraded hosts
                cursor.execute("SELECT COUNT(*) FROM hosts WHERE status = 'degraded'")
                stats['degraded_hosts'] = cursor.fetchone()[0]
                
                # Hosts with open ports
                cursor.execute("SELECT COUNT(*) FROM hosts WHERE ports != '' AND ports IS NOT NULL")
                stats['hosts_with_ports'] = cursor.fetchone()[0]
                
                # Hosts with vulnerabilities
                cursor.execute("SELECT COUNT(*) FROM hosts WHERE vulnerabilities != '' AND vulnerabilities IS NOT NULL")
                stats['hosts_with_vulns'] = cursor.fetchone()[0]
                
                # Total scans
                cursor.execute("SELECT COUNT(*) FROM scan_history")
                stats['total_scans'] = cursor.fetchone()[0]
                
                return stats
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {}
    
    def export_to_csv(self, csv_path: str = None) -> bool:
        """
        Export database to CSV format (for backward compatibility).
        
        Args:
            csv_path: Path to CSV file (default: netkb.csv)
        
        Returns:
            bool: True if successful
        """
        if csv_path is None:
            csv_path = self.netkb_csv
        
        try:
            hosts = self.get_all_hosts()
            
            if not hosts:
                logger.warning("No hosts to export")
                return False
            
            # Define CSV columns
            fieldnames = [
                'MAC', 'IP', 'Hostname', 'Vendor', 'Ports', 'Services',
                'Nmap Vulnerabilities', 'Alive Count', 'Network Profile',
                'Scanner', 'ssh_connector', 'rdp_connector', 'ftp_connector',
                'smb_connector', 'telnet_connector', 'sql_connector',
                'steal_files_ssh', 'steal_files_rdp', 'steal_files_ftp',
                'steal_files_smb', 'steal_files_telnet', 'steal_data_sql',
                'nmap_vuln_scanner', 'Notes', 'First Seen', 'Last Seen', 'Status'
            ]
            
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for host in hosts:
                    row = {
                        'MAC': host.get('mac', ''),
                        'IP': host.get('ip', ''),
                        'Hostname': host.get('hostname', ''),
                        'Vendor': host.get('vendor', ''),
                        'Ports': host.get('ports', ''),
                        'Services': host.get('services', ''),
                        'Nmap Vulnerabilities': host.get('vulnerabilities', ''),
                        'Alive Count': host.get('alive_count', 0),
                        'Network Profile': host.get('network_profile', ''),
                        'Scanner': host.get('scanner_status', ''),
                        'ssh_connector': host.get('ssh_connector', ''),
                        'rdp_connector': host.get('rdp_connector', ''),
                        'ftp_connector': host.get('ftp_connector', ''),
                        'smb_connector': host.get('smb_connector', ''),
                        'telnet_connector': host.get('telnet_connector', ''),
                        'sql_connector': host.get('sql_connector', ''),
                        'steal_files_ssh': host.get('steal_files_ssh', ''),
                        'steal_files_rdp': host.get('steal_files_rdp', ''),
                        'steal_files_ftp': host.get('steal_files_ftp', ''),
                        'steal_files_smb': host.get('steal_files_smb', ''),
                        'steal_files_telnet': host.get('steal_files_telnet', ''),
                        'steal_data_sql': host.get('steal_data_sql', ''),
                        'nmap_vuln_scanner': host.get('nmap_vuln_scanner', ''),
                        'Notes': host.get('notes', ''),
                        'First Seen': host.get('first_seen', ''),
                        'Last Seen': host.get('last_seen', ''),
                        'Status': host.get('status', ''),
                    }
                    writer.writerow(row)
            
            logger.info(f"Exported {len(hosts)} hosts to {csv_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export to CSV: {e}")
            return False


    # ============================================================================
    # WIFI MANAGEMENT METHODS
    # ============================================================================
    
    def cache_wifi_scan(self, networks: List[Dict[str, Any]]):
        """
        Cache WiFi scan results to reduce expensive nmcli rescan calls.
        
        Args:
            networks: List of network dicts with ssid, signal, security, etc.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                timestamp = datetime.now()
                
                for network in networks:
                    ssid = network.get('ssid', '').strip()
                    if not ssid or network.get('instruction'):  # Skip instruction entries
                        continue
                    
                    # Check if network exists
                    cursor.execute("""
                        SELECT scan_count FROM wifi_scan_cache WHERE ssid = ?
                    """, (ssid,))
                    row = cursor.fetchone()
                    
                    if row:
                        # Update existing entry
                        scan_count = row[0] + 1
                        cursor.execute("""
                            UPDATE wifi_scan_cache
                            SET signal = ?,
                                security = ?,
                                last_seen = ?,
                                scan_count = ?,
                                is_known = ?,
                                has_system_profile = ?
                            WHERE ssid = ?
                        """, (
                            network.get('signal', 0),
                            network.get('security', ''),
                            timestamp,
                            scan_count,
                            1 if network.get('known', False) else 0,
                            1 if network.get('has_system_profile', False) else 0,
                            ssid
                        ))
                    else:
                        # Insert new entry
                        cursor.execute("""
                            INSERT INTO wifi_scan_cache 
                            (ssid, signal, security, last_seen, scan_count, is_known, has_system_profile)
                            VALUES (?, ?, ?, ?, 1, ?, ?)
                        """, (
                            ssid,
                            network.get('signal', 0),
                            network.get('security', ''),
                            timestamp,
                            1 if network.get('known', False) else 0,
                            1 if network.get('has_system_profile', False) else 0
                        ))
                
                conn.commit()
                logger.debug(f"Cached {len([n for n in networks if not n.get('instruction')])} WiFi networks")
                
        except Exception as e:
            logger.error(f"Error caching WiFi scan: {e}")
    
    def get_cached_wifi_networks(self, max_age_seconds: int = 300) -> List[Dict[str, Any]]:
        """
        Get cached WiFi networks scanned within the specified time window.
        
        Args:
            max_age_seconds: Maximum age of cached data (default: 5 minutes)
            
        Returns:
            List of network dicts
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cutoff_time = datetime.now() - timedelta(seconds=max_age_seconds)
                
                cursor.execute("""
                    SELECT ssid, signal, security, last_seen, is_known, has_system_profile
                    FROM wifi_scan_cache
                    WHERE last_seen >= ?
                    ORDER BY signal DESC
                """, (cutoff_time,))
                
                networks = []
                for row in cursor.fetchall():
                    networks.append({
                        'ssid': row[0],
                        'signal': row[1],
                        'security': row[2],
                        'last_seen': row[3],
                        'known': bool(row[4]),
                        'has_system_profile': bool(row[5])
                    })
                
                logger.debug(f"Retrieved {len(networks)} cached WiFi networks (max age: {max_age_seconds}s)")
                return networks
                
        except Exception as e:
            logger.error(f"Error retrieving cached WiFi networks: {e}")
            return []
    
    def log_wifi_connection_attempt(self, ssid: str, success: bool, 
                                    failure_reason: Optional[str] = None,
                                    signal_strength: Optional[int] = None,
                                    was_auto_connect: bool = False,
                                    network_profile_existed: bool = False,
                                    from_ap_mode: bool = False) -> int:
        """
        Log a WiFi connection attempt for history tracking.
        
        Returns:
            Connection history ID
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO wifi_connection_history
                    (ssid, success, failure_reason, signal_strength, 
                     was_auto_connect, network_profile_existed, from_ap_mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    ssid,
                    1 if success else 0,
                    failure_reason,
                    signal_strength,
                    1 if was_auto_connect else 0,
                    1 if network_profile_existed else 0,
                    1 if from_ap_mode else 0
                ))
                
                conn_id = cursor.lastrowid
                conn.commit()
                
                # Update analytics
                self._update_wifi_analytics(ssid, success, failure_reason, signal_strength)
                
                logger.debug(f"Logged WiFi connection attempt: {ssid} (success={success})")
                return conn_id
                
        except Exception as e:
            logger.error(f"Error logging WiFi connection attempt: {e}")
            return -1
    
    def update_wifi_disconnection(self, ssid: str, connection_id: Optional[int] = None):
        """
        Update WiFi connection history with disconnection time and calculate duration.
        
        Args:
            ssid: Network SSID
            connection_id: Specific connection ID, or None to update most recent
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.now()
                
                if connection_id:
                    # Update specific connection
                    cursor.execute("""
                        SELECT connection_time FROM wifi_connection_history
                        WHERE id = ? AND success = 1
                    """, (connection_id,))
                else:
                    # Update most recent successful connection for this SSID
                    cursor.execute("""
                        SELECT id, connection_time FROM wifi_connection_history
                        WHERE ssid = ? AND success = 1 AND disconnection_time IS NULL
                        ORDER BY connection_time DESC
                        LIMIT 1
                    """, (ssid,))
                
                row = cursor.fetchone()
                if row:
                    if connection_id:
                        conn_id = connection_id
                        conn_time_str = row[0]
                    else:
                        conn_id = row[0]
                        conn_time_str = row[1]
                    
                    # Calculate duration
                    conn_time = datetime.fromisoformat(conn_time_str)
                    duration = int((now - conn_time).total_seconds())
                    
                    cursor.execute("""
                        UPDATE wifi_connection_history
                        SET disconnection_time = ?,
                            duration_seconds = ?
                        WHERE id = ?
                    """, (now, duration, conn_id))
                    
                    conn.commit()
                    logger.debug(f"Updated disconnection for {ssid} (duration: {duration}s)")
                
        except Exception as e:
            logger.error(f"Error updating WiFi disconnection: {e}")
    
    def _update_wifi_analytics(self, ssid: str, success: bool, 
                              failure_reason: Optional[str] = None,
                              signal_strength: Optional[int] = None):
        """
        Update WiFi network analytics based on connection attempt.
        Internal method called after logging connection history.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.now()
                
                # Get current analytics
                cursor.execute("""
                    SELECT total_connections, successful_connections, failed_connections,
                           average_signal, min_signal, max_signal
                    FROM wifi_network_analytics
                    WHERE ssid = ?
                """, (ssid,))
                
                row = cursor.fetchone()
                
                if row:
                    # Update existing analytics
                    total = row[0] + 1
                    successful = row[1] + (1 if success else 0)
                    failed = row[2] + (0 if success else 1)
                    avg_signal = row[3]
                    min_signal = row[4]
                    max_signal = row[5]
                    
                    # Update signal stats if provided
                    if signal_strength is not None:
                        if avg_signal:
                            avg_signal = (avg_signal * (total - 1) + signal_strength) / total
                        else:
                            avg_signal = signal_strength
                        
                        if min_signal is None or signal_strength < min_signal:
                            min_signal = signal_strength
                        if max_signal is None or signal_strength > max_signal:
                            max_signal = signal_strength
                    
                    success_rate = (successful / total * 100.0) if total > 0 else 0.0
                    
                    # Calculate priority score (weighted: 60% success rate, 40% signal strength)
                    priority_score = (success_rate * 0.6) + ((avg_signal or 0) * 0.4)
                    
                    cursor.execute("""
                        UPDATE wifi_network_analytics
                        SET total_connections = ?,
                            successful_connections = ?,
                            failed_connections = ?,
                            average_signal = ?,
                            min_signal = ?,
                            max_signal = ?,
                            last_connection_attempt = ?,
                            last_successful_connection = CASE WHEN ? THEN ? ELSE last_successful_connection END,
                            last_failure_reason = CASE WHEN ? THEN ? ELSE last_failure_reason END,
                            success_rate = ?,
                            priority_score = ?,
                            updated_at = ?
                        WHERE ssid = ?
                    """, (
                        total, successful, failed,
                        avg_signal, min_signal, max_signal,
                        now,
                        success, now,
                        not success, failure_reason,
                        success_rate,
                        priority_score,
                        now,
                        ssid
                    ))
                else:
                    # Insert new analytics
                    success_rate = 100.0 if success else 0.0
                    priority_score = (success_rate * 0.6) + ((signal_strength or 0) * 0.4)
                    
                    cursor.execute("""
                        INSERT INTO wifi_network_analytics
                        (ssid, total_connections, successful_connections, failed_connections,
                         average_signal, min_signal, max_signal,
                         last_connection_attempt, last_successful_connection, last_failure_reason,
                         success_rate, priority_score, updated_at)
                        VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        ssid,
                        1 if success else 0,
                        0 if success else 1,
                        signal_strength,
                        signal_strength,
                        signal_strength,
                        now,
                        now if success else None,
                        failure_reason if not success else None,
                        success_rate,
                        priority_score,
                        now
                    ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error updating WiFi analytics: {e}")
    
    def get_wifi_network_analytics(self, ssid: str = None) -> List[Dict[str, Any]]:
        """
        Get WiFi network analytics for one or all networks.
        
        Args:
            ssid: Specific SSID or None for all networks
            
        Returns:
            List of analytics dicts sorted by priority score
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if ssid:
                    cursor.execute("""
                        SELECT * FROM wifi_network_analytics
                        WHERE ssid = ?
                    """, (ssid,))
                else:
                    cursor.execute("""
                        SELECT * FROM wifi_network_analytics
                        ORDER BY priority_score DESC
                    """)
                
                columns = [desc[0] for desc in cursor.description]
                results = []
                
                for row in cursor.fetchall():
                    result = dict(zip(columns, row))
                    results.append(result)
                
                logger.debug(f"Retrieved analytics for {len(results)} WiFi networks")
                return results
                
        except Exception as e:
            logger.error(f"Error retrieving WiFi analytics: {e}")
            return []
    
    def get_recommended_networks(self, available_ssids: List[str] = None, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Get recommended WiFi networks based on historical performance.
        
        Args:
            available_ssids: List of currently available SSIDs (optional filter)
            limit: Maximum number of recommendations
            
        Returns:
            List of network analytics sorted by priority score
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if available_ssids:
                    placeholders = ','.join('?' * len(available_ssids))
                    cursor.execute(f"""
                        SELECT * FROM wifi_network_analytics
                        WHERE ssid IN ({placeholders})
                        AND success_rate > 50.0
                        ORDER BY priority_score DESC
                        LIMIT ?
                    """, (*available_ssids, limit))
                else:
                    cursor.execute("""
                        SELECT * FROM wifi_network_analytics
                        WHERE success_rate > 50.0
                        ORDER BY priority_score DESC
                        LIMIT ?
                    """, (limit,))
                
                columns = [desc[0] for desc in cursor.description]
                results = []
                
                for row in cursor.fetchall():
                    result = dict(zip(columns, row))
                    results.append(result)
                
                logger.info(f"Recommended {len(results)} WiFi networks")
                return results
                
        except Exception as e:
            logger.error(f"Error getting recommended networks: {e}")
            return []
    
    def get_wifi_connection_history(self, ssid: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get WiFi connection history.
        
        Args:
            ssid: Filter by specific SSID, or None for all
            limit: Maximum number of records to return
            
        Returns:
            List of connection history records
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if ssid:
                    cursor.execute("""
                        SELECT * FROM wifi_connection_history
                        WHERE ssid = ?
                        ORDER BY connection_time DESC
                        LIMIT ?
                    """, (ssid, limit))
                else:
                    cursor.execute("""
                        SELECT * FROM wifi_connection_history
                        ORDER BY connection_time DESC
                        LIMIT ?
                    """, (limit,))
                
                columns = [desc[0] for desc in cursor.description]
                results = []
                
                for row in cursor.fetchall():
                    result = dict(zip(columns, row))
                    results.append(result)
                
                return results
                
        except Exception as e:
            logger.error(f"Error retrieving WiFi connection history: {e}")
            return []
    
    def cleanup_old_wifi_data(self, days: int = 30):
        """
        Clean up old WiFi data to prevent database bloat.
        
        Args:
            days: Remove data older than this many days
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cutoff_date = datetime.now() - timedelta(days=days)
                
                # Remove old scan cache
                cursor.execute("""
                    DELETE FROM wifi_scan_cache
                    WHERE last_seen < ?
                """, (cutoff_date,))
                scan_deleted = cursor.rowcount
                
                # Remove old connection history
                cursor.execute("""
                    DELETE FROM wifi_connection_history
                    WHERE connection_time < ?
                """, (cutoff_date,))
                history_deleted = cursor.rowcount
                
                # Remove analytics for networks not seen in the time period
                cursor.execute("""
                    DELETE FROM wifi_network_analytics
                    WHERE last_connection_attempt < ?
                """, (cutoff_date,))
                analytics_deleted = cursor.rowcount
                
                conn.commit()
                logger.info(f"Cleaned up old WiFi data: {scan_deleted} scans, "
                          f"{history_deleted} history, {analytics_deleted} analytics")
                
        except Exception as e:
            logger.error(f"Error cleaning up WiFi data: {e}")

    # ========================================================================
    # Advanced Vulnerability Scanner Persistence Methods
    # ========================================================================

    def save_scan_job(self, scan_id: str, scan_type: str, target: str, status: str = 'pending',
                      progress_percent: int = 0, findings_count: int = 0, current_check: str = '',
                      started_at: datetime = None, completed_at: datetime = None,
                      error_message: str = '', options: dict = None) -> bool:
        """
        Save or update a scan job to the database.

        Args:
            scan_id: Unique scan identifier
            scan_type: Type of scan (nuclei, nikto, zap_full, etc.)
            target: Target URL or IP
            status: pending, running, completed, failed, cancelled
            progress_percent: 0-100
            findings_count: Number of findings discovered
            current_check: Current operation being performed
            started_at: When scan started
            completed_at: When scan completed
            error_message: Error message if failed
            options: Scan options dict (will be JSON serialized)

        Returns:
            bool: True if successful
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                options_json = json.dumps(options) if options else None

                cursor.execute("""
                    INSERT INTO scan_jobs (
                        scan_id, scan_type, target, status, progress_percent,
                        findings_count, current_check, started_at, completed_at,
                        error_message, options, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(scan_id) DO UPDATE SET
                        status = excluded.status,
                        progress_percent = excluded.progress_percent,
                        findings_count = excluded.findings_count,
                        current_check = excluded.current_check,
                        started_at = COALESCE(excluded.started_at, scan_jobs.started_at),
                        completed_at = excluded.completed_at,
                        error_message = excluded.error_message,
                        options = COALESCE(excluded.options, scan_jobs.options),
                        updated_at = CURRENT_TIMESTAMP
                """, (scan_id, scan_type, target, status, progress_percent,
                      findings_count, current_check, started_at, completed_at,
                      error_message, options_json))

                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to save scan job {scan_id}: {e}")
            return False

    def get_scan_job(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a scan job by ID.

        Args:
            scan_id: Unique scan identifier

        Returns:
            Dict with scan job data or None if not found
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM scan_jobs WHERE scan_id = ?", (scan_id,))
                row = cursor.fetchone()

                if row:
                    result = dict(row)
                    # Parse options JSON
                    if result.get('options'):
                        try:
                            result['options'] = json.loads(result['options'])
                        except json.JSONDecodeError:
                            result['options'] = {}
                    return result
                return None
        except Exception as e:
            logger.error(f"Failed to get scan job {scan_id}: {e}")
            return None

    def get_scan_jobs(self, status: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get scan jobs, optionally filtered by status.

        Args:
            status: Filter by status (pending, running, completed, failed)
            limit: Maximum number of records

        Returns:
            List of scan job dicts
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                if status:
                    cursor.execute("""
                        SELECT * FROM scan_jobs
                        WHERE status = ?
                        ORDER BY created_at DESC
                        LIMIT ?
                    """, (status, limit))
                else:
                    cursor.execute("""
                        SELECT * FROM scan_jobs
                        ORDER BY created_at DESC
                        LIMIT ?
                    """, (limit,))

                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    if result.get('options'):
                        try:
                            result['options'] = json.loads(result['options'])
                        except json.JSONDecodeError:
                            result['options'] = {}
                    results.append(result)

                return results
        except Exception as e:
            logger.error(f"Failed to get scan jobs: {e}")
            return []

    def get_interrupted_scans(self) -> List[Dict[str, Any]]:
        """
        Get scans that were interrupted (status is 'running' or 'pending' with old updated_at).
        These are scans that need recovery after restart.

        Returns:
            List of interrupted scan jobs
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                # Scans marked as 'running' are potentially interrupted
                cursor.execute("""
                    SELECT * FROM scan_jobs
                    WHERE status IN ('running', 'pending')
                    ORDER BY created_at DESC
                """)

                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    if result.get('options'):
                        try:
                            result['options'] = json.loads(result['options'])
                        except json.JSONDecodeError:
                            result['options'] = {}
                    results.append(result)

                return results
        except Exception as e:
            logger.error(f"Failed to get interrupted scans: {e}")
            return []

    def mark_scan_interrupted(self, scan_id: str) -> bool:
        """
        Mark a scan as interrupted (failed due to system restart).

        Args:
            scan_id: Scan ID to mark as interrupted

        Returns:
            bool: True if successful
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE scan_jobs
                    SET status = 'interrupted',
                        error_message = 'Scan interrupted by system restart',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE scan_id = ?
                """, (scan_id,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to mark scan {scan_id} as interrupted: {e}")
            return False

    def delete_scan_job(self, scan_id: str) -> bool:
        """
        Delete a scan job and its findings.

        Args:
            scan_id: Scan ID to delete

        Returns:
            bool: True if successful
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scan_jobs WHERE scan_id = ?", (scan_id,))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to delete scan job {scan_id}: {e}")
            return False

    def save_scan_finding(self, finding_id: str, scan_id: str, scanner: str, host: str,
                          port: int = None, severity: str = 'info', title: str = '',
                          description: str = '', cve_ids: List[str] = None,
                          cwe_ids: List[str] = None, cvss_score: float = None,
                          evidence: str = '', remediation: str = '',
                          references: List[str] = None, tags: List[str] = None,
                          matched_at: str = '', template_id: str = '',
                          raw_output: str = '', details: dict = None) -> bool:
        """
        Save a vulnerability finding to the database.

        Args:
            finding_id: Unique finding identifier
            scan_id: Parent scan ID
            scanner: Scanner that found it (nuclei, zap, nikto, etc.)
            host: Target host
            port: Target port (optional)
            severity: info, low, medium, high, critical
            title: Finding title
            description: Detailed description
            cve_ids: List of CVE IDs
            cwe_ids: List of CWE IDs
            cvss_score: CVSS score if available
            evidence: Evidence/proof
            remediation: How to fix
            references: List of reference URLs
            tags: List of tags
            matched_at: URL or location where found
            template_id: Template ID (for nuclei)
            raw_output: Raw scanner output
            details: Additional details dict

        Returns:
            bool: True if successful
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    INSERT INTO scan_findings (
                        finding_id, scan_id, scanner, host, port, severity, title,
                        description, cve_ids, cwe_ids, cvss_score, evidence,
                        remediation, reference_urls, tags, matched_at, template_id,
                        raw_output, details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(finding_id) DO UPDATE SET
                        severity = excluded.severity,
                        description = excluded.description,
                        evidence = excluded.evidence,
                        remediation = excluded.remediation
                """, (
                    finding_id, scan_id, scanner, host, port, severity, title,
                    description,
                    json.dumps(cve_ids) if cve_ids else None,
                    json.dumps(cwe_ids) if cwe_ids else None,
                    cvss_score, evidence[:5000] if evidence else None,
                    remediation,
                    json.dumps(references) if references else None,
                    json.dumps(tags) if tags else None,
                    matched_at, template_id,
                    raw_output[:10000] if raw_output else None,
                    json.dumps(details) if details else None
                ))

                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to save finding {finding_id}: {e}")
            return False

    def get_scan_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Get all findings for a specific scan.

        Args:
            scan_id: Scan ID to get findings for

        Returns:
            List of finding dicts
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM scan_findings
                    WHERE scan_id = ?
                    ORDER BY
                        CASE severity
                            WHEN 'critical' THEN 1
                            WHEN 'high' THEN 2
                            WHEN 'medium' THEN 3
                            WHEN 'low' THEN 4
                            ELSE 5
                        END,
                        timestamp DESC
                """, (scan_id,))

                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    # Parse JSON fields
                    for field in ['cve_ids', 'cwe_ids', 'reference_urls', 'tags', 'details']:
                        if result.get(field):
                            try:
                                result[field] = json.loads(result[field])
                            except json.JSONDecodeError:
                                result[field] = []
                    results.append(result)

                return results
        except Exception as e:
            logger.error(f"Failed to get findings for scan {scan_id}: {e}")
            return []

    def get_all_findings(self, severity: str = None, scanner: str = None,
                         host: str = None, limit: int = 500) -> List[Dict[str, Any]]:
        """
        Get all findings with optional filtering.

        Args:
            severity: Filter by severity
            scanner: Filter by scanner
            host: Filter by host
            limit: Maximum number of records

        Returns:
            List of finding dicts
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                query = "SELECT * FROM scan_findings WHERE 1=1"
                params = []

                if severity:
                    query += " AND severity = ?"
                    params.append(severity)
                if scanner:
                    query += " AND scanner = ?"
                    params.append(scanner)
                if host:
                    query += " AND host LIKE ?"
                    params.append(f"%{host}%")

                query += """
                    ORDER BY
                        CASE severity
                            WHEN 'critical' THEN 1
                            WHEN 'high' THEN 2
                            WHEN 'medium' THEN 3
                            WHEN 'low' THEN 4
                            ELSE 5
                        END,
                        timestamp DESC
                    LIMIT ?
                """
                params.append(limit)

                cursor.execute(query, params)

                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    for field in ['cve_ids', 'cwe_ids', 'reference_urls', 'tags', 'details']:
                        if result.get(field):
                            try:
                                result[field] = json.loads(result[field])
                            except json.JSONDecodeError:
                                result[field] = []
                    results.append(result)

                return results
        except Exception as e:
            logger.error(f"Failed to get all findings: {e}")
            return []

    def get_findings_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics for all findings.

        Returns:
            Dict with summary stats (counts by severity, scanner, etc.)
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                summary = {
                    'total': 0,
                    'by_severity': {},
                    'by_scanner': {},
                    'unique_hosts': 0
                }

                # Total count
                cursor.execute("SELECT COUNT(*) FROM scan_findings")
                summary['total'] = cursor.fetchone()[0]

                # By severity
                cursor.execute("""
                    SELECT severity, COUNT(*) as count
                    FROM scan_findings
                    GROUP BY severity
                """)
                for row in cursor.fetchall():
                    summary['by_severity'][row['severity']] = row['count']

                # By scanner
                cursor.execute("""
                    SELECT scanner, COUNT(*) as count
                    FROM scan_findings
                    GROUP BY scanner
                """)
                for row in cursor.fetchall():
                    summary['by_scanner'][row['scanner']] = row['count']

                # Unique hosts
                cursor.execute("SELECT COUNT(DISTINCT host) FROM scan_findings")
                summary['unique_hosts'] = cursor.fetchone()[0]

                return summary
        except Exception as e:
            logger.error(f"Failed to get findings summary: {e}")
            return {'total': 0, 'by_severity': {}, 'by_scanner': {}, 'unique_hosts': 0}

    def cleanup_old_scans(self, days: int = 30) -> int:
        """
        Clean up old scan jobs and their findings.

        Args:
            days: Remove scans older than this many days

        Returns:
            Number of scans deleted
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cutoff_date = datetime.now() - timedelta(days=days)

                # Get count before deletion
                cursor.execute("""
                    SELECT COUNT(*) FROM scan_jobs
                    WHERE created_at < ? AND status IN ('completed', 'failed', 'cancelled', 'interrupted')
                """, (cutoff_date,))
                count = cursor.fetchone()[0]

                # Delete old scans (findings will cascade)
                cursor.execute("""
                    DELETE FROM scan_jobs
                    WHERE created_at < ? AND status IN ('completed', 'failed', 'cancelled', 'interrupted')
                """, (cutoff_date,))

                conn.commit()
                logger.info(f"Cleaned up {count} old scan jobs")
                return count
        except Exception as e:
            logger.error(f"Failed to cleanup old scans: {e}")
            return 0

    # ================================================================
    # ZAP Target Credentials Methods
    # ================================================================

    def save_zap_credentials(self, target_host: str, auth_type: str,
                             login_url: str = None, username: str = None,
                             password: str = None, login_request_data: str = None,
                             username_field: str = 'username', password_field: str = 'password',
                             http_realm: str = None, notes: str = None,
                             bearer_token: str = None, api_key: str = None,
                             api_key_header: str = 'X-API-Key', cookie_value: str = None) -> bool:
        """
        Save or update ZAP authentication credentials for a target.

        Args:
            target_host: Target host/IP (e.g., "192.168.1.1" or "example.com")
            auth_type: Authentication type ('form', 'http_basic', 'bearer_token', 'api_key', 'cookie', 'none')
            login_url: URL of login page (for form auth)
            username: Username for authentication
            password: Password (will be base64 encoded, not truly encrypted)
            login_request_data: Custom POST data template
            username_field: Name of username field
            password_field: Name of password field
            http_realm: HTTP realm (for basic auth)
            notes: Optional notes about the credentials
            bearer_token: Bearer/JWT token for API authentication
            api_key: API key for header-based authentication
            api_key_header: Header name for API key (default: X-API-Key)
            cookie_value: Cookie string for cookie-based authentication

        Returns:
            True if saved successfully
        """
        import base64

        try:
            # Normalize target host (remove protocol, trailing slashes)
            target_host = self._normalize_target_host(target_host)

            # Base64 encode sensitive values (basic obfuscation - not secure encryption)
            password_encoded = None
            if password:
                password_encoded = base64.b64encode(password.encode('utf-8')).decode('utf-8')

            bearer_token_encoded = None
            if bearer_token:
                bearer_token_encoded = base64.b64encode(bearer_token.encode('utf-8')).decode('utf-8')

            api_key_encoded = None
            if api_key:
                api_key_encoded = base64.b64encode(api_key.encode('utf-8')).decode('utf-8')

            cookie_value_encoded = None
            if cookie_value:
                cookie_value_encoded = base64.b64encode(cookie_value.encode('utf-8')).decode('utf-8')

            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Upsert credentials
                cursor.execute("""
                    INSERT INTO zap_target_credentials
                    (target_host, auth_type, login_url, username, password_encrypted,
                     login_request_data, username_field, password_field, http_realm, notes,
                     bearer_token_encrypted, api_key_encrypted, api_key_header, cookie_value_encrypted, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(target_host) DO UPDATE SET
                        auth_type = excluded.auth_type,
                        login_url = excluded.login_url,
                        username = excluded.username,
                        password_encrypted = excluded.password_encrypted,
                        login_request_data = excluded.login_request_data,
                        username_field = excluded.username_field,
                        password_field = excluded.password_field,
                        http_realm = excluded.http_realm,
                        notes = excluded.notes,
                        bearer_token_encrypted = excluded.bearer_token_encrypted,
                        api_key_encrypted = excluded.api_key_encrypted,
                        api_key_header = excluded.api_key_header,
                        cookie_value_encrypted = excluded.cookie_value_encrypted,
                        updated_at = CURRENT_TIMESTAMP
                """, (target_host, auth_type, login_url, username, password_encoded,
                      login_request_data, username_field, password_field, http_realm, notes,
                      bearer_token_encoded, api_key_encoded, api_key_header, cookie_value_encoded))

                conn.commit()
                logger.info(f"Saved ZAP credentials for target: {target_host}")
                return True

        except Exception as e:
            logger.error(f"Failed to save ZAP credentials for {target_host}: {e}")
            return False

    def get_zap_credentials(self, target_host: str) -> Optional[Dict[str, Any]]:
        """
        Get ZAP credentials for a specific target.

        Args:
            target_host: Target host/IP to look up

        Returns:
            Dict with credentials or None if not found
        """
        import base64

        try:
            # Normalize target host
            target_host = self._normalize_target_host(target_host)

            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM zap_target_credentials WHERE target_host = ?
                """, (target_host,))

                row = cursor.fetchone()
                if row:
                    result = dict(row)

                    # Decode password
                    if result.get('password_encrypted'):
                        try:
                            result['password'] = base64.b64decode(
                                result['password_encrypted'].encode('utf-8')
                            ).decode('utf-8')
                        except Exception:
                            result['password'] = None
                    else:
                        result['password'] = None
                    if 'password_encrypted' in result:
                        del result['password_encrypted']

                    # Decode bearer token
                    if result.get('bearer_token_encrypted'):
                        try:
                            result['bearer_token'] = base64.b64decode(
                                result['bearer_token_encrypted'].encode('utf-8')
                            ).decode('utf-8')
                        except Exception:
                            result['bearer_token'] = None
                    else:
                        result['bearer_token'] = None
                    if 'bearer_token_encrypted' in result:
                        del result['bearer_token_encrypted']

                    # Decode API key
                    if result.get('api_key_encrypted'):
                        try:
                            result['api_key'] = base64.b64decode(
                                result['api_key_encrypted'].encode('utf-8')
                            ).decode('utf-8')
                        except Exception:
                            result['api_key'] = None
                    else:
                        result['api_key'] = None
                    if 'api_key_encrypted' in result:
                        del result['api_key_encrypted']

                    # Decode cookie value
                    if result.get('cookie_value_encrypted'):
                        try:
                            result['cookie_value'] = base64.b64decode(
                                result['cookie_value_encrypted'].encode('utf-8')
                            ).decode('utf-8')
                        except Exception:
                            result['cookie_value'] = None
                    else:
                        result['cookie_value'] = None
                    if 'cookie_value_encrypted' in result:
                        del result['cookie_value_encrypted']

                    return result

                return None

        except Exception as e:
            logger.error(f"Failed to get ZAP credentials for {target_host}: {e}")
            return None

    def get_zap_credentials_for_url(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Get ZAP credentials for a URL (extracts host and looks up).

        Args:
            url: Full URL (e.g., "http://192.168.1.1:8080/app")

        Returns:
            Dict with credentials or None if not found
        """
        import urllib.parse

        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.netloc or url

            # Try with port first, then without
            result = self.get_zap_credentials(host)
            if result:
                return result

            # Try without port
            host_no_port = host.split(':')[0]
            if host_no_port != host:
                return self.get_zap_credentials(host_no_port)

            return None

        except Exception as e:
            logger.error(f"Failed to get ZAP credentials for URL {url}: {e}")
            return None

    def delete_zap_credentials(self, target_host: str) -> bool:
        """
        Delete ZAP credentials for a target.

        Args:
            target_host: Target host/IP to delete credentials for

        Returns:
            True if deleted (or didn't exist)
        """
        try:
            target_host = self._normalize_target_host(target_host)

            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    DELETE FROM zap_target_credentials WHERE target_host = ?
                """, (target_host,))
                conn.commit()

                if cursor.rowcount > 0:
                    logger.info(f"Deleted ZAP credentials for target: {target_host}")
                return True

        except Exception as e:
            logger.error(f"Failed to delete ZAP credentials for {target_host}: {e}")
            return False

    def list_zap_credentials(self) -> List[Dict[str, Any]]:
        """
        List all saved ZAP credentials (without passwords).

        Returns:
            List of credential entries (passwords masked)
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, target_host, auth_type, login_url, username,
                           username_field, password_field, http_realm, notes,
                           created_at, updated_at
                    FROM zap_target_credentials
                    ORDER BY updated_at DESC
                """)

                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    # Indicate if password is set without revealing it
                    result['has_password'] = True  # If row exists, password was provided
                    results.append(result)

                return results

        except Exception as e:
            logger.error(f"Failed to list ZAP credentials: {e}")
            return []

    def check_zap_credentials_exist(self, target_host: str) -> Dict[str, Any]:
        """
        Check if credentials exist for a target (without returning password).

        Args:
            target_host: Target host/IP to check

        Returns:
            Dict with exists: bool, auth_type: str, username: str (if exists)
        """
        try:
            target_host = self._normalize_target_host(target_host)

            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT auth_type, username, login_url, notes
                    FROM zap_target_credentials WHERE target_host = ?
                """, (target_host,))

                row = cursor.fetchone()
                if row:
                    return {
                        'exists': True,
                        'auth_type': row['auth_type'],
                        'username': row['username'],
                        'login_url': row['login_url'],
                        'notes': row['notes']
                    }

                return {'exists': False}

        except Exception as e:
            logger.error(f"Failed to check ZAP credentials for {target_host}: {e}")
            return {'exists': False, 'error': str(e)}

    def _normalize_target_host(self, target: str) -> str:
        """
        Normalize a target URL/host for consistent storage.
        Extracts just the host:port portion.
        """
        import urllib.parse

        if not target:
            return ''

        # If it looks like a URL, parse it
        if '://' in target:
            parsed = urllib.parse.urlparse(target)
            host = parsed.netloc or parsed.path
        else:
            host = target

        # Remove trailing slashes and paths
        host = host.split('/')[0]

        # Lowercase for consistency
        return host.lower().strip()


# Singleton instance
_db_instance = None
_db_lock = threading.Lock()

def get_db(currentdir: str = None) -> DatabaseManager:
    """
    Get singleton DatabaseManager instance.
    Thread-safe lazy initialization.

    Args:
        currentdir: Root directory of Ragnar installation

    Returns:
        DatabaseManager instance
    """
    global _db_instance

    if _db_instance is None:
        with _db_lock:
            if _db_instance is None:
                _db_instance = DatabaseManager(currentdir=currentdir)

    return _db_instance


def close_db():
    """Close the singleton database instance. Used before encrypting the DB file."""
    global _db_instance
    with _db_lock:
        _db_instance = None


def reinit_db(currentdir: str = None) -> DatabaseManager:
    """Reinitialize the singleton database instance. Used after decrypting the DB file."""
    global _db_instance
    with _db_lock:
        _db_instance = DatabaseManager(currentdir=currentdir)
    return _db_instance


if __name__ == "__main__":
    # Test the database manager
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    db = DatabaseManager()
    
    # Test upsert
    db.upsert_host(
        mac="aa:bb:cc:dd:ee:ff",
        ip="192.168.1.100",
        hostname="test-host",
        vendor="Test Vendor",
        ports="22,80,443"
    )
    
    # Test get
    host = db.get_host_by_mac("aa:bb:cc:dd:ee:ff")
    print(f"Host: {host}")
    
    # Test stats
    stats = db.get_stats()
    print(f"Stats: {stats}")
    
    # Test ping tracking
    db.update_ping_status("aa:bb:cc:dd:ee:ff", success=True)
    
    print("Database tests completed successfully!")
