# advanced_vuln_scanner.py
"""
Advanced Vulnerability Assessment Module for Ragnar Server Mode

This module provides enhanced vulnerability scanning capabilities
only available when running on a capable server (8GB+ RAM).

Features:
- Nuclei template-based scanning
- Nikto web server assessment
- SQLMap SQL injection testing
- OWASP ZAP web application scanning
- Parallel vulnerability scanning
- CVE correlation and enrichment
- Exploit suggestion engine
"""

import os
import re
import json
import time
import shutil
import threading
import subprocess
import tempfile
import logging
import urllib.request
import urllib.parse
import urllib.error
import socket
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed  # kept for _run_full_scan only
from queue import Queue, Empty

from logger import Logger
from server_capabilities import get_server_capabilities, is_server_mode

logger = Logger(name="advanced_vuln_scanner", level=logging.INFO)


class VulnSeverity(Enum):
    """Vulnerability severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @classmethod
    def from_string(cls, value: str) -> 'VulnSeverity':
        """Convert string to severity, with fallback"""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.INFO


class ScanType(Enum):
    """Types of vulnerability scans"""
    NUCLEI = "nuclei"
    NIKTO = "nikto"
    SQLMAP = "sqlmap"
    NMAP_VULN = "nmap_vuln"
    WHATWEB = "whatweb"
    ZAP_SPIDER = "zap_spider"
    ZAP_ACTIVE = "zap_active"
    ZAP_FULL = "zap_full"
    FULL = "full"


class ScanStrength(Enum):
    """ZAP scan strength profiles"""
    STANDARD = "standard"
    THOROUGH = "thorough"
    INSANE = "insane"


@dataclass
class VulnerabilityFinding:
    """A single vulnerability finding"""
    finding_id: str
    scanner: str
    host: str
    port: Optional[int]
    severity: VulnSeverity
    title: str
    description: str
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    evidence: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    matched_at: str = ""
    template_id: str = ""
    raw_output: str = ""
    details: Dict[str, Any] = field(default_factory=dict)  # Additional scanner-specific details
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'finding_id': self.finding_id,
            'scanner': self.scanner,
            'host': self.host,
            'port': self.port,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'cve_ids': self.cve_ids,
            'cwe_ids': self.cwe_ids,
            'cvss_score': self.cvss_score,
            'evidence': self.evidence[:1000],  # Limit size
            'remediation': self.remediation,
            'references': self.references[:10],
            'tags': self.tags,
            'matched_at': self.matched_at,
            'template_id': self.template_id,
            'details': self.details,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ScanProgress:
    """Progress tracking for a scan"""
    scan_id: str
    scan_type: ScanType
    target: str
    status: str  # pending, running, completed, failed
    progress_percent: int = 0
    findings_count: int = 0
    current_check: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: str = ""
    auth_type: str = ""  # Auth type used for this scan (cookie, bearer_token, etc.)
    auth_status: str = ""  # Auth validation status (applied, verified, failed)
    log_entries: List[Dict[str, str]] = field(default_factory=list)  # Buffered scan log entries

    def to_dict(self) -> Dict[str, Any]:
        return {
            'scan_id': self.scan_id,
            'scan_type': self.scan_type.value,
            'target': self.target,
            'status': self.status,
            'progress_percent': self.progress_percent,
            'findings_count': self.findings_count,
            'current_check': self.current_check,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'error_message': self.error_message,
            'auth_type': self.auth_type,
            'auth_status': self.auth_status,
            'duration_seconds': (
                (self.completed_at or datetime.now()) - self.started_at
            ).total_seconds() if self.started_at else 0
        }


class AdvancedVulnScanner:
    """
    Advanced vulnerability scanner for Ragnar server mode.

    Provides enterprise-grade vulnerability scanning using:
    - Nuclei for template-based scanning
    - Nikto for web server assessment
    - SQLMap for SQL injection testing
    - OWASP ZAP for web application security testing
    - Enhanced nmap vuln scripts
    """

    # Nuclei severity mapping
    NUCLEI_SEVERITY_MAP = {
        'info': VulnSeverity.INFO,
        'low': VulnSeverity.LOW,
        'medium': VulnSeverity.MEDIUM,
        'high': VulnSeverity.HIGH,
        'critical': VulnSeverity.CRITICAL,
    }

    # ZAP severity/risk mapping (ZAP uses 0-3 risk levels)
    ZAP_RISK_MAP = {
        0: VulnSeverity.INFO,       # Informational
        1: VulnSeverity.LOW,        # Low
        2: VulnSeverity.MEDIUM,     # Medium
        3: VulnSeverity.HIGH,       # High
    }
    ZAP_RISK_NAME_MAP = {
        'informational': VulnSeverity.INFO,
        'low': VulnSeverity.LOW,
        'medium': VulnSeverity.MEDIUM,
        'high': VulnSeverity.HIGH,
    }

    # ZAP confidence levels
    ZAP_CONFIDENCE_MAP = {
        0: 'False Positive',
        1: 'Low',
        2: 'Medium',
        3: 'High',
        4: 'Confirmed',
    }
    ZAP_CONFIDENCE_NAME_MAP = {
        'false positive': 'False Positive',
        'low': 'Low',
        'medium': 'Medium',
        'high': 'High',
        'confirmed': 'Confirmed',
    }

    # Default Nuclei templates (fast scan)
    NUCLEI_FAST_TEMPLATES = [
        'cves/', 'default-logins/', 'exposures/', 'misconfiguration/',
        'technologies/', 'takeovers/'
    ]

    # Full Nuclei templates
    NUCLEI_FULL_TEMPLATES = [
        'cves/', 'default-logins/', 'exposures/', 'misconfiguration/',
        'technologies/', 'takeovers/', 'vulnerabilities/', 'fuzzing/'
    ]

    # ZAP configuration
    ZAP_DEFAULT_PORT = 8090
    ZAP_API_KEY_LENGTH = 32
    ZAP_STARTUP_TIMEOUT = 90  # seconds to wait for ZAP to start (ARM override: 180s)
    ZAP_SCAN_POLICIES = ['Default Policy', 'Light', 'Medium', 'High']

    # Scan strength profiles for deep scanning
    SCAN_STRENGTH_PROFILES = {
        'standard': {
            'attack_strength': 'MEDIUM',
            'alert_threshold': 'MEDIUM',
            'spider_max_children': 20,
            'spider_timeout': 300,
            'ajax_timeout': 60,
            'ajax_timeout_auth': 120,
            'active_scan_timeout': 1800,
            'stall_threshold': 24,
            'threads_per_host': 2,
            'spider_depth': 5,
            'enable_fuzzer': False,
            'payloads_per_param': 0,
        },
        'thorough': {
            'attack_strength': 'HIGH',
            'alert_threshold': 'LOW',
            'spider_max_children': 30,
            'spider_timeout': 450,
            'ajax_timeout': 90,
            'ajax_timeout_auth': 180,
            'active_scan_timeout': 2700,
            'stall_threshold': 36,
            'threads_per_host': 3,
            'spider_depth': 8,
            'enable_fuzzer': True,
            'payloads_per_param': 20,
        },
        'insane': {
            'attack_strength': 'INSANE',
            'alert_threshold': 'LOW',
            'spider_max_children': 50,
            'spider_timeout': 900,
            'ajax_timeout': 180,
            'ajax_timeout_auth': 300,
            'active_scan_timeout': 5400,
            'stall_threshold': 60,
            'threads_per_host': 5,
            'spider_depth': 12,
            'enable_fuzzer': True,
            'payloads_per_param': 50,
        },
    }

    # Injection scanner plugin IDs for scan policy configuration
    ZAP_INJECTION_SCANNER_IDS = [
        # XSS
        40012, 40014, 40016, 40017,
        # SQL Injection
        40018, 40019, 40020, 40021, 40022, 40024, 40026, 40027,
        # Remote Code Execution / Injection
        40003, 40008, 40009, 40032, 40033, 90019, 90020, 90025,
        # XXE / XML
        40034, 90023, 90029,
        # SSRF
        40046, 90034,
        # Deserialization
        90035, 90036,
        # Log4Shell / Spring4Shell
        40043, 40045,
        # Path Traversal / File Inclusion
        6, 7, 10045, 10095,
        # Session / Auth
        40013, 40026, 10058,
        # Header / Protocol
        10105, 10104,
        # Misc injection
        30001, 30002, 90021, 90024, 40028, 10048,
        # LDAP / NoSQL
        40015, 90028,
    ]

    # Ragnar-Fuzz payload library
    RAGNAR_FUZZ_PAYLOADS = {
        'xss_basic': [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
        ],
        'xss_polyglot': [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",
            '"><img src=x onerror=alert(String.fromCharCode(88,83,83))>',
            '<svg/onload=alert`1`>',
        ],
        'xss_waf_bypass': [
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
            '<img src=x onerror=\\u0061lert(1)>',
        ],
        'xss_attribute': [
            '" onfocus="alert(1)" autofocus="',
            "' onfocus='alert(1)' autofocus='",
            '" onmouseover="alert(1)" "',
            "' onmouseover='alert(1)' '",
        ],
        'xss_js_context': [
            "';alert(1)//",
            '";alert(1)//',
            '</script><script>alert(1)</script>',
            "\\';alert(1);//",
            "javascript:alert(1)",
            "javascript:alert(1)//",
        ],
        'xss_js_uri': [
            'javascript:alert(1)',
            'jAvAsCrIpT:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'vbscript:alert(1)',
        ],
        'xss_url_encoded': [
            '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
            '%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E',
            '%27%3E%3Csvg%20onload%3Dalert(1)%3E',
        ],
        'xss_double_encoded': [
            '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
            '%2522%253E%253Cscript%253Ealert(1)%253C%252Fscript%253E',
        ],
        'xss_unicode': [
            '\u003cscript\u003ealert(1)\u003c/script\u003e',
            '\uff1cscript\uff1ealert(1)\uff1c/script\uff1e',
            '\u0022\u003e\u003cscript\u003ealert(1)\u003c/script\u003e',
        ],
        'xss_html_entity': [
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
            '&quot; onfocus=&quot;alert(1)&quot; autofocus=&quot;',
        ],
        'ssti': [
            '{{7*7}}', '${7*7}', '<%= 7*7 %>', '#{7*7}',
            '{{constructor.constructor("return this")()}}',
            '${T(java.lang.Runtime).getRuntime().exec("id")}',
            '{% import os %}{{ os.popen("id").read() }}',
            '{{config.__class__.__init__.__globals__["os"].popen("id").read()}}',
            '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
            '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
        ],
        'sqli': [
            "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--",
            "1 UNION SELECT NULL--", "1' AND SLEEP(5)--",
            "' WAITFOR DELAY '0:0:5'--",
            "1; DROP TABLE users--",
            "admin'--", "' OR ''='",
            "1' ORDER BY 1--",
            "') OR ('1'='1",
            "1 AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        ],
        'cmdi': [
            '; id', '| id', '`id`', '$(id)',
            '; cat /etc/passwd', '| cat /etc/passwd',
            '& whoami', '&& whoami',
        ],
        'path_traversal': [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '..%2f..%2f..%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd',
        ],
        'ssrf': [
            'http://127.0.0.1',
            'http://169.254.169.254/latest/meta-data/',
            'http://[::1]',
            'http://0x7f000001',
            'http://localhost:22',
        ],
        'xxe': [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        ],
        'crlf': [
            '%0d%0aSet-Cookie:ragnar=test',
            '\\r\\nX-Injected: ragnar',
            '%0AHost: evil.com',
        ],
        'log4shell': [
            '${jndi:ldap://127.0.0.1/a}',
            '${jndi:dns://127.0.0.1/a}',
        ],
        'deserialization': [
            'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==',
            'O:8:"stdClass":0:{}',
            'a]a:1:{s:1:"a";O:8:"stdClass":0:{}}',
        ],
    }

    # Common test parameter names for synthetic fuzz targets
    FUZZ_SYNTHETIC_PARAMS = [
        'id', 'q', 'search', 'query', 'name', 'page', 'redirect',
        'url', 'file', 'path', 'callback', 'next', 'return', 'ref',
    ]

    def __init__(self, shared_data=None):
        self.shared_data = shared_data
        self._lock = threading.Lock()

        # Scan tracking
        self.active_scans: Dict[str, ScanProgress] = {}
        self.scan_results: Dict[str, List[VulnerabilityFinding]] = {}
        self._scan_counter = 0

        # Scan history (deque for recent scans)
        from collections import deque
        self.scan_history: deque = deque(maxlen=100)

        # Scan threading (direct threads instead of ThreadPoolExecutor
        # to avoid "cannot schedule new futures after interpreter shutdown"
        # on Python 3.12+/3.13 where atexit shuts down executors early)
        self._max_workers = 4  # Configurable based on system

        # Tool paths
        self._tool_paths = {}
        self._detect_tools()

        # ZAP daemon management
        self._zap_process: Optional[subprocess.Popen] = None
        self._zap_port = self.ZAP_DEFAULT_PORT
        self._zap_api_key = self._generate_api_key()
        self._zap_base_url = f"http://127.0.0.1:{self._zap_port}"
        self._zap_watchdog_stop = threading.Event()
        self._zap_user_stopped = False  # True when user explicitly stops ZAP
        self._zap_busy = False  # True during startup or active scan — suppresses watchdog
        self._zap_start_lock = threading.Lock()  # Prevents concurrent start_zap_daemon calls

        # Check capabilities
        caps = get_server_capabilities(shared_data)
        if caps.capabilities.parallel_scanning_enabled:
            self._max_workers = min(caps.capabilities.cpu_cores, 8)

        # Database manager reference
        self._db = None
        self._init_database()

        # Recover any interrupted scans on startup
        self._recover_interrupted_scans()

        # Watchdog thread: auto-starts ZAP and keeps it alive
        if self._tool_paths.get('zap'):
            threading.Thread(target=self._zap_watchdog, daemon=True).start()

    def _init_database(self):
        """Initialize database connection for scan persistence"""
        try:
            from db_manager import get_db
            self._db = get_db()
            logger.info("Database connection initialized for scan persistence")
        except Exception as e:
            logger.warning(f"Database initialization failed (scans will not persist): {e}")
            self._db = None

    def _recover_interrupted_scans(self):
        """Mark interrupted scans and optionally recover them"""
        if not self._db:
            return

        try:
            interrupted = self._db.get_interrupted_scans()
            for scan in interrupted:
                scan_id = scan.get('scan_id')
                status = scan.get('status')

                if status == 'running':
                    # Mark as interrupted - it was running when system restarted
                    self._db.mark_scan_interrupted(scan_id)
                    logger.info(f"Marked scan {scan_id} as interrupted")

                    # Create a progress entry for UI display
                    progress = ScanProgress(
                        scan_id=scan_id,
                        scan_type=ScanType(scan.get('scan_type', 'nuclei')),
                        target=scan.get('target', ''),
                        status='interrupted',
                        progress_percent=scan.get('progress_percent', 0),
                        findings_count=scan.get('findings_count', 0),
                        current_check=scan.get('current_check', ''),
                        error_message='Scan interrupted by system restart'
                    )
                    if scan.get('started_at'):
                        try:
                            progress.started_at = datetime.fromisoformat(scan['started_at'].replace('Z', '+00:00'))
                        except (ValueError, TypeError):
                            pass

                    self.active_scans[scan_id] = progress
                    self.scan_history.append(progress)

                    # Load existing findings from database
                    findings_data = self._db.get_scan_findings(scan_id)
                    self.scan_results[scan_id] = [
                        self._dict_to_finding(f) for f in findings_data
                    ]

            logger.info(f"Recovered {len(interrupted)} interrupted scans")
        except Exception as e:
            logger.error(f"Error recovering interrupted scans: {e}")

    def _zap_watchdog(self):
        """Background watchdog that starts the ZAP daemon and keeps it alive.

        Polls every 30 seconds.  Requires 3 consecutive failed health checks
        (~90 s) before attempting a restart, to tolerate brief Java GC pauses
        on ARM.  Uses back-off for repeated restart failures.
        """
        POLL_INTERVAL = 30          # seconds between health checks
        FAILURES_BEFORE_RESTART = 3 # require 3 consecutive failures (~90s)
        BACKOFF_DELAYS = [30, 60, 120]  # restart back-off schedule
        consecutive_failures = 0
        restart_attempts = 0

        while not self._zap_watchdog_stop.is_set():
            try:
                if self._zap_user_stopped or self._zap_busy:
                    self._zap_watchdog_stop.wait(timeout=POLL_INTERVAL)
                    continue

                if self._is_zap_running():
                    consecutive_failures = 0
                    restart_attempts = 0
                    self._zap_watchdog_stop.wait(timeout=POLL_INTERVAL)
                    continue

                # ZAP health check failed
                consecutive_failures += 1
                if consecutive_failures < FAILURES_BEFORE_RESTART:
                    logger.debug(
                        f"[ZAP-WATCHDOG] Health check failed "
                        f"({consecutive_failures}/{FAILURES_BEFORE_RESTART}), "
                        f"will retry before restarting"
                    )
                    self._zap_watchdog_stop.wait(timeout=POLL_INTERVAL)
                    continue

                # Confirmed down after multiple checks — attempt restart
                restart_attempts += 1
                delay_idx = min(restart_attempts - 1, len(BACKOFF_DELAYS) - 1)
                logger.warning(
                    f"[ZAP-WATCHDOG] ZAP daemon confirmed down after "
                    f"{consecutive_failures} checks, restarting "
                    f"(attempt {restart_attempts})..."
                )
                self._zap_busy = True
                try:
                    if self.start_zap_daemon():
                        logger.info("[ZAP-WATCHDOG] ZAP daemon restarted successfully")
                        consecutive_failures = 0
                        restart_attempts = 0
                    else:
                        backoff = BACKOFF_DELAYS[delay_idx]
                        logger.warning(
                            f"[ZAP-WATCHDOG] Restart failed, retrying in {backoff}s"
                        )
                        consecutive_failures = 0  # reset so we wait again
                        self._zap_watchdog_stop.wait(timeout=backoff)
                        continue
                finally:
                    self._zap_busy = False

            except Exception as exc:
                logger.debug(f"[ZAP-WATCHDOG] Error during health check: {exc}")

            self._zap_watchdog_stop.wait(timeout=POLL_INTERVAL)

    def _dict_to_finding(self, data: Dict) -> VulnerabilityFinding:
        """Convert a dictionary (from DB) back to VulnerabilityFinding"""
        # Handle both 'reference_urls' (DB column) and 'references' (legacy/API)
        refs = data.get('reference_urls') or data.get('references', [])

        # Parse timestamp from DB (stored as ISO string)
        timestamp = datetime.now()
        if data.get('timestamp'):
            try:
                if isinstance(data['timestamp'], str):
                    timestamp = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
                elif isinstance(data['timestamp'], datetime):
                    timestamp = data['timestamp']
            except (ValueError, TypeError):
                pass

        return VulnerabilityFinding(
            finding_id=data.get('finding_id', ''),
            scanner=data.get('scanner', ''),
            host=data.get('host', ''),
            port=data.get('port'),
            severity=VulnSeverity.from_string(data.get('severity', 'info')),
            title=data.get('title', ''),
            description=data.get('description', ''),
            cve_ids=data.get('cve_ids', []) if data.get('cve_ids') else [],
            cwe_ids=data.get('cwe_ids', []) if data.get('cwe_ids') else [],
            cvss_score=data.get('cvss_score'),
            evidence=data.get('evidence', '') or '',
            remediation=data.get('remediation', '') or '',
            references=refs if refs else [],
            tags=data.get('tags', []) if data.get('tags') else [],
            matched_at=data.get('matched_at', '') or '',
            template_id=data.get('template_id', '') or '',
            raw_output=data.get('raw_output', '') or '',
            details=data.get('details', {}) if data.get('details') else {},
            timestamp=timestamp
        )

    def _save_scan_to_db(self, scan_id: str, progress: ScanProgress, options: Dict = None):
        """Save scan progress to database"""
        if not self._db:
            return

        try:
            self._db.save_scan_job(
                scan_id=scan_id,
                scan_type=progress.scan_type.value,
                target=progress.target,
                status=progress.status,
                progress_percent=progress.progress_percent,
                findings_count=progress.findings_count,
                current_check=progress.current_check,
                started_at=progress.started_at,
                completed_at=progress.completed_at,
                error_message=progress.error_message,
                options=options
            )
        except Exception as e:
            logger.debug(f"Error saving scan to DB: {e}")

    def _save_finding_to_db(self, finding: VulnerabilityFinding, scan_id: str):
        """Save a finding to the database"""
        if not self._db:
            return

        try:
            self._db.save_scan_finding(
                finding_id=finding.finding_id,
                scan_id=scan_id,
                scanner=finding.scanner,
                host=finding.host,
                port=finding.port,
                severity=finding.severity.value,
                title=finding.title,
                description=finding.description,
                cve_ids=finding.cve_ids,
                cwe_ids=finding.cwe_ids,
                cvss_score=finding.cvss_score,
                evidence=finding.evidence,
                remediation=finding.remediation,
                references=finding.references,
                tags=finding.tags,
                matched_at=finding.matched_at,
                template_id=finding.template_id,
                raw_output=finding.raw_output,
                details=finding.details
            )
        except Exception as e:
            logger.debug(f"Error saving finding to DB: {e}")

    def _update_progress(self, scan_id: str, progress_percent: int = None,
                         current_check: str = None, findings_count: int = None):
        """Update scan progress and persist to database (call periodically during scans)"""
        progress = self.active_scans.get(scan_id)
        if not progress:
            return

        if progress_percent is not None:
            progress.progress_percent = progress_percent
        if current_check is not None:
            progress.current_check = current_check
        if findings_count is not None:
            progress.findings_count = findings_count
        else:
            progress.findings_count = len(self.scan_results.get(scan_id, []))

        # Persist progress to database
        self._save_scan_to_db(scan_id, progress)

    def _scan_log(self, scan_id: str, level: str, message: str):
        """Log a message and buffer it for the scan's live log feed"""
        log_func = getattr(logger, level, logger.info)
        log_func(f"[{scan_id}] {message}")

        progress = self.active_scans.get(scan_id)
        if progress:
            entry = {
                'timestamp': datetime.now().isoformat(),
                'level': level,
                'message': message
            }
            progress.log_entries.append(entry)
            # Cap log buffer to prevent memory bloat
            if len(progress.log_entries) > 500:
                progress.log_entries = progress.log_entries[-500:]

    def get_scan_logs(self, scan_id: str, since_index: int = 0) -> List[Dict]:
        """Get log entries for a scan, optionally starting from an index"""
        progress = self.active_scans.get(scan_id)
        if progress:
            return progress.log_entries[since_index:]
        return []

    def _get_strength_profile(self, options: Dict) -> Dict:
        """Get scan strength profile configuration from options."""
        strength = options.get('scan_strength', 'standard')
        return self.SCAN_STRENGTH_PROFILES.get(strength, self.SCAN_STRENGTH_PROFILES['standard'])

    def _build_fuzz_auth_headers(self, options: Dict) -> Dict[str, str]:
        """Build HTTP headers dict from scan auth options for direct requests."""
        headers = {}
        if not options:
            return headers
        if options.get('bearer_token'):
            headers['Authorization'] = f"Bearer {options['bearer_token']}"
        elif options.get('http_basic_auth'):
            import base64
            creds = options['http_basic_auth']
            encoded = base64.b64encode(creds.encode('utf-8')).decode('utf-8')
            headers['Authorization'] = f"Basic {encoded}"
        elif options.get('api_key'):
            header_name = options.get('api_key_header', 'X-API-Key')
            headers[header_name] = options['api_key']
        elif options.get('cookie_value'):
            headers['Cookie'] = options['cookie_value']
        elif options.get('oauth2_client_creds'):
            creds = options['oauth2_client_creds']
            token = self._obtain_oauth2_token_for_fuzz(creds)
            if token:
                headers['Authorization'] = f"Bearer {token}"
        # Also include custom headers if specified
        custom = options.get('custom_headers', '')
        if custom:
            for line in custom.strip().split('\n'):
                if ':' in line:
                    key, val = line.split(':', 1)
                    headers[key.strip()] = val.strip()
        return headers

    def _obtain_oauth2_token_for_fuzz(self, creds: Dict) -> Optional[str]:
        """Obtain an OAuth2 token for fuzzer direct requests."""
        token_url = creds.get('token_url', '')
        client_id = creds.get('client_id', '')
        client_secret = creds.get('client_secret', '')
        scope = creds.get('scope', '')
        if not token_url or not client_id or not client_secret:
            return None
        try:
            data = urllib.parse.urlencode({
                'grant_type': 'client_credentials',
                'client_id': client_id,
                'client_secret': client_secret,
                'scope': scope,
            }).encode('utf-8')
            req = urllib.request.Request(token_url, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            with urllib.request.urlopen(req, timeout=15) as resp:
                token_data = json.loads(resp.read().decode('utf-8'))
                return token_data.get('access_token')
        except Exception as e:
            logger.warning(f"OAuth2 token acquisition for fuzz failed: {e}")
            return None

    def _generate_api_key(self) -> str:
        """Get or generate a stable API key for ZAP.

        Persists the key to a file so that if multiple scanner instances
        exist (e.g. due to race conditions), they all use the same key
        and can share a single ZAP daemon without fighting.
        """
        import secrets
        key_file = os.path.join(self.shared_data.currentdir, 'data', '.zap_api_key')
        try:
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            if os.path.exists(key_file):
                stored = open(key_file, 'r').read().strip()
                if len(stored) >= 16:
                    return stored
        except Exception:
            pass
        key = secrets.token_hex(self.ZAP_API_KEY_LENGTH // 2)
        try:
            with open(key_file, 'w') as f:
                f.write(key)
        except Exception:
            pass
        return key
    
    def _detect_tools(self):
        """Detect available security tools"""
        tools = ['nuclei', 'nikto', 'sqlmap', 'nmap', 'whatweb']
        for tool in tools:
            path = shutil.which(tool)
            self._tool_paths[tool] = path
            if path:
                logger.info(f"Found {tool} at {path}")
            else:
                logger.debug(f"{tool} not found in PATH")

        # Detect ZAP - check multiple possible locations
        # Priority: Ragnar tools dir > /opt > standard locations > PATH
        ragnar_dir = os.path.dirname(os.path.abspath(__file__))
        import sys
        is_windows = sys.platform == 'win32'

        if is_windows:
            # Windows ZAP locations
            zap_paths = [
                # Ragnar's tools directory
                os.path.join(ragnar_dir, 'tools', 'zap', 'zap.bat'),
                # Standard Windows installation paths
                os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'OWASP', 'Zed Attack Proxy', 'zap.bat'),
                os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'), 'OWASP', 'Zed Attack Proxy', 'zap.bat'),
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs', 'ZAP', 'zap.bat'),
                # Also check for java-based invocation
                shutil.which('zap.bat'),
                shutil.which('zap'),
            ]
        else:
            # Linux/Mac ZAP locations
            zap_paths = [
                # Ragnar's tools directory (installed by install_advanced_tools.sh)
                os.path.join(ragnar_dir, 'tools', 'zap', 'zap.sh'),
                # Standard system locations
                '/opt/zaproxy/zap.sh',
                '/usr/share/zaproxy/zap.sh',
                '/usr/local/bin/zap.sh',
                # Homebrew on macOS
                '/opt/homebrew/bin/zap.sh',
                '/usr/local/Cellar/zap/*/zap.sh',
                # PATH lookups
                shutil.which('zap.sh'),
                shutil.which('zap'),
                shutil.which('zaproxy'),
            ]

        for zap_path in zap_paths:
            if zap_path and os.path.exists(zap_path):
                self._tool_paths['zap'] = zap_path
                logger.info(f"Found OWASP ZAP at {zap_path}")
                break
        else:
            self._tool_paths['zap'] = None
            logger.debug("OWASP ZAP not found")

        # Detect browser for AJAX spider (chromium/chrome preferred, then firefox, fallback htmlunit)
        self._detected_browser = None

        if is_windows:
            # Check common Windows Chrome paths
            chrome_paths = [
                os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'Google', 'Chrome', 'Application', 'chrome.exe'),
                os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'), 'Google', 'Chrome', 'Application', 'chrome.exe'),
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome', 'Application', 'chrome.exe'),
            ]
            firefox_paths = [
                os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'Mozilla Firefox', 'firefox.exe'),
                os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'), 'Mozilla Firefox', 'firefox.exe'),
            ]

            for path in chrome_paths:
                if os.path.exists(path):
                    self._detected_browser = 'chrome-headless'
                    logger.info(f"Found Chrome for AJAX spider at {path}")
                    break

            if not self._detected_browser:
                for exe in ['chrome', 'chromium']:
                    if shutil.which(exe):
                        self._detected_browser = 'chrome-headless'
                        logger.info(f"Found {exe} in PATH for AJAX spider")
                        break

            if not self._detected_browser:
                for path in firefox_paths:
                    if os.path.exists(path):
                        self._detected_browser = 'firefox-headless'
                        logger.info(f"Found Firefox for AJAX spider at {path}")
                        break

            if not self._detected_browser and shutil.which('firefox'):
                self._detected_browser = 'firefox-headless'
                logger.info("Found Firefox in PATH for AJAX spider")
        else:
            # Linux/Mac - check in priority order (Raspberry Pi has chromium-browser)
            browser_checks = [
                ('chrome-headless', ['chromium-browser', 'chromium', 'google-chrome', 'google-chrome-stable']),
                ('firefox-headless', ['firefox', 'firefox-esr']),
            ]

            for browser_id, executables in browser_checks:
                for exe in executables:
                    if shutil.which(exe):
                        self._detected_browser = browser_id
                        logger.info(f"Found {exe} for AJAX spider (browser ID: {browser_id})")
                        break
                if self._detected_browser:
                    break

        if not self._detected_browser:
            logger.warning("No browser detected for AJAX spider - will use htmlunit fallback. "
                           "Install Chrome/Chromium or Firefox for better JavaScript crawling.")
            self._detected_browser = 'htmlunit'

    def is_available(self) -> bool:
        """Check if advanced vuln scanning is available"""
        return get_server_capabilities().capabilities.advanced_vuln_enabled

    def get_available_scanners(self) -> Dict[str, bool]:
        """Get status of available scanners"""
        zap_available = self._tool_paths.get('zap') is not None
        zap_running = self._is_zap_running() if zap_available else False
        return {
            'nuclei': self._tool_paths.get('nuclei') is not None,
            'nikto': self._tool_paths.get('nikto') is not None,
            'sqlmap': self._tool_paths.get('sqlmap') is not None,
            'nmap_vuln': self._tool_paths.get('nmap') is not None,
            'whatweb': self._tool_paths.get('whatweb') is not None,
            'zap': zap_available,
            'zap_running': zap_running,
            'ajax_spider_browser': getattr(self, '_detected_browser', None),
        }
    
    def start_scan(self, target: str, scan_type: ScanType = ScanType.NUCLEI,
                   options: Dict = None) -> str:
        """Start a vulnerability scan"""
        if not self.is_available():
            raise RuntimeError("Advanced vulnerability scanning not available")

        options = options or {}

        with self._lock:
            self._scan_counter += 1
            scan_id = f"AVS-{self._scan_counter:06d}-{int(time.time())}"

        progress = ScanProgress(
            scan_id=scan_id,
            scan_type=scan_type,
            target=target,
            status='pending'
        )

        self.active_scans[scan_id] = progress
        self.scan_results[scan_id] = []
        self.scan_history.append(progress)

        # Save to database
        self._save_scan_to_db(scan_id, progress, options)

        # Start scan in a direct daemon thread (avoids Python 3.12+/3.13
        # ThreadPoolExecutor atexit shutdown that causes "cannot schedule
        # new futures after interpreter shutdown").
        scan_thread = threading.Thread(
            target=self._run_scan,
            args=(scan_id, target, scan_type, options),
            name=f"avs-{scan_id}",
            daemon=True,
        )
        scan_thread.start()

        logger.info(f"Started {scan_type.value} scan {scan_id} against {target}")
        return scan_id
    
    def _run_scan(self, scan_id: str, target: str, scan_type: ScanType, options: Dict):
        """Execute the vulnerability scan"""
        progress = self.active_scans.get(scan_id)
        if not progress:
            return

        progress.status = 'running'
        progress.started_at = datetime.now()
        self._scan_log(scan_id, 'info', f"Starting {scan_type.value} scan against {target}")

        # Save running status to database
        self._save_scan_to_db(scan_id, progress, options)

        try:
            if scan_type == ScanType.NUCLEI:
                self._run_nuclei_scan(scan_id, target, options)
            elif scan_type == ScanType.NIKTO:
                self._run_nikto_scan(scan_id, target, options)
            elif scan_type == ScanType.SQLMAP:
                self._run_sqlmap_scan(scan_id, target, options)
            elif scan_type == ScanType.NMAP_VULN:
                self._run_nmap_vuln_scan(scan_id, target, options)
            elif scan_type == ScanType.WHATWEB:
                self._run_whatweb_scan(scan_id, target, options)
            elif scan_type == ScanType.ZAP_SPIDER:
                self._run_zap_spider(scan_id, target, options)
            elif scan_type == ScanType.ZAP_ACTIVE:
                self._run_zap_active_scan(scan_id, target, options)
            elif scan_type == ScanType.ZAP_FULL:
                self._run_zap_full_scan(scan_id, target, options)
            elif scan_type == ScanType.FULL:
                self._run_full_scan(scan_id, target, options)

            progress.status = 'completed'
            progress.progress_percent = 100
            self._scan_log(scan_id, 'info', f"Scan completed successfully with {len(self.scan_results.get(scan_id, []))} findings")

        except Exception as e:
            self._scan_log(scan_id, 'error', f"Scan failed: {e}")
            progress.status = 'failed'
            progress.error_message = str(e)
        finally:
            progress.completed_at = datetime.now()
            progress.findings_count = len(self.scan_results.get(scan_id, []))
            # Save final status to database
            self._save_scan_to_db(scan_id, progress, options)
            # Save all findings to database
            for finding in self.scan_results.get(scan_id, []):
                self._save_finding_to_db(finding, scan_id)
    
    def _run_nuclei_scan(self, scan_id: str, target: str, options: Dict):
        """Run Nuclei template-based scan"""
        nuclei_path = self._tool_paths.get('nuclei')
        if not nuclei_path:
            raise RuntimeError("Nuclei not installed")
        
        progress = self.active_scans[scan_id]
        
        # Build command
        templates = options.get('templates', self.NUCLEI_FAST_TEMPLATES)
        severity_filter = options.get('severity', 'low,medium,high,critical')
        rate_limit = options.get('rate_limit', 150)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                nuclei_path,
                '-u', target,
                '-jsonl',
                '-o', output_path,
                '-severity', severity_filter,
                '-rate-limit', str(rate_limit),
                '-silent',
                '-no-color'
            ]
            
            # Add template filters if specified
            if templates:
                for t in templates[:5]:  # Limit templates
                    cmd.extend(['-t', t])

            # Add HTTP Basic Auth header if provided
            if options.get('http_basic_auth'):
                import base64
                auth_string = options['http_basic_auth']
                auth_bytes = base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')
                cmd.extend(['-H', f'Authorization: Basic {auth_bytes}'])

            # Add Bearer Token if provided
            if options.get('bearer_token'):
                cmd.extend(['-H', f'Authorization: Bearer {options["bearer_token"]}'])

            # Add API Key header if provided
            if options.get('api_key'):
                header_name = options.get('api_key_header', 'X-API-Key')
                cmd.extend(['-H', f'{header_name}: {options["api_key"]}'])

            # Add Cookie if provided
            if options.get('cookie_value'):
                cmd.extend(['-H', f'Cookie: {options["cookie_value"]}'])

            # Add custom headers if provided
            if options.get('headers'):
                for header in options['headers']:
                    cmd.extend(['-H', header])

            logger.debug(f"Running Nuclei: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Monitor progress
            while process.poll() is None:
                time.sleep(2)
                progress.current_check = "Scanning with Nuclei templates..."
                # Update findings count from output file
                if os.path.exists(output_path):
                    with open(output_path, 'r') as f:
                        lines = f.readlines()
                        progress.findings_count = len(lines)
            
            # Parse results
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    for line in f:
                        try:
                            finding = self._parse_nuclei_result(line.strip(), scan_id)
                            if finding:
                                self.scan_results[scan_id].append(finding)
                        except json.JSONDecodeError:
                            continue
                            
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)
    
    def _parse_nuclei_result(self, json_line: str, scan_id: str) -> Optional[VulnerabilityFinding]:
        """Parse a Nuclei JSON output line"""
        try:
            data = json.loads(json_line)
            
            # Extract CVEs from tags or info
            cve_ids = []
            tags = data.get('info', {}).get('tags', [])
            for tag in tags:
                if tag.upper().startswith('CVE-'):
                    cve_ids.append(tag.upper())
            
            # Also check classification
            classification = data.get('info', {}).get('classification', {})
            if 'cve-id' in classification:
                cve_ids.extend(classification['cve-id'])
            
            severity_str = data.get('info', {}).get('severity', 'info')
            severity = self.NUCLEI_SEVERITY_MAP.get(severity_str, VulnSeverity.INFO)
            
            finding = VulnerabilityFinding(
                finding_id=f"{scan_id}-{len(self.scan_results.get(scan_id, []))+1:04d}",
                scanner='nuclei',
                host=data.get('host', data.get('matched-at', '')),
                port=data.get('port'),
                severity=severity,
                title=data.get('info', {}).get('name', 'Unknown'),
                description=data.get('info', {}).get('description', ''),
                cve_ids=list(set(cve_ids)),
                cwe_ids=classification.get('cwe-id', []),
                cvss_score=classification.get('cvss-score'),
                evidence=data.get('extracted-results', ''),
                remediation=data.get('info', {}).get('remediation', ''),
                references=data.get('info', {}).get('reference', []),
                tags=tags,
                matched_at=data.get('matched-at', ''),
                template_id=data.get('template-id', ''),
                raw_output=json_line[:2000]
            )
            
            return finding
            
        except Exception as e:
            logger.debug(f"Error parsing Nuclei result: {e}")
            return None
    
    def _run_nikto_scan(self, scan_id: str, target: str, options: Dict):
        """Run Nikto web server scan"""
        nikto_path = self._tool_paths.get('nikto')
        if not nikto_path:
            raise RuntimeError("Nikto not installed")
        
        progress = self.active_scans[scan_id]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                nikto_path,
                '-h', target,
                '-Format', 'json',
                '-o', output_path,
                '-nointeractive',
                '-maxtime', options.get('max_time', '300s')
            ]

            # Add port if specified
            if options.get('port'):
                cmd.extend(['-p', str(options['port'])])

            # Add HTTP Basic Auth if provided (Nikto native support)
            if options.get('http_basic_auth'):
                auth_parts = options['http_basic_auth'].split(':', 1)
                if len(auth_parts) == 2:
                    cmd.extend(['-id', f'{auth_parts[0]}:{auth_parts[1]}'])

            # Note: Nikto doesn't support custom headers for bearer_token, api_key, or cookie auth
            # These auth methods are better suited for Nuclei scans which support -H flag

            logger.info(f"Running Nikto: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=600)
            
            if stdout:
                logger.debug(f"Nikto stdout: {stdout[:500]}")
            if stderr:
                logger.debug(f"Nikto stderr: {stderr[:500]}")
            
            progress.current_check = "Parsing Nikto results..."
            
            # Parse results
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    raw_content = f.read()
                    logger.info(f"Nikto output file size: {len(raw_content)} bytes")
                    if raw_content:
                        logger.debug(f"Nikto raw output (first 1000 chars): {raw_content[:1000]}")
                        try:
                            results = json.loads(raw_content)
                            logger.info(f"Nikto parsed JSON keys: {list(results.keys()) if isinstance(results, dict) else 'array'}")
                            self._parse_nikto_results(results, scan_id, target)
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse Nikto JSON output: {e}")
                            # Try to parse as plain text output
                            self._parse_nikto_text_output(raw_content, scan_id, target)
                    else:
                        logger.warning("Nikto output file is empty")
            else:
                logger.warning(f"Nikto output file not found: {output_path}")
                        
        except subprocess.TimeoutExpired:
            process.kill()
            progress.error_message = "Nikto scan timed out"
        except Exception as e:
            logger.error(f"Nikto scan error: {e}")
            progress.error_message = str(e)
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)
    
    def _parse_nikto_results(self, results: Any, scan_id: str, target: str = ''):
        """Parse Nikto JSON results"""
        try:
            vulnerabilities = []
            host = target
            port = None
            
            # Nikto 2.5+ JSON format is often an array with a single object containing 'vulnerabilities'
            if isinstance(results, list):
                for item in results:
                    if isinstance(item, dict):
                        host = item.get('host', host) or item.get('ip', host)
                        port = item.get('port', port)
                        vulns = item.get('vulnerabilities', [])
                        if vulns:
                            vulnerabilities.extend(vulns)
            elif isinstance(results, dict):
                host = results.get('host', host) or results.get('ip', host)
                port = results.get('port', port)
                vulnerabilities = results.get('vulnerabilities', [])
            
            logger.info(f"Nikto found {len(vulnerabilities)} vulnerabilities for {host}:{port}")
            
            for vuln in vulnerabilities:
                # Map Nikto OSVDB/id to severity
                osvdb = str(vuln.get('OSVDB', vuln.get('id', '0')))
                msg = vuln.get('msg', vuln.get('message', 'Nikto Finding'))
                method = vuln.get('method', 'GET')
                uri = vuln.get('url', vuln.get('uri', '/'))
                
                # Determine severity based on keywords
                severity = VulnSeverity.INFO
                msg_lower = msg.lower()
                if any(kw in msg_lower for kw in ['sql injection', 'xss', 'rce', 'command injection', 'critical']):
                    severity = VulnSeverity.HIGH
                elif any(kw in msg_lower for kw in ['directory listing', 'backup', 'config', 'password', 'admin']):
                    severity = VulnSeverity.MEDIUM
                elif any(kw in msg_lower for kw in ['outdated', 'version', 'disclosure', 'header']):
                    severity = VulnSeverity.LOW
                
                finding = VulnerabilityFinding(
                    finding_id=f"{scan_id}-nikto-{len(self.scan_results.get(scan_id, []))+1:04d}",
                    scanner='nikto',
                    host=str(host),
                    port=int(port) if port else None,
                    severity=severity,
                    title=f"[{method}] {uri}" if uri else msg[:80],
                    description=msg,
                    references=[f"OSVDB-{osvdb}"] if osvdb != '0' else [],
                    tags=['nikto', 'web'],
                    raw_output=json.dumps(vuln)[:1000]
                )
                
                self.scan_results[scan_id].append(finding)
                logger.debug(f"Added Nikto finding: {finding.title}")
                
        except Exception as e:
            logger.error(f"Error parsing Nikto results: {e}")
    
    def _parse_nikto_text_output(self, text: str, scan_id: str, target: str):
        """Parse Nikto plain text output as fallback"""
        try:
            lines = text.split('\n')
            for line in lines:
                line = line.strip()
                # Nikto text format: + /path: Description
                if line.startswith('+') and ':' in line:
                    parts = line[1:].strip().split(':', 1)
                    if len(parts) == 2:
                        uri = parts[0].strip()
                        msg = parts[1].strip()
                        
                        # Skip info lines
                        if any(skip in msg.lower() for skip in ['target ip:', 'target hostname:', 'target port:', 'start time:', 'end time:', 'host(s) tested']):
                            continue
                        
                        severity = VulnSeverity.INFO
                        msg_lower = msg.lower()
                        if any(kw in msg_lower for kw in ['vulnerable', 'injection', 'xss']):
                            severity = VulnSeverity.HIGH
                        elif any(kw in msg_lower for kw in ['directory', 'listing', 'backup', 'config']):
                            severity = VulnSeverity.MEDIUM
                        elif any(kw in msg_lower for kw in ['outdated', 'version']):
                            severity = VulnSeverity.LOW
                        
                        finding = VulnerabilityFinding(
                            finding_id=f"{scan_id}-nikto-{len(self.scan_results.get(scan_id, []))+1:04d}",
                            scanner='nikto',
                            host=target,
                            severity=severity,
                            title=f"{uri}: {msg[:60]}",
                            description=msg,
                            tags=['nikto', 'web'],
                            raw_output=line[:500]
                        )
                        self.scan_results[scan_id].append(finding)
                        
            logger.info(f"Parsed {len(self.scan_results.get(scan_id, []))} findings from Nikto text output")
        except Exception as e:
            logger.error(f"Error parsing Nikto text output: {e}")
    
    def _run_sqlmap_scan(self, scan_id: str, target: str, options: Dict):
        """Run SQLMap SQL injection scan"""
        sqlmap_path = self._tool_paths.get('sqlmap')
        if not sqlmap_path:
            raise RuntimeError("SQLMap not installed")
        
        progress = self.active_scans[scan_id]
        
        with tempfile.TemporaryDirectory() as output_dir:
            cmd = [
                'python3', sqlmap_path,
                '-u', target,
                '--batch',
                '--level', str(options.get('level', 1)),
                '--risk', str(options.get('risk', 1)),
                '--output-dir', output_dir,
                '--forms' if options.get('forms', False) else '',
                '--crawl', str(options.get('crawl_depth', 1))
            ]
            
            # Remove empty strings
            cmd = [c for c in cmd if c]
            
            logger.debug(f"Running SQLMap: {' '.join(cmd)}")
            
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Read output for progress
                for line in iter(process.stdout.readline, ''):
                    if 'identified the following injection' in line.lower():
                        progress.findings_count += 1
                    if 'testing' in line.lower():
                        progress.current_check = line.strip()[:100]
                
                process.wait(timeout=1800)  # 30 min max
                
                # Parse output directory for results
                self._parse_sqlmap_output(output_dir, scan_id, target)
                
            except subprocess.TimeoutExpired:
                process.kill()
                progress.error_message = "SQLMap scan timed out"
    
    def _parse_sqlmap_output(self, output_dir: str, scan_id: str, target: str):
        """Parse SQLMap output directory"""
        try:
            # SQLMap stores results in target-specific subdirectories
            for root, dirs, files in os.walk(output_dir):
                for file in files:
                    if file == 'log':
                        log_path = os.path.join(root, file)
                        with open(log_path, 'r') as f:
                            content = f.read()
                            
                        # Look for injection points
                        if 'injectable' in content.lower():
                            finding = VulnerabilityFinding(
                                finding_id=f"{scan_id}-sqli-{len(self.scan_results.get(scan_id, []))+1:04d}",
                                scanner='sqlmap',
                                host=target,
                                port=None,
                                severity=VulnSeverity.CRITICAL,
                                title='SQL Injection Vulnerability',
                                description='SQLMap identified SQL injection vulnerability',
                                cwe_ids=['CWE-89'],
                                tags=['sqli', 'injection', 'critical'],
                                evidence=content[:2000],
                                remediation='Use parameterized queries and input validation'
                            )
                            self.scan_results[scan_id].append(finding)
                            
        except Exception as e:
            logger.error(f"Error parsing SQLMap output: {e}")
    
    def _run_nmap_vuln_scan(self, scan_id: str, target: str, options: Dict):
        """Run Nmap vulnerability scripts"""
        nmap_path = self._tool_paths.get('nmap')
        if not nmap_path:
            raise RuntimeError("Nmap not installed")
        
        progress = self.active_scans[scan_id]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            ports = options.get('ports', '21,22,23,25,80,443,445,3306,3389,8080')
            scripts = options.get('scripts', 'vuln,auth,default')
            
            cmd = [
                'sudo', nmap_path,
                '-sV',
                '-p', ports,
                f'--script={scripts}',
                '-oX', output_path,
                '--host-timeout', '10m',
                target
            ]
            
            logger.debug(f"Running Nmap vuln: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=900)
            
            # Parse XML output
            self._parse_nmap_vuln_xml(output_path, scan_id)
            
        except subprocess.TimeoutExpired:
            process.kill()
            progress.error_message = "Nmap vuln scan timed out"
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)
    
    def _parse_nmap_vuln_xml(self, xml_path: str, scan_id: str):
        """Parse Nmap XML output for vulnerabilities"""
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            for host in root.findall('.//host'):
                addr_elem = host.find('.//address[@addrtype="ipv4"]')
                host_ip = addr_elem.get('addr', '') if addr_elem is not None else ''
                
                for port in host.findall('.//port'):
                    port_id = port.get('portid', '')
                    
                    for script in port.findall('.//script'):
                        script_id = script.get('id', '')
                        output = script.get('output', '')
                        
                        # Look for vulnerability indicators
                        if 'VULNERABLE' in output or 'vuln' in script_id.lower():
                            # Extract CVEs from output
                            cve_pattern = r'CVE-\d{4}-\d+'
                            cves = re.findall(cve_pattern, output)
                            
                            severity = VulnSeverity.HIGH if cves else VulnSeverity.MEDIUM
                            
                            finding = VulnerabilityFinding(
                                finding_id=f"{scan_id}-nmap-{len(self.scan_results.get(scan_id, []))+1:04d}",
                                scanner='nmap_vuln',
                                host=host_ip,
                                port=int(port_id) if port_id.isdigit() else None,
                                severity=severity,
                                title=f"Nmap {script_id}",
                                description=output[:500],
                                cve_ids=cves,
                                tags=['nmap', 'vuln-script'],
                                raw_output=output[:2000]
                            )
                            
                            self.scan_results[scan_id].append(finding)
                            
        except Exception as e:
            logger.error(f"Error parsing Nmap XML: {e}")
    
    def _run_whatweb_scan(self, scan_id: str, target: str, options: Dict):
        """Run WhatWeb technology fingerprinting"""
        whatweb_path = self._tool_paths.get('whatweb')
        if not whatweb_path:
            raise RuntimeError("WhatWeb not installed")
        
        progress = self.active_scans[scan_id]
        
        try:
            cmd = [
                whatweb_path,
                '--log-json=-',
                '-a', str(options.get('aggression', 3)),
                target
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Parse JSON output
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)
                        self._parse_whatweb_result(data, scan_id)
                    except json.JSONDecodeError:
                        continue
                        
        except subprocess.TimeoutExpired:
            progress.error_message = "WhatWeb scan timed out"
    
    def _parse_whatweb_result(self, data: Dict, scan_id: str):
        """Parse WhatWeb JSON result"""
        try:
            plugins = data.get('plugins', {})
            target = data.get('target', '')
            
            for plugin_name, plugin_data in plugins.items():
                # Check for version info or interesting findings
                version = None
                if isinstance(plugin_data, dict):
                    version = plugin_data.get('version', [])
                    if isinstance(version, list) and version:
                        version = version[0]
                
                # Only create findings for interesting technologies
                interesting = ['WordPress', 'Drupal', 'Joomla', 'phpMyAdmin', 
                             'Apache', 'nginx', 'IIS', 'PHP', 'ASP.NET']
                
                if plugin_name in interesting:
                    finding = VulnerabilityFinding(
                        finding_id=f"{scan_id}-whatweb-{len(self.scan_results.get(scan_id, []))+1:04d}",
                        scanner='whatweb',
                        host=target,
                        port=None,
                        severity=VulnSeverity.INFO,
                        title=f"Technology: {plugin_name}",
                        description=f"Detected {plugin_name}" + (f" version {version}" if version else ""),
                        tags=['technology', 'fingerprint', plugin_name.lower()],
                        evidence=str(version) if version else ''
                    )
                    
                    self.scan_results[scan_id].append(finding)
                    
        except Exception as e:
            logger.debug(f"Error parsing WhatWeb result: {e}")

    # =========================================================================
    # OWASP ZAP Integration
    # =========================================================================

    def _is_zap_running(self) -> bool:
        """Check if ZAP daemon is running and responsive.

        Uses two attempts with generous timeouts to tolerate Java GC pauses
        on ARM/Raspberry Pi where ZAP can be temporarily unresponsive.
        """
        for attempt in range(2):
            try:
                url = f"{self._zap_base_url}/JSON/core/view/version/?apikey={self._zap_api_key}"
                req = urllib.request.Request(url, method='GET')
                with urllib.request.urlopen(req, timeout=10) as response:
                    return response.status == 200
            except urllib.error.HTTPError as e:
                # ZAP is running but API key is wrong (401/403) - it's still running
                if e.code in (401, 403):
                    return True
                return False
            except Exception:
                if attempt == 0:
                    time.sleep(2)  # Brief pause before retry
                    continue
                return False
        return False

    def _zap_api_call(self, endpoint: str, params: Dict = None) -> Dict:
        """Make a ZAP API call and return JSON response"""
        params = params or {}
        params['apikey'] = self._zap_api_key

        query_string = urllib.parse.urlencode(params)
        url = f"{self._zap_base_url}/{endpoint}?{query_string}"

        try:
            req = urllib.request.Request(url, method='GET')
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            # Read the error response body for more details
            error_body = ""
            try:
                error_body = e.read().decode('utf-8', errors='replace')
            except:
                pass
            logger.error(f"ZAP API HTTP error: {e.code} - {e.reason}. Endpoint: {endpoint}. Response: {error_body[:500]}")

            # Parse ZAP error response for better messages
            friendly_error = self._parse_zap_error(e.code, error_body, endpoint, params)
            raise RuntimeError(friendly_error)
        except urllib.error.URLError as e:
            logger.error(f"ZAP API URL error: {e.reason}. Is ZAP running?")
            raise RuntimeError(f"Cannot connect to ZAP: {e.reason}. Make sure ZAP daemon is running.")
        except Exception as e:
            logger.error(f"ZAP API error: {e}")
            raise

    def _parse_zap_error(self, code: int, error_body: str, endpoint: str, params: Dict) -> str:
        """Parse ZAP error response into a user-friendly message"""
        # Try to parse JSON error from ZAP
        error_detail = ""
        try:
            error_json = json.loads(error_body)
            error_detail = error_json.get('message', '') or error_json.get('error', '')
        except:
            error_detail = error_body[:200] if error_body else ""

        # Check for common 500 error causes
        if code == 500:
            target_url = params.get('url', '')

            # URL-related errors
            if 'url' in endpoint.lower() or target_url:
                if not target_url:
                    return "ZAP Error: No target URL provided for scan."

                # Check URL format
                if not target_url.startswith(('http://', 'https://')):
                    return f"ZAP Error: Invalid URL format '{target_url}'. URL must start with http:// or https://"

                # Common ZAP 500 causes
                if 'failed to connect' in error_detail.lower() or 'connection' in error_detail.lower():
                    return f"ZAP Error: Cannot connect to target '{target_url}'. Check if the target is accessible and the URL is correct."

                if 'timeout' in error_detail.lower():
                    return f"ZAP Error: Connection to '{target_url}' timed out. Target may be slow or unreachable."

                if 'ssl' in error_detail.lower() or 'certificate' in error_detail.lower():
                    return f"ZAP Error: SSL/TLS error connecting to '{target_url}'. The target may have certificate issues."

                # Generic target error
                return (f"ZAP Error: Failed to access target '{target_url}'. "
                        f"Possible causes: target unreachable, invalid URL, SSL issues, or network problems. "
                        f"Details: {error_detail[:100]}" if error_detail else
                        f"ZAP Error: Failed to access target '{target_url}'. Check if the URL is correct and the target is accessible.")

            # Spider/scan errors
            if 'spider' in endpoint.lower():
                return f"ZAP Spider Error: {error_detail[:150] if error_detail else 'Internal error during spidering. Try clearing ZAP session and retrying.'}"

            if 'ascan' in endpoint.lower():
                return f"ZAP Active Scan Error: {error_detail[:150] if error_detail else 'Internal error during active scan. Try clearing ZAP session and retrying.'}"

            # Context errors
            if 'context' in endpoint.lower():
                return f"ZAP Context Error: {error_detail[:150] if error_detail else 'Error managing scan context. Try clearing ZAP session.'}"

            # Generic 500 error
            return f"ZAP Internal Error (500): {error_detail[:200] if error_detail else 'An internal error occurred. Try restarting ZAP or clearing the session.'}"

        # Other HTTP errors
        return f"ZAP API error {code}: {error_detail[:200] if error_detail else 'Unknown error'}"

    def _validate_target_url(self, target: str) -> Tuple[bool, str]:
        """Validate that a target URL is properly formatted and potentially reachable"""
        if not target:
            return False, "Target URL is empty"

        # Check URL scheme
        if not target.startswith(('http://', 'https://')):
            return False, f"Invalid URL scheme. URL must start with http:// or https://, got: {target[:50]}"

        # Parse URL
        try:
            parsed = urllib.parse.urlparse(target)
            if not parsed.netloc:
                return False, f"Invalid URL format - no host found: {target[:50]}"
        except Exception as e:
            return False, f"URL parsing error: {e}"

        # Quick connectivity check (with short timeout)
        try:
            host = parsed.netloc.split(':')[0]
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            if result != 0:
                return False, f"Cannot connect to {host}:{port}. Target may be unreachable or firewall is blocking."
        except socket.gaierror:
            return False, f"Cannot resolve hostname: {parsed.netloc}. Check if the URL is correct."
        except socket.timeout:
            return False, f"Connection to {parsed.netloc} timed out. Target may be slow or unreachable."
        except Exception as e:
            # Don't fail on connectivity check errors, just warn
            logger.warning(f"Target connectivity check failed (non-fatal): {e}")

        return True, ""

    def _cleanup_dead_zap(self, port: int = None):
        """Clean up dead/zombie ZAP process and free the port.

        After heavy scans (especially insane strength), ZAP can OOM or crash
        leaving behind a zombie process and a locked port.  This method
        ensures a clean slate before attempting to start a new instance.
        """
        port = port or self._zap_port
        logger.info(f"[ZAP-CLEANUP] Starting cleanup for port {port}")

        # 1. Clean up our tracked process if it died
        if self._zap_process:
            retcode = self._zap_process.poll()
            if retcode is not None:
                stderr_tail = ''
                try:
                    stderr_tail = self._zap_process.stderr.read()[-1000:] if self._zap_process.stderr else ''
                except Exception:
                    pass
                logger.warning(f"[ZAP-CLEANUP] Dead ZAP process found (PID {self._zap_process.pid}, "
                               f"exit code {retcode})")
                if stderr_tail:
                    logger.warning(f"[ZAP-CLEANUP] Last stderr from dead process: {stderr_tail}")
                self._zap_process = None
            else:
                # Process object exists and hasn't exited — check if API responds
                if not self._is_zap_running():
                    logger.warning(f"[ZAP-CLEANUP] ZAP process alive (PID {self._zap_process.pid}) "
                                   f"but API not responding on port {port} — killing it")
                    try:
                        self._zap_process.kill()
                        self._zap_process.wait(timeout=10)
                        logger.info("[ZAP-CLEANUP] Killed unresponsive ZAP process")
                    except Exception as e:
                        logger.warning(f"[ZAP-CLEANUP] Error killing ZAP process: {e}")
                    self._zap_process = None
                else:
                    logger.info(f"[ZAP-CLEANUP] ZAP process (PID {self._zap_process.pid}) is running and responsive — no cleanup needed")
        else:
            logger.info("[ZAP-CLEANUP] No tracked ZAP process reference")

        # 2. Always remove stale ZAP lock files BEFORE checking port.
        # The lock file persists even after ZAP crashes / is killed,
        # causing "home directory already in use" on the next start.
        self._remove_zap_lock_files()

        # 3. Check if port is occupied — but don't kill a healthy ZAP
        port_occupied = self._is_port_in_use(port)
        if not port_occupied:
            logger.info(f"[ZAP-CLEANUP] Port {port} is free")
            return  # Nothing to clean up

        # Port is occupied — check if it's a responsive ZAP before killing
        try:
            url = f"http://127.0.0.1:{port}/JSON/core/view/version/"
            req = urllib.request.Request(url, method='GET')
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    logger.info(f"[ZAP-CLEANUP] Port {port} has a healthy ZAP — keeping it alive")
                    return
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                logger.info(f"[ZAP-CLEANUP] Port {port} has a running ZAP (HTTP {e.code}) — keeping it alive")
                return
        except Exception:
            pass  # Not a responsive ZAP — proceed with kill

        logger.warning(f"[ZAP-CLEANUP] Port {port} is in use by unresponsive process — killing it")

        try:
            import sys
            if sys.platform == 'win32':
                # Windows: find PID on port and kill it
                result = subprocess.run(
                    ['netstat', '-ano'],
                    capture_output=True, text=True, timeout=10
                )
                killed_any = False
                for line in result.stdout.splitlines():
                    if f':{port}' in line and 'LISTENING' in line:
                        parts = line.strip().split()
                        pid = parts[-1]
                        if pid.isdigit():
                            logger.info(f"[ZAP-CLEANUP] Killing orphan process on port {port} (PID {pid})")
                            kill_result = subprocess.run(
                                ['taskkill', '/F', '/PID', pid],
                                capture_output=True, text=True, timeout=10
                            )
                            logger.info(f"[ZAP-CLEANUP] taskkill result: {kill_result.stdout.strip()} {kill_result.stderr.strip()}")
                            killed_any = True
                if not killed_any:
                    logger.warning(f"[ZAP-CLEANUP] Port {port} in use but could not identify PID from netstat")
            else:
                # Linux/macOS: use fuser or lsof
                try:
                    result = subprocess.run(
                        ['fuser', f'{port}/tcp'],
                        capture_output=True, text=True, timeout=10
                    )
                    pids = result.stdout.strip().split()
                    for pid in pids:
                        if pid.strip().isdigit():
                            logger.info(f"[ZAP-CLEANUP] Killing orphan process on port {port} (PID {pid})")
                            os.kill(int(pid), 9)
                except FileNotFoundError:
                    # fuser not available, try lsof
                    try:
                        result = subprocess.run(
                            ['lsof', '-ti', f':{port}'],
                            capture_output=True, text=True, timeout=10
                        )
                        for pid in result.stdout.strip().splitlines():
                            if pid.strip().isdigit():
                                logger.info(f"[ZAP-CLEANUP] Killing orphan process on port {port} (PID {pid})")
                                os.kill(int(pid.strip()), 9)
                    except FileNotFoundError:
                        logger.warning("[ZAP-CLEANUP] Neither fuser nor lsof available for port cleanup")
        except Exception as e:
            logger.warning(f"[ZAP-CLEANUP] Port cleanup failed: {e}")

        # 4. Remove lock files again after kill (in case the killed process recreated one)
        self._remove_zap_lock_files()

        # 5. Brief wait for port to be released by OS
        time.sleep(1)

        # 6. Verify port is now free
        if self._is_port_in_use(port):
            logger.error(f"[ZAP-CLEANUP] Port {port} STILL in use after cleanup — ZAP restart may fail")
        else:
            logger.info(f"[ZAP-CLEANUP] Port {port} is now free after cleanup")

    def _is_port_in_use(self, port: int) -> bool:
        """Check if a TCP port is currently in use."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _remove_zap_lock_files(self):
        """Remove ZAP home directory lock files to prevent 'home directory already in use'.

        ZAP creates a .ZAP_D_LOCK file in its home directory which persists
        even after a crash or kill.  This prevents new instances from starting.
        """
        for zap_home in ['/root/.ZAP', os.path.expanduser('~/.ZAP')]:
            lock_file = os.path.join(zap_home, '.ZAP_D_LOCK')
            if os.path.exists(lock_file):
                try:
                    os.remove(lock_file)
                    logger.info(f"[ZAP-CLEANUP] Removed stale lock file: {lock_file}")
                except OSError as e:
                    logger.warning(f"[ZAP-CLEANUP] Could not remove lock file {lock_file}: {e}")

    def start_zap_daemon(self, port: int = None) -> bool:
        """Start ZAP in daemon mode.

        Handles stale/crashed ZAP processes by cleaning up zombies and
        freeing locked ports before attempting to start a fresh instance.
        Thread-safe: uses _zap_start_lock to prevent concurrent starts.
        """
        # Serialize all startup attempts so the watchdog and scan flow
        # never race to start/kill ZAP concurrently.
        acquired = self._zap_start_lock.acquire(timeout=200)
        if not acquired:
            logger.warning("[ZAP-START] Could not acquire start lock (another start in progress)")
            # Another thread is already starting ZAP — check if it succeeded
            return self._is_zap_running()
        try:
            return self._start_zap_daemon_inner(port)
        finally:
            self._zap_start_lock.release()

    def _start_zap_daemon_inner(self, port: int = None) -> bool:
        """Inner startup logic, called under _zap_start_lock."""
        # Suppress watchdog restarts while we're starting
        was_busy = self._zap_busy
        self._zap_busy = True
        try:
            return self._start_zap_daemon_impl(port)
        finally:
            self._zap_busy = was_busy

    def _start_zap_daemon_impl(self, port: int = None) -> bool:
        """Actual ZAP daemon startup implementation."""
        # Clear the user-stopped flag so the watchdog resumes guarding
        self._zap_user_stopped = False
        logger.info("[ZAP-START] ═══════════════════════════════════════════")
        logger.info("[ZAP-START] Beginning ZAP daemon startup sequence")
        logger.info(f"[ZAP-START] Requested port: {port or self._zap_port}")
        logger.info(f"[ZAP-START] Current _zap_process ref: {self._zap_process is not None}")

        if self._is_zap_running():
            logger.info("[ZAP-START] ZAP API is already responding — checking API key...")
            # Verify API key works by making a real API call
            try:
                version_resp = self._zap_api_call('JSON/core/view/version')
                logger.info(f"[ZAP-START] ZAP already running, version: {version_resp}. API key valid.")
                return True
            except Exception as e:
                logger.warning(f"[ZAP-START] ZAP is responding but API key failed: {e}")
                # Try with no API key (ZAP may have been started without one)
                try:
                    url = f"{self._zap_base_url}/JSON/core/view/version/"
                    req = urllib.request.Request(url, method='GET')
                    with urllib.request.urlopen(req, timeout=5) as response:
                        if response.status == 200:
                            logger.info("[ZAP-START] ZAP running without API key — adapting")
                            self._zap_api_key = ''
                            return True
                except Exception:
                    pass
                # ZAP is running with a different key — regenerate ours to match
                logger.warning("[ZAP-START] ZAP running with unknown API key — "
                               "regenerating key and restarting to sync")
                self._zap_api_key = self._generate_api_key()

        logger.info("[ZAP-START] ZAP API not responding — running cleanup...")
        # ZAP is not responding — clean up any dead process / port lock
        self._cleanup_dead_zap(port or self._zap_port)

        zap_path = self._tool_paths.get('zap')
        if not zap_path:
            logger.error("[ZAP-START] FAILED: No ZAP binary found in known paths. "
                         "Install ZAP or set the path manually.")
            return False

        if not os.path.exists(zap_path):
            logger.error(f"[ZAP-START] FAILED: ZAP binary path no longer exists: {zap_path}")
            return False

        logger.info(f"[ZAP-START] ZAP binary: {zap_path}")
        logger.info(f"[ZAP-START] ZAP binary size: {os.path.getsize(zap_path)} bytes")

        # Verify Java is available (ZAP requires Java 11+)
        java_path = shutil.which('java')
        if not java_path:
            logger.error("[ZAP-START] FAILED: Java not found in PATH. "
                         "ZAP requires Java 11+. Install with: sudo apt install default-jre")
            return False

        # Log Java version for diagnostics
        try:
            java_version_result = subprocess.run(
                [java_path, '-version'],
                capture_output=True, text=True, timeout=10
            )
            java_ver = (java_version_result.stderr or java_version_result.stdout).strip().split('\n')[0]
            logger.info(f"[ZAP-START] Java: {java_path} -> {java_ver}")
        except Exception as e:
            logger.warning(f"[ZAP-START] Could not determine Java version: {e}")

        # Log system memory
        try:
            import psutil
            mem = psutil.virtual_memory()
            logger.info(f"[ZAP-START] System memory: {mem.total // (1024*1024)}MB total, "
                        f"{mem.available // (1024*1024)}MB available ({mem.percent}% used)")
        except ImportError:
            # psutil not available — try OS-specific fallback
            try:
                import sys as _sys
                if _sys.platform == 'win32':
                    result = subprocess.run(
                        ['wmic', 'OS', 'get', 'FreePhysicalMemory,TotalVisibleMemorySize', '/format:csv'],
                        capture_output=True, text=True, timeout=10
                    )
                    logger.info(f"[ZAP-START] Memory (wmic): {result.stdout.strip()}")
                else:
                    result = subprocess.run(['free', '-m'], capture_output=True, text=True, timeout=5)
                    if result.stdout:
                        for line in result.stdout.strip().split('\n'):
                            if 'Mem' in line:
                                logger.info(f"[ZAP-START] {line.strip()}")
            except Exception:
                logger.debug("[ZAP-START] Could not determine system memory")

        port = port or self._zap_port
        self._zap_port = port
        self._zap_base_url = f"http://127.0.0.1:{port}"

        # Final port check before launch
        if self._is_port_in_use(port):
            logger.error(f"[ZAP-START] Port {port} is STILL in use after cleanup. "
                         f"Cannot start ZAP daemon. Another process may be holding it.")
            return False

        # Determine JVM heap cap so ZAP cannot consume all RAM and get
        # OOM-killed.  Cap at ~25% of total RAM, with a floor of 512M
        # and a ceiling of 2G (plenty for ZAP daemon mode).
        jvm_xmx = '512m'  # safe fallback
        try:
            try:
                import psutil
                total_mb = psutil.virtual_memory().total // (1024 * 1024)
            except ImportError:
                # Fallback: read /proc/meminfo on Linux
                with open('/proc/meminfo') as f:
                    for line in f:
                        if line.startswith('MemTotal'):
                            total_mb = int(line.split()[1]) // 1024
                            break
                    else:
                        total_mb = 0
            if total_mb:
                cap_mb = max(512, min(total_mb // 4, 2048))
                jvm_xmx = f'{cap_mb}m'
                logger.info(f"[ZAP-START] JVM heap cap: -Xmx{jvm_xmx} "
                            f"(system RAM: {total_mb}MB)")
        except Exception as e:
            logger.debug(f"[ZAP-START] Could not determine RAM for heap cap: {e}")

        # Build command based on platform
        import sys
        is_windows = sys.platform == 'win32'

        cmd = [
            zap_path,
            '-daemon',
            '-port', str(port),
            '-config', f'api.key={self._zap_api_key}',
            '-config', 'api.addrs.addr.name=127.0.0.1',
            '-config', 'api.addrs.addr.regex=true',
            '-config', 'connection.timeoutInSecs=120',
        ]

        # Note: zap.sh already sets -Xmx to 25% of system RAM automatically.
        # Passing -J-Xmx to ZAP 2.17.0 causes 'Unsupported option' error.
        logger.info(f"[ZAP-START] Command: {' '.join(cmd)}")

        # Detect ARM/Raspberry Pi - ZAP needs much longer startup on ARM
        import platform
        machine = platform.machine().lower()
        is_arm = any(arch in machine for arch in ('arm', 'aarch64'))
        startup_timeout = 180 if is_arm else self.ZAP_STARTUP_TIMEOUT
        logger.info(f"[ZAP-START] Platform: {machine}, ARM: {is_arm}, "
                    f"startup timeout: {startup_timeout}s")

        try:
            # Use shell=True on Windows for .bat files
            popen_kwargs = {
                'stdout': subprocess.PIPE,
                'stderr': subprocess.PIPE,
                'text': True,
                'shell': is_windows,  # Required for .bat files on Windows
            }
            # CREATE_NO_WINDOW only exists on Windows
            if is_windows:
                popen_kwargs['creationflags'] = getattr(subprocess, 'CREATE_NO_WINDOW', 0)

            self._zap_process = subprocess.Popen(cmd, **popen_kwargs)
            logger.info(f"[ZAP-START] Process launched — PID: {self._zap_process.pid}")

            # Wait for ZAP to start (poll every 3s)
            start_time = time.time()
            poll_count = 0
            while time.time() - start_time < startup_timeout:
                poll_count += 1
                elapsed = int(time.time() - start_time)

                # Check if process has exited early (crash/error)
                retcode = self._zap_process.poll()
                if retcode is not None:
                    stdout_output = ''
                    stderr_output = ''
                    try:
                        stdout_output = self._zap_process.stdout.read()[-3000:] if self._zap_process.stdout else ''
                    except Exception:
                        pass
                    try:
                        stderr_output = self._zap_process.stderr.read()[-3000:] if self._zap_process.stderr else ''
                    except Exception:
                        pass
                    logger.error(f"[ZAP-START] FAILED: Process exited after {elapsed}s "
                                 f"with code {retcode} (poll #{poll_count})")
                    if stdout_output:
                        logger.error(f"[ZAP-START] stdout: {stdout_output}")
                    if stderr_output:
                        logger.error(f"[ZAP-START] stderr: {stderr_output}")
                    else:
                        logger.error("[ZAP-START] No stderr output captured")

                    # Decode common exit codes
                    if retcode == 137 or retcode == -9:
                        logger.error("[ZAP-START] Exit code 137/-9 = Killed (likely OOM killer)")
                    elif retcode == 1:
                        logger.error("[ZAP-START] Exit code 1 = General error "
                                     "(port conflict, config issue, or Java error)")
                    elif retcode == 127:
                        logger.error("[ZAP-START] Exit code 127 = Command not found")

                    self._zap_process = None
                    return False

                if self._is_zap_running():
                    logger.info(f"[ZAP-START] SUCCESS: ZAP daemon started on port {port} "
                                f"in {elapsed}s (poll #{poll_count})")
                    # Log ZAP version
                    try:
                        ver = self._zap_api_call('JSON/core/view/version')
                        logger.info(f"[ZAP-START] ZAP version: {ver}")
                    except Exception:
                        pass
                    logger.info("[ZAP-START] ═══════════════════════════════════════════")
                    return True

                if poll_count % 5 == 0:  # Log every ~15s
                    logger.info(f"[ZAP-START] Waiting for ZAP API... {elapsed}s elapsed "
                                f"(poll #{poll_count}, timeout={startup_timeout}s)")
                time.sleep(3)

            # Timeout reached - capture diagnostics
            elapsed = int(time.time() - start_time)
            logger.error(f"[ZAP-START] FAILED: Timeout after {elapsed}s ({poll_count} polls)")
            retcode = self._zap_process.poll()
            if retcode is not None:
                logger.error(f"[ZAP-START] Process exited during timeout with code {retcode}")
                try:
                    stderr_output = self._zap_process.stderr.read()[-3000:]
                    if stderr_output:
                        logger.error(f"[ZAP-START] stderr: {stderr_output}")
                except Exception:
                    pass
            else:
                logger.error(f"[ZAP-START] Process still alive (PID {self._zap_process.pid}) "
                             f"but API not responding on port {port}")
                logger.error("[ZAP-START] Possible causes: Java startup extremely slow, "
                             "port binding failed silently, or ZAP stuck in init")
            logger.info("[ZAP-START] ═══════════════════════════════════════════")
            return False

        except FileNotFoundError:
            logger.error(f"[ZAP-START] FAILED: Binary not found or not executable: {zap_path}")
            return False
        except PermissionError:
            logger.error(f"[ZAP-START] FAILED: Permission denied: {zap_path}")
            return False
        except OSError as e:
            logger.error(f"[ZAP-START] FAILED: OS error launching process: {e}")
            return False
        except Exception as e:
            logger.error(f"[ZAP-START] FAILED: Unexpected error: {type(e).__name__}: {e}")
            return False

    def stop_zap_daemon(self, user_requested: bool = True) -> bool:
        """Stop the ZAP daemon.

        Args:
            user_requested: If True (default), the watchdog will not
                automatically restart ZAP until the user starts it again.
        """
        if user_requested:
            self._zap_user_stopped = True
        try:
            if self._is_zap_running():
                self._zap_api_call('JSON/core/action/shutdown')
                time.sleep(2)

            if self._zap_process:
                self._zap_process.terminate()
                self._zap_process.wait(timeout=10)
                self._zap_process = None

            # Always clean up lock files so the next start won't fail
            self._remove_zap_lock_files()
            logger.info("ZAP daemon stopped")
            return True

        except Exception as e:
            logger.error(f"Error stopping ZAP daemon: {e}")
            if self._zap_process:
                self._zap_process.kill()
                self._zap_process = None
            self._remove_zap_lock_files()
            return False

    def get_zap_status(self) -> Dict[str, Any]:
        """Get ZAP daemon status and info"""
        status = {
            'installed': self._tool_paths.get('zap') is not None,
            'running': False,
            'port': self._zap_port,
            'version': None,
            'hosts_accessed': 0,
            'alerts_count': 0,
            'messages_count': 0,
            'watchdog_active': not self._zap_watchdog_stop.is_set(),
            'watchdog_paused': self._zap_user_stopped,
        }

        if not self._is_zap_running():
            return status

        status['running'] = True

        try:
            # Get version
            version_resp = self._zap_api_call('JSON/core/view/version')
            status['version'] = version_resp.get('version')

            # Get stats
            hosts_resp = self._zap_api_call('JSON/core/view/hosts')
            status['hosts_accessed'] = len(hosts_resp.get('hosts', []))

            alerts_resp = self._zap_api_call('JSON/core/view/numberOfAlerts')
            status['alerts_count'] = int(alerts_resp.get('numberOfAlerts', 0))

            msgs_resp = self._zap_api_call('JSON/core/view/numberOfMessages')
            status['messages_count'] = int(msgs_resp.get('numberOfMessages', 0))

        except Exception as e:
            logger.debug(f"Error getting ZAP status: {e}")

        return status

    def _zap_add_to_scope(self, target: str) -> bool:
        """Add target URL to ZAP scope (for focused scanning)"""
        try:
            # Create a context for the target
            context_name = f"ragnar_{int(time.time())}"
            self._zap_api_call('JSON/context/action/newContext', {'contextName': context_name})

            # Add target to context scope
            # Escape the URL for regex
            url_pattern = target.replace('.', '\\.').replace('/', '\\/')
            if not url_pattern.endswith('.*'):
                url_pattern += '.*'

            self._zap_api_call('JSON/context/action/includeInContext', {
                'contextName': context_name,
                'regex': url_pattern
            })

            # Ensure the context is in scope so inScopeOnly scans work
            self._zap_set_context_in_scope(context_name, True)

            logger.info(f"Added {target} to ZAP scope (context: {context_name})")
            return True

        except Exception as e:
            logger.error(f"Error adding target to ZAP scope: {e}")
            return False

    def _zap_set_context_in_scope(self, context_name: str, in_scope: bool = True) -> bool:
        """Set a ZAP context as in-scope for scanning."""
        try:
            self._zap_api_call('JSON/context/action/setContextInScope', {
                'contextName': context_name,
                'booleanInScope': str(bool(in_scope)).lower()
            })
            logger.info(f"Set context '{context_name}' in-scope={in_scope}")
            return True
        except Exception as e:
            logger.warning(f"Failed to set context '{context_name}' in-scope={in_scope}: {e}")
            return False

    def _setup_api_scan(self, target: str, options: Dict, progress):
        """Set up ZAP for API scanning: import OpenAPI spec, add custom headers, seed request"""
        # Import OpenAPI spec if provided
        openapi_url = options.get('openapi_url')
        if openapi_url:
            progress.current_check = "Importing OpenAPI specification..."
            try:
                self.zap_import_openapi(openapi_url, target)
                logger.info(f"Imported OpenAPI spec from {openapi_url} for API scan")
            except Exception as e:
                logger.warning(f"Failed to import OpenAPI spec via addon: {e}")

            # Always seed endpoints from the spec into ZAP's site tree as a
            # fallback.  The OpenAPI addon may not be installed, or ZAP may
            # fail to parse the spec.  Seeding ensures every path and its
            # parameters appear in the site tree so the active scanner can
            # fuzz them.
            progress.current_check = "Seeding API endpoints from spec..."
            try:
                self._seed_endpoints_from_spec(openapi_url, target, options)
            except Exception as e:
                logger.warning(f"Failed to seed endpoints from spec: {e}")

        # Add custom headers via Replacer rules
        custom_headers = options.get('custom_headers', '')
        if custom_headers:
            progress.current_check = "Applying custom headers..."
            for i, line in enumerate(custom_headers.strip().split('\n')):
                line = line.strip()
                if not line or ':' not in line:
                    continue
                header_name, header_value = line.split(':', 1)
                header_name = header_name.strip()
                header_value = header_value.strip()
                if not header_name:
                    continue
                rule_desc = f'ApiScan-Header-{i}'
                try:
                    # Remove existing rule with same name
                    try:
                        self._zap_api_call('JSON/replacer/action/removeRule', {'description': rule_desc})
                    except Exception:
                        pass
                    self._zap_api_call('JSON/replacer/action/addRule', {
                        'description': rule_desc,
                        'enabled': 'true',
                        'matchType': 'REQ_HEADER',
                        'matchString': header_name,
                        'replacement': header_value,
                        'matchRegex': 'false',
                        'initiators': ''
                    })
                    logger.info(f"Added custom header via Replacer: {header_name}")
                except Exception as e:
                    logger.warning(f"Failed to add custom header '{header_name}': {e}")

        # Seed ZAP with a custom HTTP request if method/body specified
        http_method = options.get('http_method', 'GET')
        request_body = options.get('request_body', '')

        if http_method != 'GET' or request_body:
            progress.current_check = f"Seeding {http_method} request to target..."
            try:
                # Parse target URL for host header
                from urllib.parse import urlparse
                parsed = urlparse(target)
                host = parsed.netloc or parsed.hostname or target

                # Build raw HTTP request message
                path = parsed.path or '/'
                if parsed.query:
                    path += f'?{parsed.query}'

                # Determine content type from custom headers or default
                content_type = 'application/json'
                if custom_headers:
                    for line in custom_headers.strip().split('\n'):
                        if ':' in line and line.split(':')[0].strip().lower() == 'content-type':
                            content_type = line.split(':', 1)[1].strip()
                            break

                request_lines = [
                    f'{http_method} {path} HTTP/1.1',
                    f'Host: {host}',
                ]

                # Add custom headers to the raw request
                if custom_headers:
                    for line in custom_headers.strip().split('\n'):
                        line = line.strip()
                        if line and ':' in line:
                            request_lines.append(line)

                # Add content-type and body for methods that support it
                if request_body and http_method in ('POST', 'PUT', 'PATCH', 'DELETE'):
                    has_content_type = any('content-type' in h.lower() for h in request_lines)
                    if not has_content_type:
                        request_lines.append(f'Content-Type: {content_type}')
                    request_lines.append(f'Content-Length: {len(request_body)}')
                    request_lines.append('')
                    request_lines.append(request_body)
                else:
                    request_lines.append('')
                    request_lines.append('')

                raw_request = '\r\n'.join(request_lines)

                self._zap_api_call('JSON/core/action/sendRequest', {
                    'request': raw_request,
                    'followRedirects': 'true'
                })
                logger.info(f"Seeded ZAP with {http_method} request to {target}")
                time.sleep(2)
            except Exception as e:
                logger.warning(f"Failed to seed API request: {e}")

    def _auto_discover_openapi_spec(self, target: str, options: Dict, progress):
        """Auto-discover an OpenAPI/Swagger spec on the target and seed endpoints.

        Probes common spec paths on the target host.  When a valid spec is
        found its endpoints are seeded into ZAP's site tree so the active
        scanner can fuzz them.  This runs for every scan mode (Web or API)
        so the user does not need to manually provide a spec URL.
        """
        parsed = urllib.parse.urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        common_paths = [
            '/openapi.json',
            '/swagger.json',
            '/v3/api-docs',
            '/v2/api-docs',
            '/swagger/v1/swagger.json',
            '/api/openapi.json',
            '/api/swagger.json',
            '/api-docs',
            '/api-docs.json',
            '/docs/openapi.json',
            '/swagger/doc.json',
            '/api/v1/openapi.json',
            '/api/v1/swagger.json',
            '/api/v2/openapi.json',
            '/.well-known/openapi.json',
        ]

        # Build auth headers for probing (specs may be behind auth)
        auth_headers = self._build_fuzz_auth_headers(options) if options else {}

        for probe_path in common_paths:
            probe_url = f"{base}{probe_path}"
            try:
                probe_req = urllib.request.Request(probe_url, method='GET')
                probe_req.add_header('Accept', 'application/json')
                for h_name, h_value in auth_headers.items():
                    probe_req.add_header(h_name, h_value)
                ssl_ctx = None
                if probe_url.startswith('https'):
                    import ssl
                    ssl_ctx = ssl.create_default_context()
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(probe_req, timeout=8, context=ssl_ctx) as resp:
                    body = resp.read().decode('utf-8')
                    spec = json.loads(body)
                    if 'paths' in spec and spec['paths']:
                        logger.info(f"Auto-discovered OpenAPI spec at {probe_url} "
                                    f"({len(spec['paths'])} paths)")
                        progress.current_check = f"Seeding endpoints from {probe_path}..."

                        # Also try the addon import (best-effort)
                        try:
                            self.zap_import_openapi(probe_url, target)
                        except Exception:
                            pass

                        self._seed_endpoints_from_spec(spec, target, options)
                        return True
            except Exception:
                continue

        logger.info("No OpenAPI spec auto-discovered on target")
        return False

    def _seed_endpoints_from_spec(self, spec_or_url, target: str, options: Dict):
        """Seed ZAP with a request to every endpoint in an OpenAPI spec.

        ``spec_or_url`` may be a parsed spec dict or a URL string.  This
        ensures all paths and their query/body parameters appear in ZAP's
        site tree even when the OpenAPI addon is missing or fails to parse the
        spec.  GET endpoints are seeded via ``accessUrl`` (which honours
        Replacer rules such as auth headers); POST/PUT/PATCH/DELETE endpoints
        are seeded via ``sendRequest`` with a JSON body built from schema
        examples.
        """
        if isinstance(spec_or_url, dict):
            spec = spec_or_url
        else:
            req = urllib.request.Request(spec_or_url)
            with urllib.request.urlopen(req, timeout=15) as response:
                spec = json.loads(response.read().decode('utf-8'))

        # Resolve base URL: always use scheme+host+port only — never carry
        # a path from the target or the spec's servers, because spec paths
        # are already absolute (e.g. /api/public).
        parsed_target = urllib.parse.urlparse(target)
        base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"

        servers = spec.get('servers', [])
        if servers and servers[0].get('url', '').startswith('http'):
            srv_parsed = urllib.parse.urlparse(servers[0]['url'])
            base_url = f"{srv_parsed.scheme}://{srv_parsed.netloc}"

        logger.info(f"Seeding endpoints with base URL: {base_url}")

        paths = spec.get('paths', {})
        custom_headers = options.get('custom_headers', '')
        seeded = 0

        for path, methods in paths.items():
            for method, details in methods.items():
                if method not in ('get', 'post', 'put', 'patch', 'delete'):
                    continue

                # Build URL with query-parameter examples
                url = f"{base_url}{path}"
                params = details.get('parameters', [])
                query_parts = {}
                for param in params:
                    if param.get('in') == 'query':
                        name = param.get('name', '')
                        example = (param.get('schema') or {}).get('example', 'test')
                        if name:
                            query_parts[name] = example
                if query_parts:
                    url += '?' + urllib.parse.urlencode(query_parts)

                try:
                    if method == 'get':
                        self._zap_api_call('JSON/core/action/accessUrl', {
                            'url': url,
                            'followRedirects': 'true'
                        })
                    else:
                        # Build a raw HTTP request for non-GET methods
                        parsed = urllib.parse.urlparse(url)
                        host = parsed.netloc
                        req_path = parsed.path or '/'
                        if parsed.query:
                            req_path += f'?{parsed.query}'

                        # Construct JSON body from schema examples
                        body = ''
                        rb = details.get('requestBody', {})
                        if rb:
                            json_schema = (rb.get('content', {})
                                             .get('application/json', {})
                                             .get('schema', {}))
                            props = json_schema.get('properties', {})
                            if props:
                                body_obj = {}
                                for pname, pschema in props.items():
                                    body_obj[pname] = pschema.get('example', '')
                                body = json.dumps(body_obj)

                        request_lines = [
                            f'{method.upper()} {req_path} HTTP/1.1',
                            f'Host: {host}',
                            'Content-Type: application/json',
                        ]

                        # Include custom headers (e.g. auth)
                        if custom_headers:
                            for hline in custom_headers.strip().split('\n'):
                                hline = hline.strip()
                                if hline and ':' in hline:
                                    request_lines.append(hline)

                        if body:
                            request_lines.append(f'Content-Length: {len(body)}')
                        request_lines.append('')
                        request_lines.append(body)

                        raw_request = '\r\n'.join(request_lines)
                        self._zap_api_call('JSON/core/action/sendRequest', {
                            'request': raw_request,
                            'followRedirects': 'true'
                        })

                    seeded += 1
                    logger.info(f"Seeded endpoint: {method.upper()} {url}")
                except Exception as e:
                    logger.warning(f"Failed to seed {method.upper()} {path}: {e}")

                time.sleep(0.3)

        logger.info(f"Seeded {seeded} endpoints from OpenAPI spec")

    def _run_zap_spider(self, scan_id: str, target: str, options: Dict):
        """Run ZAP spider to discover URLs"""
        self._zap_busy = True
        try:
            self._run_zap_spider_inner(scan_id, target, options)
        finally:
            self._zap_busy = False

    def _run_zap_spider_inner(self, scan_id: str, target: str, options: Dict):
        """Inner spider logic — called with busy-flag protection."""
        if not self._is_zap_running():
            self._scan_log(scan_id, 'warning', "ZAP daemon not responding — attempting to start for spider scan...")
            started = False
            for attempt in range(2):
                self._scan_log(scan_id, 'info', f"ZAP start attempt {attempt + 1}/2...")
                if self.start_zap_daemon():
                    self._scan_log(scan_id, 'info', "ZAP daemon started successfully")
                    started = True
                    break
                if attempt == 0:
                    self._scan_log(scan_id, 'warning', "First attempt failed — retrying in 3s...")
                    time.sleep(3)
            if not started:
                self._scan_log(scan_id, 'error',
                               "ZAP daemon failed to start. Check server logs for [ZAP-START] diagnostics.")
                raise RuntimeError("Failed to start ZAP daemon")

        progress = self.active_scans[scan_id]

        # Clear previous session to avoid stale alerts from other targets
        progress.current_check = "Clearing previous ZAP session..."
        try:
            self._zap_api_call('JSON/core/action/newSession', {'overwrite': 'true'})
            self._scan_log(scan_id, 'info', "ZAP session cleared before spider scan")
        except Exception as e:
            self._scan_log(scan_id, 'warning', f"Could not clear ZAP session: {e}")

        progress.current_check = "Validating target URL..."

        # Validate target URL first
        is_valid, error_msg = self._validate_target_url(target)
        if not is_valid:
            raise RuntimeError(f"Target URL validation failed: {error_msg}")

        # Apply auth if provided
        self._apply_and_verify_auth(scan_id, target, options, progress)

        # API scan mode: import OpenAPI spec and/or seed custom request
        if options.get('scan_mode') == 'api':
            self._setup_api_scan(target, options, progress)

        # Auto-discover OpenAPI spec on target when no spec URL was provided.
        # Runs in EVERY scan mode (Web or API) so endpoints are always seeded.
        if not options.get('openapi_url'):
            try:
                self._auto_discover_openapi_spec(target, options, progress)
            except Exception as e:
                logger.debug(f"OpenAPI auto-discovery skipped: {e}")

        progress.current_check = "Starting ZAP spider..."

        try:
            # Add target to scope
            self._zap_add_to_scope(target)

            # Access the target first to seed ZAP
            progress.current_check = "Accessing target URL..."
            try:
                self._zap_api_call('JSON/core/action/accessUrl', {'url': target, 'followRedirects': 'true'})
            except RuntimeError as e:
                # If accessing URL fails, provide helpful message
                error_str = str(e)
                if '500' in error_str:
                    raise RuntimeError(f"ZAP cannot access target '{target}'. Verify the URL is correct and the target is accessible from this machine.")
                raise
            time.sleep(2)

            # Start spider
            max_children = options.get('max_children', 10)
            recurse = options.get('recurse', True)
            subtree_only = options.get('subtree_only', True)

            spider_resp = self._zap_api_call('JSON/spider/action/scan', {
                'url': target,
                'maxChildren': str(max_children),
                'recurse': str(recurse).lower(),
                'subtreeOnly': str(subtree_only).lower()
            })

            spider_id = spider_resp.get('scan')
            if not spider_id:
                raise RuntimeError("Failed to start ZAP spider")

            logger.info(f"ZAP spider started with ID: {spider_id}")

            # Monitor spider progress
            while True:
                status_resp = self._zap_api_call('JSON/spider/view/status', {'scanId': spider_id})
                spider_progress = int(status_resp.get('status', 0))
                progress.progress_percent = spider_progress
                progress.current_check = f"Spidering... {spider_progress}%"

                if spider_progress >= 100:
                    break

                time.sleep(2)

            # Get spider results
            results_resp = self._zap_api_call('JSON/spider/view/results', {'scanId': spider_id})
            urls_found = results_resp.get('results', [])

            logger.info(f"ZAP spider completed. Found {len(urls_found)} URLs")

            # Create info finding for discovered URLs
            if urls_found:
                finding = VulnerabilityFinding(
                    finding_id=f"{scan_id}-zap-spider-001",
                    scanner='zap_spider',
                    host=target,
                    port=None,
                    severity=VulnSeverity.INFO,
                    title=f"Spider Discovery: {len(urls_found)} URLs found",
                    description=f"ZAP spider discovered {len(urls_found)} URLs on the target",
                    tags=['zap', 'spider', 'discovery'],
                    evidence='\n'.join(urls_found[:50]),  # First 50 URLs
                    raw_output=json.dumps(urls_found[:100])
                )
                self.scan_results[scan_id].append(finding)

            # Also fetch any passive scan alerts found during spidering
            self._fetch_zap_alerts(scan_id, target)

        except Exception as e:
            logger.error(f"ZAP spider error: {e}")
            # Add auth hint if auth is configured
            error_msg = str(e)
            auth_status = self.zap_get_auth_status()
            if auth_status.get('has_auth'):
                error_msg += " [Note: Authentication is configured. If target doesn't require auth, clear ZAP auth settings.]"
            raise RuntimeError(error_msg)

    def _run_zap_active_scan(self, scan_id: str, target: str, options: Dict):
        """Run ZAP active vulnerability scan with strength-aware configuration."""
        self._zap_busy = True
        try:
            self._run_zap_active_scan_inner(scan_id, target, options)
        finally:
            self._zap_busy = False

    def _run_zap_active_scan_inner(self, scan_id: str, target: str, options: Dict):
        """Inner active scan logic — called with busy-flag protection."""
        if not self._is_zap_running():
            self._scan_log(scan_id, 'warning', "ZAP daemon not responding — attempting to start for active scan...")
            started = False
            for attempt in range(2):
                self._scan_log(scan_id, 'info', f"ZAP start attempt {attempt + 1}/2...")
                if self.start_zap_daemon():
                    self._scan_log(scan_id, 'info', "ZAP daemon started successfully")
                    started = True
                    break
                if attempt == 0:
                    self._scan_log(scan_id, 'warning', "First attempt failed — retrying in 3s...")
                    time.sleep(3)
            if not started:
                self._scan_log(scan_id, 'error',
                               "ZAP daemon failed to start. Check server logs for [ZAP-START] diagnostics.")
                raise RuntimeError("Failed to start ZAP daemon")

        progress = self.active_scans[scan_id]
        profile = self._get_strength_profile(options)
        strength = options.get('scan_strength', 'standard')
        policy_name = None

        # Clear previous session to avoid stale alerts from other targets
        progress.current_check = "Clearing previous ZAP session..."
        try:
            self._zap_api_call('JSON/core/action/newSession', {'overwrite': 'true'})
            self._scan_log(scan_id, 'info', "ZAP session cleared before active scan")
        except Exception as e:
            self._scan_log(scan_id, 'warning', f"Could not clear ZAP session: {e}")

        progress.current_check = "Validating target URL..."

        # Validate target URL first
        is_valid, error_msg = self._validate_target_url(target)
        if not is_valid:
            raise RuntimeError(f"Target URL validation failed: {error_msg}")

        # Apply auth if provided
        self._apply_and_verify_auth(scan_id, target, options, progress)

        # API scan mode: import OpenAPI spec and/or seed custom request
        if options.get('scan_mode') == 'api':
            self._setup_api_scan(target, options, progress)

        # Auto-discover OpenAPI spec on target when no spec URL was provided.
        if not options.get('openapi_url'):
            try:
                self._auto_discover_openapi_spec(target, options, progress)
            except Exception as e:
                logger.debug(f"OpenAPI auto-discovery skipped: {e}")

        # Configure input vectors for thorough/insane
        if strength != 'standard':
            progress.current_check = "Configuring scan input vectors..."
            self._configure_zap_input_vectors(scan_id, options)

        # Create scan policy for thorough/insane
        if strength != 'standard':
            progress.current_check = "Creating scan policy..."
            policy_name = self._create_zap_scan_policy(scan_id, options)

        progress.current_check = "Starting ZAP active scan..."

        try:
            # Add target to scope
            self._zap_add_to_scope(target)

            # Access target first to seed ZAP
            progress.current_check = "Accessing target URL..."
            try:
                self._zap_api_call('JSON/core/action/accessUrl', {'url': target, 'followRedirects': 'true'})
            except RuntimeError as e:
                error_str = str(e)
                if '500' in error_str:
                    raise RuntimeError(f"ZAP cannot access target '{target}'. Verify the URL is correct and the target is accessible from this machine.")
                raise
            time.sleep(2)

            # Run a quick spider first to discover URLs for active scanning
            progress.current_check = "Quick spider to discover URLs..."
            self._scan_log(scan_id, 'info', f"Running quick spider before active scan on {target}")

            spider_resp = self._zap_api_call('JSON/spider/action/scan', {
                'url': target,
                'maxChildren': str(profile['spider_max_children']),
                'recurse': 'true',
                'subtreeOnly': 'true'
            })
            spider_id = spider_resp.get('scan')

            if spider_id:
                spider_start = time.time()
                spider_timeout = min(profile['spider_timeout'], 300)

                while time.time() - spider_start < spider_timeout:
                    try:
                        status_resp = self._zap_api_call('JSON/spider/view/status', {'scanId': spider_id})
                        spider_progress = int(status_resp.get('status', 0))
                        progress.progress_percent = int(spider_progress * 0.2)
                        progress.current_check = f"Discovering URLs... {spider_progress}%"

                        if spider_progress >= 100:
                            break
                    except Exception as e:
                        logger.warning(f"Spider status check error: {e}")
                        break

                    time.sleep(2)

                try:
                    results_resp = self._zap_api_call('JSON/spider/view/results', {'scanId': spider_id})
                    urls_found = results_resp.get('results', [])
                    self._scan_log(scan_id, 'info', f"Quick spider found {len(urls_found)} URLs")
                except Exception:
                    pass

            # Start active scan with policy if available
            progress.current_check = "Starting active vulnerability scan..."
            scan_params = {
                'url': target,
                'recurse': str(options.get('recurse', True)).lower(),
                'inScopeOnly': str(options.get('in_scope_only', True)).lower(),
            }

            if policy_name:
                scan_params['scanPolicyName'] = policy_name
            else:
                scan_policy = options.get('scan_policy', 'Default Policy')
                if scan_policy and scan_policy in self.ZAP_SCAN_POLICIES:
                    scan_params['scanPolicyName'] = scan_policy

            scan_resp = self._zap_api_call('JSON/ascan/action/scan', scan_params)
            scan_id_zap = scan_resp.get('scan')

            if not scan_id_zap:
                raise RuntimeError("Failed to start ZAP active scan - no scan ID returned")

            self._scan_log(scan_id, 'info', f"ZAP active scan started with ID: {scan_id_zap}")

            # Monitor scan progress with timeout
            scan_start = time.time()
            scan_timeout = profile['active_scan_timeout']
            last_progress = -1
            stall_count = 0

            while time.time() - scan_start < scan_timeout:
                try:
                    status_resp = self._zap_api_call('JSON/ascan/view/status', {'scanId': scan_id_zap})
                    scan_progress = int(status_resp.get('status', 0))

                    progress.progress_percent = 20 + int(scan_progress * 0.8)
                    progress.current_check = f"Active scanning... {scan_progress}%"

                    try:
                        alerts_resp = self._zap_api_call('JSON/core/view/numberOfAlerts', {'baseurl': target})
                        progress.findings_count = int(alerts_resp.get('numberOfAlerts', 0))
                    except Exception:
                        pass

                    if scan_progress >= 100:
                        break

                    if scan_progress == last_progress:
                        stall_count += 1
                        if stall_count >= profile['stall_threshold']:
                            self._scan_log(scan_id, 'warning',
                                           f"Active scan stalled at {scan_progress}%, stopping...")
                            break
                    else:
                        stall_count = 0
                        last_progress = scan_progress

                except Exception as e:
                    logger.warning(f"Active scan status check error: {e}")

                time.sleep(5)

            if time.time() - scan_start >= scan_timeout:
                self._scan_log(scan_id, 'warning', f"Active scan timed out after {scan_timeout}s")

            self._scan_log(scan_id, 'info', "ZAP active scan completed")

            # ragnar-fuzz phase (thorough/insane only)
            if profile['enable_fuzzer']:
                progress.current_check = "Running ragnar-fuzz..."
                self._scan_log(scan_id, 'info', "Starting ragnar-fuzz custom parameter fuzzer...")
                self._run_zap_parameter_fuzz_phase(scan_id, target, options, progress)

                progress.current_check = "Detecting JSON reflections..."
                self._scan_log(scan_id, 'info', "Scanning for JSON API reflections...")
                self._detect_json_reflections(scan_id, target, options, progress)

            # Fetch all alerts
            self._fetch_zap_alerts(scan_id, target)

        except Exception as e:
            logger.error(f"ZAP active scan error: {e}")
            error_msg = str(e)
            auth_status = self.zap_get_auth_status()
            if auth_status.get('has_auth'):
                error_msg += " [Note: Authentication is configured. If target doesn't require auth, clear ZAP auth settings.]"
            raise RuntimeError(error_msg)
        finally:
            self._remove_zap_scan_policy(scan_id, policy_name)

    def _get_zap_context_id(self, context_name: str = 'default') -> Optional[str]:
        """Get ZAP context ID by name, returns None if not found"""
        try:
            ctx_resp = self._zap_api_call('JSON/context/view/context', {'contextName': context_name})
            return ctx_resp.get('context', {}).get('id')
        except Exception:
            return None

    def _verify_zap_auth(self, target: str, options: Dict, progress: ScanProgress) -> bool:
        """Verify authentication works by making an authenticated request to the target.
        Returns True if auth is verified or not needed, False if auth failed."""
        auth_status = self.zap_get_auth_status()
        if not auth_status.get('has_auth'):
            return True  # No auth configured, skip verification

        progress.current_check = "Verifying authentication..."
        auth_type = auth_status.get('auth_type', 'unknown')
        logger.info(f"Verifying {auth_type} authentication against {target}")

        try:
            # For simple auth types, verify by making a request through ZAP
            # Access the target URL - ZAP will apply configured auth
            self._zap_api_call('JSON/core/action/accessUrl', {
                'url': target, 'followRedirects': 'true'
            })
            time.sleep(1)

            # Check if we got a non-error response by looking at ZAP's message history
            try:
                msgs_resp = self._zap_api_call('JSON/core/view/messages', {
                    'baseurl': target, 'start': '0', 'count': '5'
                })
                messages = msgs_resp.get('messages', [])
                if messages:
                    last_msg = messages[-1]
                    status_code = 0
                    resp_header = last_msg.get('responseHeader', '')
                    if resp_header:
                        # Parse "HTTP/1.1 200 OK" format safely
                        parts = resp_header.split(' ', 2)
                        if len(parts) >= 2 and parts[1].isdigit():
                            status_code = int(parts[1])
                    if status_code in (401, 403):
                        logger.warning(f"Auth verification got {status_code} - credentials may be invalid")
                        progress.current_check = f"Auth verification warning: got HTTP {status_code}"
                    else:
                        logger.info(f"Auth verification OK - got HTTP {status_code}")
            except Exception as msg_err:
                logger.debug(f"Could not check auth verification response: {msg_err}")

            return True
        except Exception as e:
            logger.warning(f"Auth verification failed: {e}")
            return True  # Don't block scan on verification failure

    def _apply_and_verify_auth(self, scan_id: str, target: str, options: Dict, progress: 'ScanProgress'):
        """Apply auth and verify it works. Sets progress.auth_type/auth_status and options._context_id."""
        auth_applied, auth_type = self._apply_scan_auth(options)
        has_auth = auth_applied

        if auth_type:
            progress.auth_type = auth_type
            progress.auth_status = "applied"
            progress.current_check = f"Verifying {auth_type} auth..."

            oauth2_token_acquired = options.get('_oauth2_token_acquired', False)
            self._scan_log(scan_id, 'info', f"Sending authenticated request to {target}...")
            auth_verified, http_status = self._verify_auth_request(target)

            if auth_verified or oauth2_token_acquired:
                if 200 <= http_status < 400:
                    progress.auth_status = f"verified (HTTP {http_status})"
                    self._scan_log(scan_id, 'info', f"AUTH VERIFIED: Target responded HTTP {http_status} with {auth_type} credentials")
                elif oauth2_token_acquired:
                    progress.auth_status = f"verified (token acquired)"
                    self._scan_log(scan_id, 'info', f"AUTH VERIFIED: OAuth2 token acquired successfully (target returned HTTP {http_status} which is an endpoint issue, not auth)")
                else:
                    progress.auth_status = f"applied (HTTP {http_status})"
                    self._scan_log(scan_id, 'info', f"Auth applied - endpoint returned HTTP {http_status} (not an auth error, scan will continue)")
                progress.current_check = f"Auth {progress.auth_status}"
            else:
                progress.auth_status = f"failed (HTTP {http_status})"
                progress.current_check = f"Auth failed: {auth_type} (HTTP {http_status})"
                self._scan_log(scan_id, 'warning', f"Auth verification FAILED: HTTP {http_status} - credentials may be invalid")

        # Get or create context ID if auth is configured
        context_id = self._get_zap_context_id('default')
        if has_auth and not context_id:
            try:
                self._zap_api_call('JSON/context/action/newContext', {'contextName': 'default'})
                context_id = self._get_zap_context_id('default')
                self._scan_log(scan_id, 'info', f"Created 'default' context for authenticated scan (ID: {context_id})")
            except Exception as e:
                self._scan_log(scan_id, 'warning', f"Could not create default context: {e}")

        if context_id:
            options['_context_id'] = context_id
            options['_has_auth'] = has_auth
            self._scan_log(scan_id, 'info', f"Using ZAP context ID {context_id} for scan (auth configured: {has_auth})")
        elif has_auth:
            options['_has_auth'] = has_auth

    def _apply_scan_auth(self, options: Dict) -> Tuple[bool, str]:
        """Apply authentication for this scan using ZAP Replacer rules.
        Returns (auth_applied: bool, auth_type: str)."""
        auth_type = ""
        
        # Cookie auth
        if options.get('cookie_value'):
            try:
                # Remove any existing cookie rule first
                try:
                    self._zap_api_call('JSON/replacer/action/removeRule', {'description': 'ScanAuth-Cookie'})
                except Exception:
                    pass
                
                self._zap_api_call('JSON/replacer/action/addRule', {
                    'description': 'ScanAuth-Cookie',
                    'enabled': 'true',
                    'matchType': 'REQ_HEADER',
                    'matchRegex': 'false',
                    'matchString': 'Cookie',
                    'replacement': options['cookie_value'],
                    'initiators': ''
                })
                logger.info("Applied cookie auth for scan")
                auth_type = "cookie"
            except Exception as e:
                logger.error(f"Failed to apply cookie auth: {e}")
                return (False, "cookie (failed)")
        
        # Bearer token auth
        if options.get('bearer_token'):
            try:
                try:
                    self._zap_api_call('JSON/replacer/action/removeRule', {'description': 'ScanAuth-Bearer'})
                except Exception:
                    pass
                
                self._zap_api_call('JSON/replacer/action/addRule', {
                    'description': 'ScanAuth-Bearer',
                    'enabled': 'true',
                    'matchType': 'REQ_HEADER',
                    'matchRegex': 'false',
                    'matchString': 'Authorization',
                    'replacement': f"Bearer {options['bearer_token']}",
                    'initiators': ''
                })
                logger.info("Applied bearer token auth for scan")
                auth_type = "bearer_token"
            except Exception as e:
                logger.error(f"Failed to apply bearer token auth: {e}")
                return (False, "bearer_token (failed)")
        
        # API key auth
        if options.get('api_key'):
            try:
                try:
                    self._zap_api_call('JSON/replacer/action/removeRule', {'description': 'ScanAuth-APIKey'})
                except Exception:
                    pass
                
                header_name = options.get('api_key_header', 'X-API-Key')
                self._zap_api_call('JSON/replacer/action/addRule', {
                    'description': 'ScanAuth-APIKey',
                    'enabled': 'true',
                    'matchType': 'REQ_HEADER',
                    'matchRegex': 'false',
                    'matchString': header_name,
                    'replacement': options['api_key'],
                    'initiators': ''
                })
                logger.info(f"Applied API key auth for scan ({header_name})")
                auth_type = f"api_key ({header_name})"
            except Exception as e:
                logger.error(f"Failed to apply API key auth: {e}")
                return (False, "api_key (failed)")
        
        # OAuth2 Client Credentials - fetch token then apply as bearer
        if options.get('oauth2_client_creds'):
            cc = options['oauth2_client_creds']
            try:
                token_url = cc['token_url']
                logger.info(f"Requesting OAuth2 token from {token_url}...")
                post_data = {
                    'grant_type': 'client_credentials',
                    'client_id': cc['client_id'],
                    'client_secret': cc['client_secret'],
                }
                if cc.get('scope'):
                    post_data['scope'] = cc['scope']

                encoded_data = urllib.parse.urlencode(post_data).encode('utf-8')
                req = urllib.request.Request(token_url, data=encoded_data, method='POST')
                req.add_header('Content-Type', 'application/x-www-form-urlencoded')

                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                    token_status = resp.status
                    token_resp = json.loads(resp.read().decode())

                access_token = token_resp.get('access_token')
                if not access_token:
                    logger.error(f"OAuth2 CC token response missing access_token: {list(token_resp.keys())}")
                    return (False, "oauth2_client_creds (no token)")

                token_type = token_resp.get('token_type', 'Bearer')
                expires_in = token_resp.get('expires_in', 'unknown')
                logger.info(f"OAuth2 token acquired (HTTP {token_status}, type={token_type}, expires_in={expires_in}s)")

                # Apply as bearer token via Replacer
                try:
                    self._zap_api_call('JSON/replacer/action/removeRule', {'description': 'ScanAuth-Bearer'})
                except Exception:
                    pass

                self._zap_api_call('JSON/replacer/action/addRule', {
                    'description': 'ScanAuth-Bearer',
                    'enabled': 'true',
                    'matchType': 'REQ_HEADER',
                    'matchRegex': 'false',
                    'matchString': 'Authorization',
                    'replacement': f"Bearer {access_token}",
                    'initiators': ''
                })
                auth_type = "oauth2_client_creds"
                # Store flag so verification knows OAuth2 token was acquired
                options['_oauth2_token_acquired'] = True
            except urllib.error.HTTPError as e:
                error_body = e.read().decode() if e.fp else ''
                logger.error(f"OAuth2 CC token request failed: HTTP {e.code} - {error_body[:500]}")
                return (False, f"oauth2_client_creds (HTTP {e.code})")
            except Exception as e:
                logger.error(f"OAuth2 CC token fetch failed: {e}")
                return (False, "oauth2_client_creds (failed)")

        # HTTP Basic auth
        if options.get('http_basic_auth'):
            try:
                try:
                    self._zap_api_call('JSON/replacer/action/removeRule', {'description': 'ScanAuth-Basic'})
                except Exception:
                    pass
                
                import base64
                auth_string = base64.b64encode(options['http_basic_auth'].encode()).decode()
                self._zap_api_call('JSON/replacer/action/addRule', {
                    'description': 'ScanAuth-Basic',
                    'enabled': 'true',
                    'matchType': 'REQ_HEADER',
                    'matchRegex': 'false',
                    'matchString': 'Authorization',
                    'replacement': f"Basic {auth_string}",
                    'initiators': ''
                })
                logger.info("Applied HTTP Basic auth for scan")
                auth_type = "http_basic"
            except Exception as e:
                logger.error(f"Failed to apply HTTP Basic auth: {e}")
                return (False, "http_basic (failed)")
        
        # Form-based auth - uses ZAP context authentication
        if options.get('form_auth'):
            fa = options['form_auth']
            try:
                success, err = self.zap_set_authentication('default', 'form', fa)
                if success:
                    logger.info("Applied form-based auth for scan")
                    auth_type = "form"
                else:
                    logger.error(f"Failed to apply form auth: {err}")
                    return (False, f"form ({err})")
            except Exception as e:
                logger.error(f"Failed to apply form auth: {e}")
                return (False, "form (failed)")

        # OAuth2 BBA - uses ZAP browser-based authentication
        if options.get('oauth2_bba'):
            bba = options['oauth2_bba']
            try:
                success, err = self.zap_set_authentication('default', 'oauth2_bba', bba)
                if success:
                    logger.info("Applied OAuth2/BBA auth for scan")
                    auth_type = "oauth2_bba"
                else:
                    logger.error(f"Failed to apply OAuth2/BBA auth: {err}")
                    return (False, f"oauth2_bba ({err})")
            except Exception as e:
                logger.error(f"Failed to apply OAuth2/BBA auth: {e}")
                return (False, "oauth2_bba (failed)")

        # Script-based auth - uses ZAP script/BBA authentication
        if options.get('script_auth'):
            sa = options['script_auth']
            try:
                success, err = self.zap_set_authentication('default', 'script_auth', sa)
                if success:
                    logger.info("Applied script-based auth for scan")
                    auth_type = "script_auth"
                else:
                    logger.error(f"Failed to apply script auth: {err}")
                    return (False, f"script_auth ({err})")
            except Exception as e:
                logger.error(f"Failed to apply script auth: {e}")
                return (False, "script_auth (failed)")

        return (bool(auth_type), auth_type)

    def _clear_scan_auth(self):
        """Clear all scan-specific auth rules from ZAP Replacer"""
        rules_to_remove = ['ScanAuth-Cookie', 'ScanAuth-Bearer', 'ScanAuth-APIKey', 'ScanAuth-Basic']
        for rule in rules_to_remove:
            try:
                self._zap_api_call('JSON/replacer/action/removeRule', {'description': rule})
            except Exception:
                pass  # Rule may not exist

    def _verify_auth_request(self, target: str) -> Tuple[bool, int]:
        """
        Make a test request to verify auth is working.
        Returns (verified: bool, http_status: int)
        - verified=True if status is 2xx, 3xx, 404, 405, 400 (auth is working, endpoint issue)
        - verified=False only if status is 401/403 (actual auth failure)
        """
        try:
            # Access the target URL via ZAP to test auth
            self._zap_api_call('JSON/core/action/accessUrl', {
                'url': target,
                'followRedirects': 'true'
            })
            
            # Give ZAP a moment to process the request
            time.sleep(1)
            
            # Get the most recent message from the history
            messages = self._zap_api_call('JSON/core/view/messages', {
                'baseurl': target,
                'start': '0',
                'count': '5'
            })
            
            if messages and 'messages' in messages and len(messages['messages']) > 0:
                # Get the most recent message
                latest_msg = messages['messages'][-1]
                status_code = int(latest_msg.get('responseHeader', '').split(' ')[1]) if 'responseHeader' in latest_msg else 0
                
                if status_code == 0:
                    # Try to extract from responseStatusCode if available
                    status_code = int(latest_msg.get('statusCode', 0) or 0)
                
                # 401/403 = actual auth failure; everything else means auth is OK
                # (404/405/400 = endpoint issue, not auth issue)
                if status_code in (401, 403):
                    return (False, status_code)
                else:
                    return (True, status_code)
            
            # If we can't get messages, return unknown status
            logger.warning("Could not retrieve response to verify auth")
            return (True, 0)  # Assume applied if we can't verify
            
        except Exception as e:
            logger.error(f"Error verifying auth request: {e}")
            return (True, 0)  # Assume applied if we can't verify

    def _run_zap_full_scan(self, scan_id: str, target: str, options: Dict):
        """Run complete ZAP scan with strength-aware orchestration.

        Standard  (3 phases): Spider → AJAX Spider → Active Scan
        Thorough+ (5 phases): Spider → AJAX Spider → Active Scan → ragnar-fuzz → JSON Reflections
        """
        self._zap_busy = True
        try:
            self._run_zap_full_scan_inner(scan_id, target, options)
        finally:
            self._zap_busy = False

    def _run_zap_full_scan_inner(self, scan_id: str, target: str, options: Dict):
        """Inner full scan logic — called with busy-flag protection."""
        if not self._is_zap_running():
            self._scan_log(scan_id, 'warning', "ZAP daemon not responding — attempting to start...")
            # Try up to 2 times (cleanup may need a moment to free the port)
            started = False
            for attempt in range(2):
                self._scan_log(scan_id, 'info',
                               f"ZAP start attempt {attempt + 1}/2 (port {self._zap_port})...")
                if self.start_zap_daemon():
                    self._scan_log(scan_id, 'info', "ZAP daemon started successfully")
                    started = True
                    break
                if attempt == 0:
                    self._scan_log(scan_id, 'warning',
                                   "First ZAP start attempt failed — cleaning up and retrying in 3s...")
                    time.sleep(3)
            if not started:
                self._scan_log(scan_id, 'error',
                               f"ZAP daemon failed to start after 2 attempts on port {self._zap_port}. "
                               "Check server logs for [ZAP-START] entries with detailed diagnostics.")
                raise RuntimeError(
                    "Failed to start ZAP daemon. This can happen after a heavy scan "
                    "causes ZAP to crash (OOM). Check Java memory or restart the service. "
                    "See server logs for [ZAP-START] diagnostics.")

        progress = self.active_scans[scan_id]
        profile = self._get_strength_profile(options)
        strength = options.get('scan_strength', 'standard')
        policy_name = None
        total_phases = 5 if profile['enable_fuzzer'] else 3

        self._scan_log(scan_id, 'info',
                       f"ZAP full scan starting with strength={strength}, phases={total_phases}")

        # Clear previous session to avoid stale alerts from other targets
        progress.current_check = "Clearing previous ZAP session..."
        try:
            self._zap_api_call('JSON/core/action/newSession', {'overwrite': 'true'})
            self._scan_log(scan_id, 'info', "ZAP session cleared before full scan")
        except Exception as e:
            self._scan_log(scan_id, 'warning', f"Could not clear ZAP session: {e}")

        progress.current_check = "Validating target URL..."

        # Validate target URL first
        is_valid, error_msg = self._validate_target_url(target)
        if not is_valid:
            raise RuntimeError(f"Target URL validation failed: {error_msg}")

        # Apply inline auth if provided in options (per-scan auth)
        self._apply_and_verify_auth(scan_id, target, options, progress)
        has_auth = options.get('_has_auth', False)

        # API scan mode: import OpenAPI spec and/or seed custom request
        if options.get('scan_mode') == 'api':
            self._setup_api_scan(target, options, progress)
        else:
            # Auto-discover OpenAPI spec on target so endpoints are seeded
            # even in Web scan mode.
            try:
                self._auto_discover_openapi_spec(target, options, progress)
            except Exception as e:
                logger.debug(f"OpenAPI auto-discovery skipped: {e}")

        # Configure input vectors for thorough/insane
        if strength != 'standard':
            progress.current_check = "Configuring scan input vectors..."
            self._configure_zap_input_vectors(scan_id, options)

        # Create scan policy for thorough/insane
        if strength != 'standard':
            progress.current_check = "Creating scan policy..."
            policy_name = self._create_zap_scan_policy(scan_id, options)

        alerts_fetched = False

        try:
            # Phase 1: Spider
            progress.current_check = f"Phase 1/{total_phases}: Running spider..."
            self._scan_log(scan_id, 'info', f"Phase 1/{total_phases}: Starting spider crawl...")
            self._run_zap_spider_phase(scan_id, target, options, progress)

            # Phase 2: Ajax Spider (if enabled)
            if options.get('ajax_spider', True):
                progress.current_check = f"Phase 2/{total_phases}: Running Ajax spider..."
                self._scan_log(scan_id, 'info', f"Phase 2/{total_phases}: Starting AJAX spider...")
                self._run_zap_ajax_spider_phase(scan_id, target, options, progress)

            # Phase 3: Active Scan (with scan policy for thorough/insane)
            progress.current_check = f"Phase 3/{total_phases}: Running active scan..."
            self._scan_log(scan_id, 'info', f"Phase 3/{total_phases}: Starting active vulnerability scan...")
            self._run_zap_active_scan_phase(scan_id, target, options, progress, policy_name)

            # Phase 4: ragnar-fuzz (thorough/insane only)
            if profile['enable_fuzzer']:
                progress.current_check = f"Phase 4/{total_phases}: Running ragnar-fuzz..."
                self._scan_log(scan_id, 'info',
                               f"Phase 4/{total_phases}: Starting ragnar-fuzz custom parameter fuzzer...")
                self._run_zap_parameter_fuzz_phase(scan_id, target, options, progress)

            # Phase 5: JSON Reflection Detection (thorough/insane only)
            if profile['enable_fuzzer']:
                progress.current_check = f"Phase 5/{total_phases}: Detecting JSON reflections..."
                self._scan_log(scan_id, 'info',
                               f"Phase 5/{total_phases}: Scanning for JSON API reflections...")
                self._detect_json_reflections(scan_id, target, options, progress)

            # Final: Fetch all ZAP alerts
            progress.current_check = "Fetching vulnerability alerts..."
            try:
                self._fetch_zap_alerts(scan_id, target)
                alerts_fetched = True
            except Exception as fetch_err:
                self._scan_log(scan_id, 'error', f"Failed to fetch alerts after scan phases: {fetch_err}")
                progress.error_message = f"Scan phases completed but alert fetching failed: {fetch_err}"

            findings_count = len(self.scan_results.get(scan_id, []))
            self._scan_log(scan_id, 'info', f"ZAP full scan completed with {findings_count} findings")

            if findings_count == 0 and not alerts_fetched:
                self._scan_log(scan_id, 'warning', f"ZAP scan completed with 0 findings - alert fetching may have failed")

        except Exception as e:
            self._scan_log(scan_id, 'error', f"ZAP full scan error: {e}")
            # Try to fetch alerts even on error - don't lose findings
            if not alerts_fetched:
                try:
                    self._scan_log(scan_id, 'info', "Attempting to fetch ZAP alerts after error...")
                    self._fetch_zap_alerts(scan_id, target)
                except Exception as fetch_error:
                    self._scan_log(scan_id, 'error', f"Failed to fetch alerts after error: {fetch_error}")
            raise RuntimeError(str(e))
        finally:
            # Clean up scan-specific auth rules
            if has_auth:
                self._clear_scan_auth()
                self._scan_log(scan_id, 'info', "Cleared scan auth rules")
            # Clean up temporary scan policy
            self._remove_zap_scan_policy(scan_id, policy_name)
            # Clear ZAP session after scan to free memory (prevents OOM on next scan)
            try:
                if self._is_zap_running():
                    self._zap_api_call('JSON/core/action/newSession', {'overwrite': 'true'})
                    self._scan_log(scan_id, 'info', "Post-scan: ZAP session cleared to free memory")
            except Exception as cleanup_err:
                self._scan_log(scan_id, 'debug', f"Post-scan session cleanup failed (non-fatal): {cleanup_err}")

    def _run_zap_spider_phase(self, scan_id: str, target: str, options: Dict, progress: ScanProgress):
        """Spider phase of full scan"""
        # If auth is configured, add target to the 'default' context where auth lives
        # Otherwise, create a new scope context
        has_auth = options.get('_context_id') or options.get('_has_auth')
        if has_auth:
            # Auth is configured - add target URL to the 'default' context
            try:
                parsed_url = urllib.parse.urlparse(target)
                include_regex = f"{parsed_url.scheme}://{parsed_url.netloc}.*"
                self._zap_api_call('JSON/context/action/includeInContext', {
                    'contextName': 'default',
                    'regex': include_regex
                })
                self._zap_set_context_in_scope('default', True)
                self._scan_log(scan_id, 'info', f"Added {include_regex} to auth context 'default'")
            except Exception as e:
                self._scan_log(scan_id, 'warning', f"Could not add target to auth context: {e}")
                # Fall back to creating new scope
                self._zap_add_to_scope(target)
        else:
            self._zap_add_to_scope(target)

        # Access target with better error handling
        try:
            self._zap_api_call('JSON/core/action/accessUrl', {'url': target, 'followRedirects': 'true'})
        except RuntimeError as e:
            error_str = str(e)
            if '500' in error_str:
                raise RuntimeError(f"ZAP cannot access target '{target}'. Verify the URL is correct and the target is accessible from this machine.")
            raise
        time.sleep(1)

        profile = self._get_strength_profile(options)
        spider_params = {
            'url': target,
            'maxChildren': str(options.get('max_children', profile['spider_max_children'])),
            'recurse': 'true',
            'subtreeOnly': 'false' if has_auth else 'true'  # Crawl full domain when authenticated
        }
        # Pass context name if auth is configured
        if has_auth:
            spider_params['contextName'] = 'default'
        spider_resp = self._zap_api_call('JSON/spider/action/scan', spider_params)
        spider_id = spider_resp.get('scan')

        if not spider_id:
            self._scan_log(scan_id, 'warning', "Failed to start spider phase, continuing...")
            return

        self._scan_log(scan_id, 'info', f"Spider started with ID: {spider_id}")

        # Spider with timeout
        spider_start = time.time()
        spider_timeout = profile['spider_timeout']

        while time.time() - spider_start < spider_timeout:
            try:
                status_resp = self._zap_api_call('JSON/spider/view/status', {'scanId': spider_id})
                spider_progress = int(status_resp.get('status', 0))
                # Scale: 0-20% if fuzzer enabled, 0-30% if standard
                if profile['enable_fuzzer']:
                    progress.progress_percent = int(spider_progress * 0.2)
                else:
                    progress.progress_percent = int(spider_progress * 0.3)
                total_phases = 5 if profile['enable_fuzzer'] else 3
                progress.current_check = f"Phase 1/{total_phases}: Spidering... {spider_progress}%"

                if spider_progress >= 100:
                    break
            except Exception as e:
                self._scan_log(scan_id, 'warning', f"Spider status error: {e}")
                break

            time.sleep(2)

        if time.time() - spider_start >= spider_timeout:
            self._scan_log(scan_id, 'warning', "Spider phase timed out")

        # Log URLs discovered by spider
        try:
            urls_resp = self._zap_api_call('JSON/spider/view/results', {'scanId': spider_id})
            urls_found = urls_resp.get('results', [])
            self._scan_log(scan_id, 'info', f"Spider completed - discovered {len(urls_found)} URLs")
            if urls_found:
                for url in urls_found[:15]:  # Log first 15
                    self._scan_log(scan_id, 'debug', f"  URL: {url}")
                if len(urls_found) > 15:
                    self._scan_log(scan_id, 'info', f"  ... and {len(urls_found) - 15} more URLs")
        except Exception as e:
            self._scan_log(scan_id, 'debug', f"Could not retrieve spider results: {e}")

    def _run_zap_ajax_spider_phase(self, scan_id: str, target: str, options: Dict, progress: ScanProgress):
        """Ajax spider phase of full scan"""
        try:
            # Configure browser for AJAX spider based on detection
            browser_id = getattr(self, '_detected_browser', None)
            if browser_id and browser_id != 'htmlunit':
                try:
                    self._zap_api_call('JSON/ajaxSpider/action/setOptionBrowserId', {
                        'String': browser_id
                    })
                    self._scan_log(scan_id, 'info', f"AJAX spider using browser: {browser_id}")
                except Exception as e:
                    self._scan_log(scan_id, 'warning', f"Failed to set AJAX spider browser to {browser_id}: {e}")
            elif browser_id == 'htmlunit':
                self._scan_log(scan_id, 'warning',
                    "No real browser detected - AJAX spider using htmlunit fallback. "
                    "Install Chrome/Chromium or Firefox for better JavaScript rendering.")

            # Use longer duration for authenticated scans (more pages to discover)
            has_auth = options.get('_context_id') or options.get('_has_auth')
            profile = self._get_strength_profile(options)
            max_duration = options.get('ajax_spider_duration',
                                       profile['ajax_timeout_auth'] if has_auth else profile['ajax_timeout'])

            # Set max duration option in ZAP before starting
            try:
                self._zap_api_call('JSON/ajaxSpider/action/setOptionMaxDuration', {
                    'Integer': str(max_duration // 60 or 1)  # ZAP expects minutes
                })
            except Exception:
                pass  # Option may not be available in older ZAP versions

            self._scan_log(scan_id, 'info', f"AJAX spider starting with max duration {max_duration}s")

            self._zap_api_call('JSON/ajaxSpider/action/scan', {
                'url': target,
                'inScope': 'true'
            })

            start_time = time.time()

            while time.time() - start_time < max_duration:
                status_resp = self._zap_api_call('JSON/ajaxSpider/view/status')
                status = status_resp.get('status', 'stopped')
                if status == 'stopped':
                    break

                elapsed = time.time() - start_time
                # Scale: 20-35% if fuzzer enabled, 30-50% if standard
                if profile['enable_fuzzer']:
                    progress.progress_percent = 20 + int((elapsed / max_duration) * 15)
                else:
                    progress.progress_percent = 30 + int((elapsed / max_duration) * 20)
                time.sleep(3)

            elapsed_total = int(time.time() - start_time)

            # Stop ajax spider if still running
            self._zap_api_call('JSON/ajaxSpider/action/stop')

            # Log results
            try:
                results_resp = self._zap_api_call('JSON/ajaxSpider/view/numberOfResults')
                ajax_results = results_resp.get('numberOfResults', '0')
                self._scan_log(scan_id, 'info', f"AJAX spider completed in {elapsed_total}s - found {ajax_results} resources")
            except Exception:
                self._scan_log(scan_id, 'info', f"AJAX spider completed in {elapsed_total}s")

        except Exception as e:
            self._scan_log(scan_id, 'warning', f"Ajax spider phase error (continuing): {e}")

    def _create_zap_scan_policy(self, scan_id: str, options: Dict) -> Optional[str]:
        """Create a temporary ZAP scan policy for thorough/insane scans.
        Returns the policy name or None if standard strength."""
        profile = self._get_strength_profile(options)
        strength = options.get('scan_strength', 'standard')

        if strength == 'standard':
            return None

        policy_name = f"ragnar-{strength}-{scan_id[-8:]}"

        try:
            self._zap_api_call('JSON/ascan/action/addScanPolicy', {
                'scanPolicyName': policy_name
            })
            self._scan_log(scan_id, 'info', f"Created scan policy: {policy_name}")
        except Exception as e:
            self._scan_log(scan_id, 'warning', f"Could not create scan policy: {e}")
            return None

        configured = 0
        for plugin_id in self.ZAP_INJECTION_SCANNER_IDS:
            try:
                self._zap_api_call('JSON/ascan/action/setScannerAttackStrength', {
                    'id': str(plugin_id),
                    'attackStrength': profile['attack_strength'],
                    'scanPolicyName': policy_name,
                })
                self._zap_api_call('JSON/ascan/action/setScannerAlertThreshold', {
                    'id': str(plugin_id),
                    'alertThreshold': profile['alert_threshold'],
                    'scanPolicyName': policy_name,
                })
                configured += 1
            except Exception:
                pass  # Plugin may not exist in this ZAP version

        self._scan_log(scan_id, 'info',
                       f"Configured {configured}/{len(self.ZAP_INJECTION_SCANNER_IDS)} "
                       f"scanner plugins for {strength} policy")
        return policy_name

    def _remove_zap_scan_policy(self, scan_id: str, policy_name: Optional[str]):
        """Remove a temporary scan policy after scan completes."""
        if not policy_name:
            return
        try:
            self._zap_api_call('JSON/ascan/action/removeScanPolicy', {
                'scanPolicyName': policy_name
            })
            self._scan_log(scan_id, 'info', f"Removed scan policy: {policy_name}")
        except Exception as e:
            self._scan_log(scan_id, 'debug', f"Could not remove scan policy {policy_name}: {e}")

    def _configure_zap_input_vectors(self, scan_id: str, options: Dict):
        """Configure ZAP input vectors for thorough/insane scans."""
        strength = options.get('scan_strength', 'standard')
        if strength == 'standard':
            return

        profile = self._get_strength_profile(options)

        try:
            # Injectable parameter types: query=1, POST=2, path=4, headers=8, cookies=16
            self._zap_api_call('JSON/ascan/action/setOptionTargetParamsInjectable', {
                'Integer': '31'
            })
            # RPC parsing: multipart=1, XML=2, JSON=4, OData=32
            self._zap_api_call('JSON/ascan/action/setOptionTargetParamsEnabledRPC', {
                'Integer': '39'
            })
            # Scan headers on all requests
            self._zap_api_call('JSON/ascan/action/setOptionScanHeadersAllRequests', {
                'Boolean': 'true'
            })
            # Handle anti-CSRF tokens automatically
            self._zap_api_call('JSON/ascan/action/setOptionHandleAntiCSRFTokens', {
                'Boolean': 'true'
            })
            # Thread count per host
            self._zap_api_call('JSON/ascan/action/setOptionThreadPerHost', {
                'Integer': str(profile['threads_per_host'])
            })
            # For insane: unlimited rule duration
            if strength == 'insane':
                try:
                    self._zap_api_call('JSON/ascan/action/setOptionMaxRuleDurationInMins', {
                        'Integer': '0'
                    })
                except Exception:
                    pass

            self._scan_log(scan_id, 'info',
                           f"Configured input vectors: injectable=31, rpc=39, "
                           f"threads={profile['threads_per_host']}, strength={strength}")

        except Exception as e:
            self._scan_log(scan_id, 'warning', f"Could not configure input vectors: {e}")

    def _analyze_reflection_context(self, payload: str, response_body: str,
                                     content_type: str = '') -> Optional[Dict]:
        """Analyze WHERE a reflected payload appears in the response.
        Returns dict with context, risk, confidence, cwe_id, description or None."""
        payload_lower = payload.lower()
        body_lower = response_body.lower()

        # Check if payload is reflected at all
        if payload not in response_body and payload_lower not in body_lower:
            return None

        idx = body_lower.find(payload_lower)
        if idx < 0:
            return None

        # Get surrounding context
        preceding = response_body[max(0, idx - 200):idx].lower()
        following = response_body[idx:idx + len(payload) + 200].lower()

        is_html = 'html' in content_type.lower() if content_type else True
        is_json = 'json' in content_type.lower() if content_type else False

        # Check JS context: <script> without closing </script> before reflection
        if is_html and '<script' in preceding and '</script' not in preceding:
            return {
                'context': 'js-context',
                'risk': 3,
                'confidence': 3,
                'cwe_id': 'CWE-79',
                'description': 'Reflected input in JavaScript context - high XSS risk',
            }

        # Check HTML attribute context
        if is_html and re.search(r'=\s*["\'][^"\']*$', preceding):
            return {
                'context': 'html-attribute',
                'risk': 3,
                'confidence': 2,
                'cwe_id': 'CWE-79',
                'description': 'Reflected input in HTML attribute context',
            }

        # Check for unescaped dangerous HTML tags in the reflected area
        dangerous_tags = ['<script', '<img', '<svg', '<body', '<iframe',
                          '<object', '<embed', '<input', '<details', '<video', '<audio']
        if is_html and any(tag in following for tag in dangerous_tags):
            return {
                'context': 'html-body',
                'risk': 3,
                'confidence': 3,
                'cwe_id': 'CWE-79',
                'description': 'Reflected input rendered as HTML with dangerous tags',
            }

        # Check for style block context
        if is_html and '<style' in preceding and '</style' not in preceding:
            return {
                'context': 'html-body',
                'risk': 2,
                'confidence': 2,
                'cwe_id': 'CWE-79',
                'description': 'Reflected input in CSS style context',
            }

        # JSON context
        if is_json:
            return {
                'context': 'json-context',
                'risk': 2,
                'confidence': 1,
                'cwe_id': 'CWE-116',
                'description': 'Reflected input in JSON response - improper encoding',
            }

        # General HTML body reflection
        if is_html:
            return {
                'context': 'html-body',
                'risk': 2,
                'confidence': 1,
                'cwe_id': 'CWE-79',
                'description': 'Reflected input in HTML response body',
            }

        # Other/ambiguous
        return {
            'context': 'other',
            'risk': 2,
            'confidence': 1,
            'cwe_id': 'CWE-79',
            'description': 'Reflected input detected in response',
        }

    def _extract_fuzz_endpoints(self, scan_id: str, target: str) -> List[Dict]:
        """Extract parameterized endpoints from ZAP message history."""
        parsed_target = urllib.parse.urlparse(target)
        target_host = parsed_target.netloc
        endpoints = []
        seen_keys = set()

        try:
            messages = self._zap_api_call('JSON/core/view/messages', {
                'baseurl': target,
                'start': '0',
                'count': '500'
            })
            msg_list = messages.get('messages', [])

            for msg in msg_list:
                req_header = msg.get('requestHeader', '')
                req_body = msg.get('requestBody', '')
                if not req_header:
                    continue

                first_line = req_header.split('\n')[0] if '\n' in req_header else req_header
                parts = first_line.split(' ')
                if len(parts) < 2:
                    continue

                method = parts[0].upper()
                req_path = parts[1]

                # Build full URL from request path
                if req_path.startswith('http'):
                    full_url = req_path
                else:
                    full_url = f"{parsed_target.scheme}://{target_host}{req_path}"

                parsed_url = urllib.parse.urlparse(full_url)

                # Check host matches
                if parsed_url.hostname != parsed_target.hostname:
                    continue

                params = {}
                if parsed_url.query:
                    params = dict(urllib.parse.parse_qsl(parsed_url.query))

                body_dict = None
                if req_body and method in ('POST', 'PUT', 'PATCH'):
                    try:
                        body_dict = json.loads(req_body)
                        if not isinstance(body_dict, dict):
                            body_dict = None
                    except (json.JSONDecodeError, ValueError):
                        pass

                # Dedup by method:path:params
                dedup_key = f"{method}:{parsed_url.path}:{sorted(params.keys()) if params else ''}"
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                if params or body_dict:
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    endpoints.append({
                        'url': base_url,
                        'params': params,
                        'method': method,
                        'body': body_dict,
                    })

        except Exception as e:
            self._scan_log(scan_id, 'warning', f"Error extracting fuzz endpoints: {e}")

        return endpoints

    def _generate_synthetic_fuzz_targets(self, endpoints: List[Dict], target: str) -> List[Dict]:
        """Generate synthetic fuzz targets by appending common params to clean paths."""
        parsed = urllib.parse.urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Collect unique clean paths from existing endpoints
        clean_paths = set()
        for ep in endpoints:
            ep_parsed = urllib.parse.urlparse(ep['url'])
            clean_paths.add(ep_parsed.path)

        # Also add the target path itself
        if parsed.path and parsed.path != '/':
            clean_paths.add(parsed.path)
        clean_paths.add('/')

        synthetic = []
        for path in list(clean_paths)[:20]:
            params = {p: 'test' for p in self.FUZZ_SYNTHETIC_PARAMS[:6]}
            synthetic.append({
                'url': f"{base}{path}",
                'params': params,
                'method': 'GET',
                'body': None,
            })

        return synthetic

    def _fuzz_json_body(self, scan_id: str, url: str, body_dict: Dict,
                        payload: str, method: str, auth_headers: Dict):
        """Fuzz JSON body keys by replacing each value with the payload."""
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc
        path = parsed.path or '/'

        for key in list(body_dict.keys())[:10]:
            fuzz_body = dict(body_dict)
            fuzz_body[key] = payload
            body_bytes = json.dumps(fuzz_body).encode('utf-8')

            request_lines = [
                f"{method} {path} HTTP/1.1",
                f"Host: {host}",
                "Content-Type: application/json",
                f"Content-Length: {len(body_bytes)}",
            ]
            for h_name, h_value in auth_headers.items():
                request_lines.append(f"{h_name}: {h_value}")
            request_lines.append('')
            request_lines.append(body_bytes.decode('utf-8'))

            raw_request = '\r\n'.join(request_lines)
            try:
                self._zap_api_call('JSON/core/action/sendRequest', {
                    'request': raw_request,
                    'followRedirects': 'true'
                })
            except Exception:
                pass

    def _verify_fuzz_reflections(self, scan_id: str, target: str,
                                 payloads_used: List[Tuple[str, str]]) -> List[VulnerabilityFinding]:
        """Bulk-verify reflections by fetching recent ZAP messages."""
        parsed_target = urllib.parse.urlparse(target)
        target_host = parsed_target.netloc
        findings = []

        try:
            messages = self._zap_api_call('JSON/core/view/messages', {
                'baseurl': target,
                'start': '0',
                'count': '500'
            })
            msg_list = messages.get('messages', [])
        except Exception as e:
            self._scan_log(scan_id, 'warning', f"Error fetching messages for reflection check: {e}")
            return findings

        # Build a set of payloads to search for
        payload_set = [(p, cat) for p, cat in payloads_used]
        seen_reflections = set()

        for msg in msg_list:
            resp_body = msg.get('responseBody', '')
            resp_header = msg.get('responseHeader', '')
            req_header = msg.get('requestHeader', '')
            if not resp_body or len(resp_body) < 10:
                continue

            content_type = ''
            for line in resp_header.split('\n'):
                if line.lower().startswith('content-type:'):
                    content_type = line.split(':', 1)[1].strip()
                    break

            # Extract request URL and method
            req_url = ''
            req_method = 'GET'
            if req_header:
                first_line = req_header.split('\n')[0]
                parts = first_line.split(' ')
                if len(parts) >= 2:
                    req_method = parts[0]
                    req_url = parts[1]

            for payload, category in payload_set:
                ctx = self._analyze_reflection_context(payload, resp_body, content_type)
                if not ctx:
                    continue

                # Dedup
                dedup_key = f"{req_url}:{payload[:30]}:{ctx['context']}"
                if dedup_key in seen_reflections:
                    continue
                seen_reflections.add(dedup_key)

                risk_map = {1: VulnSeverity.LOW, 2: VulnSeverity.MEDIUM, 3: VulnSeverity.HIGH}
                severity = risk_map.get(ctx['risk'], VulnSeverity.MEDIUM)

                finding = VulnerabilityFinding(
                    finding_id=f"{scan_id}-ragnar-fuzz-{len(findings):04d}",
                    scanner='ragnar-fuzz',
                    host=target_host,
                    port=parsed_target.port,
                    severity=severity,
                    title=f"Reflected Input - {ctx['context']}",
                    description=ctx['description'],
                    cwe_ids=[ctx['cwe_id']],
                    tags=['ragnar-fuzz', ctx['context'], category],
                    matched_at=req_url or target,
                    evidence=f"Payload: {payload[:100]} | Context: {ctx['context']}",
                    details={
                        'context': ctx['context'],
                        'payload': payload[:200],
                        'category': category,
                        'method': req_method,
                        'confidence': ctx['confidence'],
                    }
                )
                findings.append(finding)

                if len(findings) >= 100:
                    break
            if len(findings) >= 100:
                break

        return findings

    def _run_zap_parameter_fuzz_phase(self, scan_id: str, target: str,
                                      options: Dict, progress: ScanProgress):
        """Ragnar-Fuzz: fire-then-verify custom parameter fuzzing.

        1. Extract parameterized endpoints from ZAP message history
        2. Generate synthetic fuzz targets from clean paths
        3. Fire all payloads rapidly via accessUrl/sendRequest
        4. Bulk-fetch messages and verify reflections
        """
        profile = self._get_strength_profile(options)
        max_payloads = profile['payloads_per_param']

        if max_payloads <= 0:
            return

        auth_headers = self._build_fuzz_auth_headers(options)

        try:
            # 1. Extract endpoints from ZAP message history
            endpoints = self._extract_fuzz_endpoints(scan_id, target)
            self._scan_log(scan_id, 'info',
                           f"ragnar-fuzz: Found {len(endpoints)} parameterized endpoints")

            # 2. Generate synthetic targets
            synthetic = self._generate_synthetic_fuzz_targets(endpoints, target)
            all_targets = endpoints + synthetic
            self._scan_log(scan_id, 'info',
                           f"ragnar-fuzz: {len(all_targets)} total fuzz targets "
                           f"({len(synthetic)} synthetic)")

            # 3. Build flat payload list limited by max_payloads
            all_payloads = []
            for category, payloads in self.RAGNAR_FUZZ_PAYLOADS.items():
                all_payloads.extend([(p, category) for p in payloads])

            # Limit total payloads per parameter
            per_param_payloads = all_payloads[:max_payloads]

            # 4. Fire payloads
            fired_count = 0
            max_targets = min(len(all_targets), 30 if max_payloads <= 20 else 60)

            for i, endpoint in enumerate(all_targets[:max_targets]):
                url = endpoint.get('url', '')
                params = endpoint.get('params', {})
                method = endpoint.get('method', 'GET')
                body = endpoint.get('body')

                progress.current_check = (
                    f"ragnar-fuzz: Fuzzing endpoint {i + 1}/{max_targets}..."
                )
                progress.progress_percent = 70 + int((i / max(max_targets, 1)) * 10)

                # Fire payloads for GET query parameters
                if method == 'GET' and params:
                    for param_name in list(params.keys())[:5]:
                        for payload, category in per_param_payloads:
                            try:
                                fuzz_params = dict(params)
                                fuzz_params[param_name] = payload
                                fuzz_url = (url + '?' +
                                            urllib.parse.urlencode(fuzz_params, safe=''))
                                self._zap_api_call('JSON/core/action/accessUrl', {
                                    'url': fuzz_url,
                                    'followRedirects': 'false'
                                })
                                fired_count += 1
                            except Exception:
                                pass
                            if fired_count % 10 == 0:
                                time.sleep(0.05)

                # Fire payloads for JSON body
                if method in ('POST', 'PUT', 'PATCH') and body:
                    for payload, category in per_param_payloads[:max_payloads // 2]:
                        try:
                            self._fuzz_json_body(scan_id, url, body,
                                                 payload, method, auth_headers)
                            fired_count += 1
                        except Exception:
                            pass
                        if fired_count % 10 == 0:
                            time.sleep(0.05)

            self._scan_log(scan_id, 'info', f"ragnar-fuzz: Fired {fired_count} payloads")

            # 5. Bulk verify reflections
            progress.current_check = "ragnar-fuzz: Verifying reflections..."
            progress.progress_percent = 82
            reflection_findings = self._verify_fuzz_reflections(
                scan_id, target, per_param_payloads)

            self._scan_log(scan_id, 'info',
                           f"ragnar-fuzz: Found {len(reflection_findings)} reflected payloads")

            for finding in reflection_findings:
                self.scan_results[scan_id].append(finding)

        except Exception as e:
            self._scan_log(scan_id, 'warning',
                           f"ragnar-fuzz phase error (continuing): {e}")

    def _detect_json_reflections(self, scan_id: str, target: str,
                                 options: Dict, progress: ScanProgress):
        """Scan ZAP message history for reflected input in JSON responses."""
        parsed_target = urllib.parse.urlparse(target)
        target_host = parsed_target.netloc
        trivial_values = {
            'true', 'false', 'null', '', '0', '1', 'undefined',
            'none', 'get', 'post', 'ok', 'yes', 'no', 'error',
            'success', 'asc', 'desc',
        }

        try:
            messages = self._zap_api_call('JSON/core/view/messages', {
                'baseurl': target,
                'start': '0',
                'count': '500'
            })
            msg_list = messages.get('messages', [])
            reflection_count = 0
            seen_keys = set()

            for msg in msg_list:
                resp_header = msg.get('responseHeader', '')
                resp_body = msg.get('responseBody', '')
                req_header = msg.get('requestHeader', '')
                req_body = msg.get('requestBody', '')

                # Only check JSON responses
                if 'application/json' not in resp_header.lower():
                    continue
                if not resp_body or len(resp_body) < 10:
                    continue

                # Extract request URL
                req_url = ''
                req_method = 'GET'
                if req_header:
                    first_line = req_header.split('\n')[0]
                    parts = first_line.split(' ')
                    if len(parts) >= 2:
                        req_method = parts[0]
                        req_url = parts[1]

                # Extract parameter values to check for reflection
                values_to_check = {}  # value -> param_name

                # From query string
                if '?' in req_url:
                    query = req_url.split('?', 1)[1]
                    for k, v_list in urllib.parse.parse_qs(query).items():
                        for val in v_list:
                            if val.lower() not in trivial_values and len(val) > 2:
                                values_to_check[val] = k

                # From JSON request body
                if req_body:
                    try:
                        body_json = json.loads(req_body)
                        if isinstance(body_json, dict):
                            for k, v in body_json.items():
                                if (isinstance(v, str)
                                        and v.lower() not in trivial_values
                                        and len(v) > 2):
                                    values_to_check[v] = k
                    except (json.JSONDecodeError, ValueError):
                        pass

                # Check reflections
                for val, param_name in values_to_check.items():
                    if val not in resp_body:
                        continue

                    # Dedup by path + param
                    parsed_req = urllib.parse.urlparse(req_url)
                    dedup_key = f"{parsed_req.path}||{param_name}"
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)

                    reflection_count += 1
                    finding = VulnerabilityFinding(
                        finding_id=f"{scan_id}-ragnar-jsonreflect-{reflection_count:04d}",
                        scanner='ragnar-fuzz',
                        host=target_host,
                        port=parsed_target.port,
                        severity=VulnSeverity.LOW,
                        title='Reflected Input in JSON API Response',
                        description=(
                            f"Parameter '{param_name}' value '{val[:50]}' is reflected "
                            f"in the JSON response. This may indicate insufficient "
                            f"output encoding in the API."
                        ),
                        cwe_ids=['CWE-116'],
                        tags=['ragnar-fuzz', 'json-reflection', 'api'],
                        matched_at=req_url or target,
                        evidence=f"Reflected value: {val[:100]}",
                        details={
                            'reflected_value': val[:200],
                            'param_name': param_name,
                            'method': req_method,
                            'response_content_type': 'application/json',
                        }
                    )
                    self.scan_results[scan_id].append(finding)

                    if reflection_count >= 50:
                        break
                if reflection_count >= 50:
                    break

            progress.progress_percent = 92
            self._scan_log(scan_id, 'info',
                           f"JSON reflection scan: checked {len(msg_list)} messages, "
                           f"found {reflection_count} reflections")

        except Exception as e:
            self._scan_log(scan_id, 'warning',
                           f"JSON reflection detection error: {e}")

    def _run_zap_active_scan_phase(self, scan_id: str, target: str, options: Dict,
                                   progress: ScanProgress, policy_name: str = None):
        """Active scan phase of full scan"""
        ascan_params = {
            'url': target,
            'recurse': 'true',
            'inScopeOnly': 'true'
        }
        # Pass context ID if auth is configured
        context_id = options.get('_context_id')
        if context_id:
            ascan_params['contextId'] = context_id
        elif options.get('_has_auth'):
            # Auth is configured but no context ID - try to get it
            context_id = self._get_zap_context_id('default')
            if context_id:
                ascan_params['contextId'] = context_id
        # Use custom scan policy if provided (thorough/insane)
        if policy_name:
            ascan_params['scanPolicyName'] = policy_name
        scan_resp = self._zap_api_call('JSON/ascan/action/scan', ascan_params)
        ascan_id = scan_resp.get('scan')

        if not ascan_id:
            self._scan_log(scan_id, 'warning', "Failed to start active scan phase, continuing to alert fetch...")
            return

        self._scan_log(scan_id, 'info', f"Active scan started with ID: {ascan_id}")

        # Active scan with timeout and stall detection
        profile = self._get_strength_profile(options)
        scan_start = time.time()
        scan_timeout = profile['active_scan_timeout']
        last_progress = -1
        stall_count = 0

        while time.time() - scan_start < scan_timeout:
            try:
                status_resp = self._zap_api_call('JSON/ascan/view/status', {'scanId': ascan_id})
                scan_progress = int(status_resp.get('status', 0))
                # Scale progress: 35-70% if fuzzer enabled, 50-100% if standard
                if profile['enable_fuzzer']:
                    progress.progress_percent = 35 + int(scan_progress * 0.35)  # 35-70%
                else:
                    progress.progress_percent = 50 + int(scan_progress * 0.5)  # 50-100%
                total_phases = 5 if profile['enable_fuzzer'] else 3
                progress.current_check = f"Phase 3/{total_phases}: Active scanning... {scan_progress}%"

                # Update findings count filtered by target host
                try:
                    alerts_resp = self._zap_api_call('JSON/core/view/numberOfAlerts', {'baseurl': target})
                    progress.findings_count = int(alerts_resp.get('numberOfAlerts', 0))
                except Exception:
                    pass

                if scan_progress >= 100:
                    break

                # Check for stalled scan (some vuln checks like timing-based SQLi take time)
                if scan_progress == last_progress:
                    stall_count += 1
                    if stall_count >= profile['stall_threshold']:
                        self._scan_log(scan_id, 'warning', f"Active scan phase stalled at {scan_progress}% for 2 minutes, stopping...")
                        break
                else:
                    stall_count = 0
                    last_progress = scan_progress

            except Exception as e:
                self._scan_log(scan_id, 'warning', f"Active scan status error: {e}")
                break

            time.sleep(5)

        if time.time() - scan_start >= scan_timeout:
            self._scan_log(scan_id, 'warning', "Active scan phase timed out")

    def _fetch_zap_alerts(self, scan_id: str, target: str):
        """Fetch all ZAP alerts and convert to VulnerabilityFinding.

        If ZAP is down when we try to fetch, restart it and retry up to 3 times.
        This prevents losing scan results when ZAP crashes between scan completion
        and alert retrieval.
        """
        MAX_RETRIES = 3
        last_err = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self._fetch_zap_alerts_inner(scan_id, target)
                return  # Success
            except Exception as e:
                last_err = e
                self._scan_log(scan_id, 'warning',
                               f"Alert fetch attempt {attempt}/{MAX_RETRIES} failed: {e}")
                if attempt < MAX_RETRIES:
                    # Try to restart ZAP if it's down
                    if not self._is_zap_running():
                        self._scan_log(scan_id, 'info',
                                       "ZAP not responding — restarting before retry...")
                        self.start_zap_daemon()
                        time.sleep(5)  # Give ZAP time to load session
                    else:
                        time.sleep(2)
        # All retries exhausted
        raise RuntimeError(f"Failed to fetch ZAP alerts after {MAX_RETRIES} attempts: {last_err}") from last_err

    def _fetch_zap_alerts_inner(self, scan_id: str, target: str):
        """Inner alert fetch — called with retry wrapper."""
        try:
            # Parse target to get host for flexible matching
            parsed_target = urllib.parse.urlparse(target)
            target_host = parsed_target.netloc or target
            target_host_no_port = parsed_target.hostname or ''
            target_no_slash = target.rstrip('/')

            # Always fetch ALL alerts - ZAP's baseurl filtering is unreliable
            self._scan_log(scan_id, 'info', f"Fetching all ZAP alerts (target: {target}, host: {target_host})")
            alerts_resp = self._zap_api_call('JSON/core/view/alerts', {
                'start': '0',
                'count': '5000'
            })
            all_alerts = alerts_resp.get('alerts', [])
            self._scan_log(scan_id, 'info', f"Total alerts in ZAP: {len(all_alerts)}")

            # Filter alerts matching this target by host
            alerts = []
            for alert in all_alerts:
                alert_url = alert.get('url', '')
                if not alert_url:
                    continue
                parsed_alert = urllib.parse.urlparse(alert_url)
                alert_host = parsed_alert.netloc or ''
                alert_host_no_port = parsed_alert.hostname or ''

                # Match by: full netloc (host:port), hostname only, or URL prefix
                if (target_host == alert_host or
                        target_host_no_port == alert_host_no_port or
                        alert_url.startswith(target_no_slash)):
                    alerts.append(alert)

            if all_alerts and not alerts:
                sample_urls = [a.get('url', 'N/A') for a in all_alerts[:5]]
                self._scan_log(scan_id, 'warning', f"Found {len(all_alerts)} total alerts but none matched host '{target_host}'. Sample URLs: {sample_urls}")

            self._scan_log(scan_id, 'info', f"Matched {len(alerts)} of {len(all_alerts)} alerts for {target}")

            for alert in alerts:
                finding = self._parse_zap_alert(alert, scan_id)
                if finding:
                    self.scan_results[scan_id].append(finding)

        except Exception as e:
            self._scan_log(scan_id, 'error', f"Error fetching ZAP alerts: {e}")
            # Propagate the error so callers know alert fetching failed
            raise RuntimeError(f"Failed to fetch ZAP alerts: {e}") from e

    def _parse_zap_alert(self, alert: Dict, scan_id: str) -> Optional[VulnerabilityFinding]:
        """Parse a ZAP alert into VulnerabilityFinding"""
        try:
            # ZAP returns risk/confidence as int (0-3) or string ("Medium")
            raw_risk = alert.get('risk', 0)
            if isinstance(raw_risk, str) and not raw_risk.isdigit():
                severity = self.ZAP_RISK_NAME_MAP.get(raw_risk.lower(), VulnSeverity.INFO)
            else:
                severity = self.ZAP_RISK_MAP.get(int(raw_risk), VulnSeverity.INFO)

            raw_conf = alert.get('confidence', 0)
            if isinstance(raw_conf, str) and not raw_conf.isdigit():
                confidence_str = self.ZAP_CONFIDENCE_NAME_MAP.get(raw_conf.lower(), 'Unknown')
            else:
                confidence_str = self.ZAP_CONFIDENCE_MAP.get(int(raw_conf), 'Unknown')

            # Extract CWE ID if present
            cwe_ids = []
            cwe_id = alert.get('cweid', '')
            if cwe_id and cwe_id != '-1':
                cwe_ids.append(f"CWE-{cwe_id}")

            # Extract WASC ID
            wasc_id = alert.get('wascid', '')

            # Build references
            references = []
            if alert.get('reference'):
                refs = alert['reference'].split('\n')
                references.extend([r.strip() for r in refs if r.strip()])

            # Parse URL for host/port
            url = alert.get('url', '')
            host = url
            port = None
            try:
                parsed = urllib.parse.urlparse(url)
                host = parsed.netloc
                if parsed.port:
                    port = parsed.port
            except Exception:
                pass

            finding = VulnerabilityFinding(
                finding_id=f"{scan_id}-zap-{alert.get('alertRef', 'unknown')}-{len(self.scan_results.get(scan_id, []))+1:04d}",
                scanner='zap',
                host=host,
                port=port,
                severity=severity,
                title=alert.get('name', 'Unknown ZAP Alert'),
                description=alert.get('description', ''),
                cwe_ids=cwe_ids,
                evidence=alert.get('evidence', '')[:1000],
                remediation=alert.get('solution', ''),
                references=references[:10],
                tags=['zap', 'web', f'confidence-{confidence_str.lower()}'],
                matched_at=url,
                raw_output=json.dumps(alert)[:2000],
                details={
                    'method': alert.get('method', ''),
                    'parameter': alert.get('param', ''),
                    'attack': alert.get('attack', ''),
                    'wasc_id': wasc_id,
                    'confidence': confidence_str,
                    'plugin_id': alert.get('pluginId', ''),
                    'alert_ref': alert.get('alertRef', ''),
                }
            )

            return finding

        except Exception as e:
            logger.warning(f"Error parsing ZAP alert: {e}")
            return None

    def zap_set_authentication(self, context_name: str, auth_type: str, auth_params: Dict) -> tuple:
        """
        Configure authentication for ZAP context.

        auth_type: 'form', 'http_basic', 'json'
        auth_params for 'form':
            - login_url: URL of login form
            - login_request_data: POST data (e.g., "username={%username%}&password={%password%}")
            - username_field: Name of username parameter
            - password_field: Name of password parameter
            - username: Actual username
            - password: Actual password

        Returns: (success: bool, error_message: str or None)
        """
        # Check if ZAP is running first
        if not self._is_zap_running():
            return (False, "ZAP daemon is not running. Please start ZAP first.")

        try:
            # First, ensure we have a context - create one if needed
            context_id = None
            try:
                # Try to get existing context
                contexts_resp = self._zap_api_call('JSON/context/view/contextList', {})
                contexts = contexts_resp.get('contextList', [])

                if context_name in contexts:
                    # Get context ID
                    context_resp = self._zap_api_call('JSON/context/view/context', {'contextName': context_name})
                    context_id = context_resp.get('context', {}).get('id', '1')
                else:
                    # Create new context
                    new_ctx_resp = self._zap_api_call('JSON/context/action/newContext', {'contextName': context_name})
                    context_id = new_ctx_resp.get('contextId', '1')
                    logger.info(f"Created new ZAP context: {context_name} (ID: {context_id})")
            except Exception as ctx_err:
                logger.warning(f"Could not manage context, using default: {ctx_err}")
                context_id = '1'

            if auth_type == 'form':
                # Validate required parameters
                login_url = auth_params.get('login_url', '').strip()
                username = auth_params.get('username', '').strip()
                password = auth_params.get('password', '')

                if not login_url:
                    return (False, "Login URL is required for form-based authentication")
                if not username:
                    return (False, "Username is required for form-based authentication")
                if not password:
                    return (False, "Password is required for form-based authentication")

                # Include the login URL's host in the context
                try:
                    parsed_url = urllib.parse.urlparse(login_url)
                    include_regex = f"{parsed_url.scheme}://{parsed_url.netloc}.*"
                    self._zap_api_call('JSON/context/action/includeInContext', {
                        'contextName': context_name,
                        'regex': include_regex
                    })
                    logger.info(f"Added {include_regex} to context {context_name}")
                except Exception as e:
                    logger.warning(f"Could not add URL to context: {e}")

                # Build login request data if not provided
                login_request_data = auth_params.get('login_request_data', '').strip()
                if not login_request_data:
                    username_field = auth_params.get('username_field', 'username')
                    password_field = auth_params.get('password_field', 'password')
                    login_request_data = f"{username_field}={{%username%}}&{password_field}={{%password%}}"

                # Set form-based authentication
                try:
                    self._zap_api_call('JSON/authentication/action/setAuthenticationMethod', {
                        'contextId': context_id,
                        'authMethodName': 'formBasedAuthentication',
                        'authMethodConfigParams': urllib.parse.urlencode({
                            'loginUrl': login_url,
                            'loginRequestData': login_request_data,
                        })
                    })
                except Exception as e:
                    return (False, f"Failed to set authentication method: {str(e)}")

                # Create and configure user
                try:
                    user_resp = self._zap_api_call('JSON/users/action/newUser', {
                        'contextId': context_id,
                        'name': 'test_user'
                    })
                    user_id = user_resp.get('userId')
                except Exception as e:
                    return (False, f"Failed to create user in ZAP: {str(e)}")

                if not user_id:
                    return (False, "Failed to create user - no user ID returned from ZAP")

                # Set user credentials
                try:
                    self._zap_api_call('JSON/users/action/setAuthenticationCredentials', {
                        'contextId': context_id,
                        'userId': user_id,
                        'authCredentialsConfigParams': urllib.parse.urlencode({
                            'username': username,
                            'password': password,
                        })
                    })
                except Exception as e:
                    return (False, f"Failed to set user credentials: {str(e)}")

                # Enable user
                try:
                    self._zap_api_call('JSON/users/action/setUserEnabled', {
                        'contextId': context_id,
                        'userId': user_id,
                        'enabled': 'true'
                    })
                except Exception as e:
                    return (False, f"Failed to enable user: {str(e)}")

                logger.info(f"ZAP form authentication configured for context {context_name}")
                return (True, None)

            elif auth_type == 'http_basic':
                # Validate required parameters
                hostname = auth_params.get('hostname', '').strip()
                if not hostname:
                    return (False, "Hostname is required for HTTP Basic authentication")

                # HTTP Basic authentication
                try:
                    self._zap_api_call('JSON/authentication/action/setAuthenticationMethod', {
                        'contextId': context_id,
                        'authMethodName': 'httpAuthentication',
                        'authMethodConfigParams': urllib.parse.urlencode({
                            'hostname': hostname,
                            'realm': auth_params.get('realm', ''),
                        })
                    })
                except Exception as e:
                    return (False, f"Failed to set HTTP Basic authentication: {str(e)}")

                logger.info("ZAP HTTP Basic authentication configured")
                return (True, None)

            elif auth_type == 'oauth2_bba':
                # OAuth2 / Microsoft Login using Browser-Based Authentication (BBA)
                # ZAP's BBA mode drives a real browser to handle complex OAuth flows
                # including Microsoft Online login sequences with multiple screens

                login_url = auth_params.get('login_url', '').strip()
                username = auth_params.get('username', '').strip()
                password = auth_params.get('password', '')
                wait_for_url = auth_params.get('wait_for_url', '').strip()  # URL pattern indicating successful login
                login_page_wait = auth_params.get('login_page_wait', 5)  # Seconds to wait for login page

                if not login_url:
                    return (False, "Login URL is required for OAuth2/BBA authentication")
                if not username:
                    return (False, "Username is required for OAuth2/BBA authentication")
                if not password:
                    return (False, "Password is required for OAuth2/BBA authentication")

                # Include the target URL's host in the context
                try:
                    parsed_url = urllib.parse.urlparse(login_url)
                    include_regex = f"{parsed_url.scheme}://{parsed_url.netloc}.*"
                    self._zap_api_call('JSON/context/action/includeInContext', {
                        'contextName': context_name,
                        'regex': include_regex
                    })
                    logger.info(f"Added {include_regex} to context {context_name}")

                    # Also include Microsoft login domains if this appears to be MS OAuth
                    if 'microsoft' in login_url.lower() or 'login.live' in login_url.lower() or 'microsoftonline' in login_url.lower():
                        ms_domains = [
                            'https://login.microsoftonline.com/.*',
                            'https://login.live.com/.*',
                            'https://login.microsoft.com/.*'
                        ]
                        for ms_domain in ms_domains:
                            try:
                                self._zap_api_call('JSON/context/action/includeInContext', {
                                    'contextName': context_name,
                                    'regex': ms_domain
                                })
                            except:
                                pass  # Best effort to add MS domains
                except Exception as e:
                    logger.warning(f"Could not add URL to context: {e}")

                # Configure Browser-Based Authentication
                try:
                    # Set authentication method to browser-based
                    bba_config = {
                        'loginPageUrl': login_url,
                        'loginPageWait': str(login_page_wait),
                    }

                    # Add wait_for_url if specified (helps ZAP know when login is complete)
                    if wait_for_url:
                        bba_config['waitForUrl'] = wait_for_url

                    self._zap_api_call('JSON/authentication/action/setAuthenticationMethod', {
                        'contextId': context_id,
                        'authMethodName': 'browserBasedAuthentication',
                        'authMethodConfigParams': urllib.parse.urlencode(bba_config)
                    })
                    logger.info(f"Set browser-based authentication for context {context_id}")
                except Exception as e:
                    return (False, f"Failed to set BBA method: {str(e)}")

                # Create user for BBA
                try:
                    user_resp = self._zap_api_call('JSON/users/action/newUser', {
                        'contextId': context_id,
                        'name': 'oauth_user'
                    })
                    user_id = user_resp.get('userId')
                except Exception as e:
                    return (False, f"Failed to create user for BBA: {str(e)}")

                if not user_id:
                    return (False, "Failed to create user - no user ID returned from ZAP")

                # Set user credentials for BBA
                try:
                    self._zap_api_call('JSON/users/action/setAuthenticationCredentials', {
                        'contextId': context_id,
                        'userId': user_id,
                        'authCredentialsConfigParams': urllib.parse.urlencode({
                            'username': username,
                            'password': password,
                        })
                    })
                except Exception as e:
                    return (False, f"Failed to set BBA credentials: {str(e)}")

                # Enable user
                try:
                    self._zap_api_call('JSON/users/action/setUserEnabled', {
                        'contextId': context_id,
                        'userId': user_id,
                        'enabled': 'true'
                    })
                except Exception as e:
                    return (False, f"Failed to enable BBA user: {str(e)}")

                logger.info(f"ZAP OAuth2/BBA authentication configured for context {context_name}")
                return (True, None)

            elif auth_type == 'script_auth':
                # Script-Based Authentication for custom/complex flows
                # This allows users to provide a custom authentication script

                script_name = auth_params.get('script_name', '').strip()
                login_url = auth_params.get('login_url', '').strip()
                username = auth_params.get('username', '').strip()
                password = auth_params.get('password', '')

                if not login_url:
                    return (False, "Login URL is required for script-based authentication")
                if not username:
                    return (False, "Username is required for script-based authentication")
                if not password:
                    return (False, "Password is required for script-based authentication")

                # Include the target URL's host in the context
                try:
                    parsed_url = urllib.parse.urlparse(login_url)
                    include_regex = f"{parsed_url.scheme}://{parsed_url.netloc}.*"
                    self._zap_api_call('JSON/context/action/includeInContext', {
                        'contextName': context_name,
                        'regex': include_regex
                    })
                except Exception as e:
                    logger.warning(f"Could not add URL to context: {e}")

                # If a script name is provided, use script-based auth
                # Otherwise fall back to form-based as a starting point
                if script_name:
                    try:
                        self._zap_api_call('JSON/authentication/action/setAuthenticationMethod', {
                            'contextId': context_id,
                            'authMethodName': 'scriptBasedAuthentication',
                            'authMethodConfigParams': urllib.parse.urlencode({
                                'scriptName': script_name,
                                'loginUrl': login_url,
                            })
                        })
                    except Exception as e:
                        return (False, f"Failed to set script-based authentication: {str(e)}")
                else:
                    # Use Client-Script Authentication (CSA) which is similar to BBA
                    # but allows more control via JavaScript
                    try:
                        self._zap_api_call('JSON/authentication/action/setAuthenticationMethod', {
                            'contextId': context_id,
                            'authMethodName': 'browserBasedAuthentication',
                            'authMethodConfigParams': urllib.parse.urlencode({
                                'loginPageUrl': login_url,
                                'loginPageWait': '10',  # Longer wait for complex flows
                            })
                        })
                    except Exception as e:
                        return (False, f"Failed to set CSA method: {str(e)}")

                # Create and configure user
                try:
                    user_resp = self._zap_api_call('JSON/users/action/newUser', {
                        'contextId': context_id,
                        'name': 'script_user'
                    })
                    user_id = user_resp.get('userId')
                except Exception as e:
                    return (False, f"Failed to create user for script auth: {str(e)}")

                if not user_id:
                    return (False, "Failed to create user - no user ID returned")

                # Set credentials
                try:
                    self._zap_api_call('JSON/users/action/setAuthenticationCredentials', {
                        'contextId': context_id,
                        'userId': user_id,
                        'authCredentialsConfigParams': urllib.parse.urlencode({
                            'username': username,
                            'password': password,
                        })
                    })
                except Exception as e:
                    return (False, f"Failed to set script auth credentials: {str(e)}")

                # Enable user
                try:
                    self._zap_api_call('JSON/users/action/setUserEnabled', {
                        'contextId': context_id,
                        'userId': user_id,
                        'enabled': 'true'
                    })
                except Exception as e:
                    return (False, f"Failed to enable script auth user: {str(e)}")

                logger.info(f"ZAP script-based authentication configured for context {context_name}")
                return (True, None)

            elif auth_type == 'bearer_token':
                # Bearer token auth - use ZAP's Replacer to add Authorization header
                bearer_token = auth_params.get('bearer_token', '').strip()
                if not bearer_token:
                    return (False, "Bearer token is required")

                try:
                    # Remove any existing Authorization replacer rule
                    try:
                        self._zap_api_call('JSON/replacer/action/removeRule', {
                            'description': 'Auth-BearerToken'
                        })
                    except Exception:
                        pass  # Rule may not exist yet

                    self._zap_api_call('JSON/replacer/action/addRule', {
                        'description': 'Auth-BearerToken',
                        'enabled': 'true',
                        'matchType': 'REQ_HEADER',
                        'matchRegex': 'false',
                        'matchString': 'Authorization',
                        'replacement': f'Bearer {bearer_token}',
                        'initiators': ''
                    })
                    logger.info("ZAP bearer token authentication configured via Replacer")
                    return (True, None)
                except Exception as e:
                    return (False, f"Failed to set bearer token: {str(e)}")

            elif auth_type == 'api_key':
                # API Key auth - use ZAP's Replacer to add custom header
                api_key = auth_params.get('api_key', '').strip()
                header_name = auth_params.get('api_key_header', 'X-API-Key').strip()
                if not api_key:
                    return (False, "API key is required")

                try:
                    try:
                        self._zap_api_call('JSON/replacer/action/removeRule', {
                            'description': 'Auth-APIKey'
                        })
                    except Exception:
                        pass

                    self._zap_api_call('JSON/replacer/action/addRule', {
                        'description': 'Auth-APIKey',
                        'enabled': 'true',
                        'matchType': 'REQ_HEADER',
                        'matchRegex': 'false',
                        'matchString': header_name,
                        'replacement': api_key,
                        'initiators': ''
                    })
                    logger.info(f"ZAP API key authentication configured via Replacer ({header_name})")
                    return (True, None)
                except Exception as e:
                    return (False, f"Failed to set API key: {str(e)}")

            elif auth_type == 'cookie':
                # Cookie auth - use ZAP's Replacer to add Cookie header
                cookie_value = auth_params.get('cookie_value', '').strip()
                if not cookie_value:
                    return (False, "Cookie value is required")

                try:
                    try:
                        self._zap_api_call('JSON/replacer/action/removeRule', {
                            'description': 'Auth-Cookie'
                        })
                    except Exception:
                        pass

                    self._zap_api_call('JSON/replacer/action/addRule', {
                        'description': 'Auth-Cookie',
                        'enabled': 'true',
                        'matchType': 'REQ_HEADER',
                        'matchRegex': 'false',
                        'matchString': 'Cookie',
                        'replacement': cookie_value,
                        'initiators': ''
                    })
                    logger.info("ZAP cookie authentication configured via Replacer")
                    return (True, None)
                except Exception as e:
                    return (False, f"Failed to set cookie auth: {str(e)}")

            else:
                return (False, f"Unsupported authentication type: '{auth_type}'. Supported types: 'form', 'http_basic', 'oauth2_bba', 'oauth2_client_creds', 'script_auth', 'bearer_token', 'api_key', 'cookie'")

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error configuring ZAP authentication: {error_msg}")
            return (False, f"Unexpected error: {error_msg}")

    def zap_import_openapi(self, spec_url: str, target_url: str = None) -> bool:
        """Import OpenAPI/Swagger specification for API scanning"""
        try:
            params = {'url': spec_url}
            if target_url:
                # hostOverride must be scheme+host+port only — never include a
                # path, otherwise ZAP prepends it to every spec path (e.g.
                # /api + /api/public → /api/api/public).
                parsed = urllib.parse.urlparse(target_url)
                params['hostOverride'] = f"{parsed.scheme}://{parsed.netloc}"

            self._zap_api_call('JSON/openapi/action/importUrl', params)
            logger.info(f"Imported OpenAPI spec from {spec_url}")
            return True

        except Exception as e:
            logger.error(f"Error importing OpenAPI spec: {e}")
            return False

    def zap_diagnose_target(self, target: str) -> Dict[str, Any]:
        """
        Diagnose potential issues with a target URL before scanning.

        Returns a dict with:
        - valid: bool - whether target appears valid for scanning
        - errors: list - list of issues found
        - warnings: list - list of potential issues
        - recommendations: list - suggestions for fixing issues
        """
        result = {
            'valid': True,
            'target': target,
            'errors': [],
            'warnings': [],
            'recommendations': []
        }

        # Check URL format
        if not target:
            result['valid'] = False
            result['errors'].append("Target URL is empty")
            result['recommendations'].append("Provide a valid URL starting with http:// or https://")
            return result

        if not target.startswith(('http://', 'https://')):
            result['valid'] = False
            result['errors'].append(f"Invalid URL scheme: {target[:30]}")
            result['recommendations'].append("URL must start with http:// or https://")
            return result

        # Parse URL
        try:
            parsed = urllib.parse.urlparse(target)
            if not parsed.netloc:
                result['valid'] = False
                result['errors'].append("URL has no host/domain")
                result['recommendations'].append("Check URL format - should be http://hostname:port/path")
                return result

            result['host'] = parsed.netloc
            result['scheme'] = parsed.scheme

        except Exception as e:
            result['valid'] = False
            result['errors'].append(f"URL parsing error: {e}")
            return result

        # Test DNS resolution
        host = parsed.netloc.split(':')[0]
        try:
            ip_addr = socket.gethostbyname(host)
            result['resolved_ip'] = ip_addr
        except socket.gaierror as e:
            result['valid'] = False
            result['errors'].append(f"Cannot resolve hostname '{host}': {e}")
            result['recommendations'].append("Check that the hostname is correct and DNS is working")
            return result

        # Test TCP connectivity
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            conn_result = sock.connect_ex((host, port))
            sock.close()

            if conn_result != 0:
                result['valid'] = False
                result['errors'].append(f"Cannot connect to {host}:{port} (error code: {conn_result})")
                result['recommendations'].append(
                    f"Target may be down, firewalled, or not listening on port {port}. "
                    "Check if the target is accessible from this machine."
                )
                return result

            result['port'] = port
            result['connectivity'] = 'ok'

        except socket.timeout:
            result['valid'] = False
            result['errors'].append(f"Connection to {host}:{port} timed out")
            result['recommendations'].append("Target may be slow, overloaded, or blocking connections")
            return result
        except Exception as e:
            result['warnings'].append(f"Connectivity check error (non-fatal): {e}")

        # Test HTTP accessibility (quick check)
        try:
            req = urllib.request.Request(target, method='HEAD')
            req.add_header('User-Agent', 'Mozilla/5.0 (compatible; OWASP ZAP; Security Scanner)')
            with urllib.request.urlopen(req, timeout=10) as response:
                result['http_status'] = response.status
                if response.status >= 400:
                    result['warnings'].append(f"Target returned HTTP {response.status}")
                    if response.status == 401:
                        result['recommendations'].append("Target requires authentication - configure ZAP auth if needed")
                    elif response.status == 403:
                        result['recommendations'].append("Target is returning 403 Forbidden - may block scanners")
                    elif response.status == 404:
                        result['warnings'].append("Target URL returned 404 - check if path is correct")
        except urllib.error.HTTPError as e:
            result['http_status'] = e.code
            if e.code == 401:
                result['warnings'].append("Target requires authentication (401)")
                result['recommendations'].append("Configure ZAP authentication if scanning authenticated areas")
            elif e.code == 403:
                result['warnings'].append("Target returned 403 Forbidden - may block scanning")
            elif e.code == 404:
                result['warnings'].append("Target path not found (404) - check URL path")
            elif e.code >= 500:
                result['warnings'].append(f"Target is returning server errors ({e.code})")
        except urllib.error.URLError as e:
            if 'ssl' in str(e.reason).lower() or 'certificate' in str(e.reason).lower():
                result['warnings'].append(f"SSL/TLS issue: {e.reason}")
                result['recommendations'].append("Target may have certificate issues - ZAP should still work but may need config")
            else:
                result['warnings'].append(f"HTTP request failed: {e.reason}")
        except Exception as e:
            result['warnings'].append(f"HTTP check error: {e}")

        # Check ZAP state if running
        if self._is_zap_running():
            try:
                auth_status = self.zap_get_auth_status()
                if auth_status.get('has_auth'):
                    result['zap_auth_configured'] = True
                    result['warnings'].append(
                        f"ZAP has authentication configured ({auth_status.get('auth_type')}). "
                        "If target doesn't need auth, this may cause issues."
                    )
                    result['recommendations'].append(
                        "If scanning without auth, clear ZAP auth settings first using 'Clear Auth'"
                    )
            except Exception:
                pass

        return result

    def zap_clear_session(self) -> bool:
        """Clear ZAP session data"""
        try:
            self._zap_api_call('JSON/core/action/newSession', {'overwrite': 'true'})
            logger.info("ZAP session cleared")
            return True
        except Exception as e:
            logger.error(f"Error clearing ZAP session: {e}")
            return False

    def zap_get_auth_status(self) -> Dict:
        """Get current ZAP authentication configuration status"""
        auth_status = {
            'has_auth': False,
            'contexts': [],
            'auth_type': None,
            'details': None
        }

        if not self._is_zap_running():
            auth_status['error'] = 'ZAP is not running'
            return auth_status

        try:
            # Get list of contexts
            contexts_resp = self._zap_api_call('JSON/context/view/contextList', {})
            context_list = contexts_resp.get('contextList', [])

            if isinstance(context_list, str):
                # Sometimes ZAP returns a comma-separated string
                context_list = [c.strip() for c in context_list.split(',') if c.strip()]

            for context_name in context_list:
                if not context_name:
                    continue

                try:
                    # Get context details
                    ctx_resp = self._zap_api_call('JSON/context/view/context', {'contextName': context_name})
                    context_info = ctx_resp.get('context', {})
                    context_id = context_info.get('id', '1')

                    # Check authentication method for this context
                    auth_resp = self._zap_api_call('JSON/authentication/view/getAuthenticationMethod', {'contextId': context_id})
                    auth_method = auth_resp.get('method', {})
                    method_name = auth_method.get('methodName', 'none')

                    context_auth = {
                        'name': context_name,
                        'id': context_id,
                        'auth_method': method_name,
                        'in_scope': context_info.get('inScope', [])
                    }

                    # Check if there are users configured
                    try:
                        users_resp = self._zap_api_call('JSON/users/view/usersList', {'contextId': context_id})
                        users = users_resp.get('usersList', [])
                        context_auth['users_configured'] = len(users) > 0
                        context_auth['user_count'] = len(users)
                    except:
                        context_auth['users_configured'] = False
                        context_auth['user_count'] = 0

                    auth_status['contexts'].append(context_auth)

                    # If this context has authentication configured, mark it
                    # ZAP uses various names for "no auth": none, manual, manualAuthentication, etc.
                    no_auth_methods = ['none', 'manual', 'manualauthentication', '']
                    if method_name and method_name.lower() not in no_auth_methods:
                        auth_status['has_auth'] = True
                        auth_status['auth_type'] = method_name
                        auth_status['details'] = f"Context '{context_name}' has {method_name} authentication"

                except Exception as ctx_err:
                    logger.debug(f"Error checking context {context_name}: {ctx_err}")
                    continue

            # Also check for Replacer-based auth (bearer_token, api_key, cookie)
            if not auth_status['has_auth']:
                try:
                    rules_resp = self._zap_api_call('JSON/replacer/view/rules', {})
                    rules = rules_resp.get('rules', [])
                    auth_rules = [r for r in rules if isinstance(r, dict) and
                                  r.get('description', '').startswith('Auth-') and
                                  r.get('enabled') == 'true']
                    if auth_rules:
                        rule_desc = auth_rules[0].get('description', '')
                        auth_type_map = {
                            'Auth-BearerToken': 'bearer_token',
                            'Auth-APIKey': 'api_key',
                            'Auth-Cookie': 'cookie'
                        }
                        auth_status['has_auth'] = True
                        auth_status['auth_type'] = auth_type_map.get(rule_desc, 'header_replacement')
                        auth_status['details'] = f"Header-based auth via Replacer: {rule_desc}"
                except Exception:
                    pass  # Replacer add-on may not be available

            if not auth_status['has_auth']:
                auth_status['details'] = 'No authentication configured'

        except Exception as e:
            logger.error(f"Error getting ZAP auth status: {e}")
            auth_status['error'] = str(e)

        return auth_status

    def zap_clear_auth(self) -> tuple:
        """Clear all ZAP authentication configurations and contexts by starting a new session"""
        if not self._is_zap_running():
            return (False, "ZAP is not running")

        try:
            # The most reliable way to clear all auth is to start a new session
            # This wipes everything: contexts, auth, users, scan history
            logger.info("Clearing ZAP session to reset all authentication...")

            try:
                self._zap_api_call('JSON/core/action/newSession', {'overwrite': 'true'})
                logger.info("ZAP session cleared - all authentication reset")
                return (True, "ZAP session cleared. All authentication configurations have been reset.")
            except Exception as session_err:
                logger.warning(f"Could not create new session: {session_err}, trying manual cleanup...")

            # Fallback: manually remove contexts and reset auth
            cleared_contexts = []
            errors = []

            # Get list of contexts
            contexts_resp = self._zap_api_call('JSON/context/view/contextList', {})
            context_list = contexts_resp.get('contextList', [])

            if isinstance(context_list, str):
                context_list = [c.strip() for c in context_list.split(',') if c.strip()]

            for context_name in context_list:
                if not context_name:
                    continue

                try:
                    # Get context ID first
                    ctx_resp = self._zap_api_call('JSON/context/view/context', {'contextName': context_name})
                    context_id = ctx_resp.get('context', {}).get('id', '1')

                    # Remove all users from this context
                    try:
                        users_resp = self._zap_api_call('JSON/users/view/usersList', {'contextId': context_id})
                        users = users_resp.get('usersList', [])
                        for user in users:
                            user_id = user.get('id') if isinstance(user, dict) else user
                            if user_id:
                                self._zap_api_call('JSON/users/action/removeUser', {
                                    'contextId': context_id,
                                    'userId': str(user_id)
                                })
                    except Exception as user_err:
                        logger.debug(f"Could not remove users from {context_name}: {user_err}")

                    # Reset authentication method to manual (no auth)
                    try:
                        self._zap_api_call('JSON/authentication/action/setAuthenticationMethod', {
                            'contextId': context_id,
                            'authMethodName': 'manualAuthentication'
                        })
                        logger.info(f"Reset auth on context {context_name}")
                    except Exception as auth_err:
                        logger.debug(f"Could not reset auth on {context_name}: {auth_err}")

                    # Remove non-default contexts entirely
                    if context_name != 'Default Context':
                        self._zap_api_call('JSON/context/action/removeContext', {'contextName': context_name})
                        cleared_contexts.append(context_name)
                        logger.info(f"Removed ZAP context: {context_name}")

                except Exception as e:
                    errors.append(f"Failed to clear {context_name}: {e}")

            # Also clear any Replacer-based auth rules (bearer, api_key, cookie)
            for rule_name in ['Auth-BearerToken', 'Auth-APIKey', 'Auth-Cookie']:
                try:
                    self._zap_api_call('JSON/replacer/action/removeRule', {
                        'description': rule_name
                    })
                except Exception:
                    pass  # Rule may not exist

            if cleared_contexts:
                msg = f"Cleared {len(cleared_contexts)} context(s) and reset authentication: {', '.join(cleared_contexts)}"
            else:
                msg = "Reset authentication on all contexts"

            if errors:
                msg += f". Some errors: {'; '.join(errors[:3])}"

            logger.info(msg)
            return (True, msg)

        except Exception as e:
            error_msg = f"Error clearing ZAP authentication: {e}"
            logger.error(error_msg)
            return (False, error_msg)

    # =========================================================================
    # End ZAP Integration
    # =========================================================================

    def _run_full_scan(self, scan_id: str, target: str, options: Dict):
        """Run all available scanners in parallel"""
        progress = self.active_scans[scan_id]
        scanners = self.get_available_scanners()
        is_web_target = target.startswith('http') or options.get('port', 80) in [80, 443, 8080, 8443]

        # Run sub-scans in direct threads (avoids executor shutdown issues on Python 3.13)
        sub_threads = []

        def _safe_run(fn, *args):
            try:
                fn(*args)
            except Exception as e:
                logger.error(f"Sub-scan error: {e}")

        if scanners.get('nuclei'):
            t = threading.Thread(target=_safe_run, args=(self._run_nuclei_scan, scan_id, target, options), daemon=True)
            t.start()
            sub_threads.append(t)
        if scanners.get('nikto') and is_web_target:
            t = threading.Thread(target=_safe_run, args=(self._run_nikto_scan, scan_id, target, options), daemon=True)
            t.start()
            sub_threads.append(t)
        if scanners.get('nmap_vuln'):
            t = threading.Thread(target=_safe_run, args=(self._run_nmap_vuln_scan, scan_id, target, options), daemon=True)
            t.start()
            sub_threads.append(t)
        # Include ZAP for web targets if available and enabled
        if scanners.get('zap') and is_web_target and options.get('include_zap', True):
            t = threading.Thread(target=_safe_run, args=(self._run_zap_full_scan, scan_id, target, options), daemon=True)
            t.start()
            sub_threads.append(t)

        # Wait for all to complete
        for t in sub_threads:
            t.join()
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get status of a scan (checks memory first, then database)"""
        with self._lock:
            if scan_id in self.active_scans:
                progress = self.active_scans[scan_id]
                progress.findings_count = len(self.scan_results.get(scan_id, []))
                return progress.to_dict()

        # Check database for historical scans
        if self._db:
            try:
                scan_data = self._db.get_scan_job(scan_id)
                if scan_data:
                    return {
                        'scan_id': scan_data.get('scan_id'),
                        'scan_type': scan_data.get('scan_type'),
                        'target': scan_data.get('target'),
                        'status': scan_data.get('status'),
                        'progress_percent': scan_data.get('progress_percent', 0),
                        'findings_count': scan_data.get('findings_count', 0),
                        'current_check': scan_data.get('current_check', ''),
                        'started_at': scan_data.get('started_at'),
                        'completed_at': scan_data.get('completed_at'),
                        'error_message': scan_data.get('error_message', ''),
                    }
            except Exception as e:
                logger.debug(f"Error getting scan from DB: {e}")

        return None

    def get_active_scans_list(self) -> List[Dict]:
        """Get list of all active/recent scans with their status"""
        scans = []

        with self._lock:
            for scan_id, progress in self.active_scans.items():
                progress.findings_count = len(self.scan_results.get(scan_id, []))
                scans.append(progress.to_dict())

        # Also include recent scans from database
        if self._db:
            try:
                db_scans = self._db.get_scan_jobs(limit=20)
                db_scan_ids = {s.get('scan_id') for s in scans}

                for scan_data in db_scans:
                    if scan_data.get('scan_id') not in db_scan_ids:
                        scans.append({
                            'scan_id': scan_data.get('scan_id'),
                            'scan_type': scan_data.get('scan_type'),
                            'target': scan_data.get('target'),
                            'status': scan_data.get('status'),
                            'progress_percent': scan_data.get('progress_percent', 0),
                            'findings_count': scan_data.get('findings_count', 0),
                            'current_check': scan_data.get('current_check', ''),
                            'started_at': scan_data.get('started_at'),
                            'completed_at': scan_data.get('completed_at'),
                            'error_message': scan_data.get('error_message', ''),
                        })
            except Exception as e:
                logger.debug(f"Error getting scans from DB: {e}")

        # Sort by start time, most recent first
        scans.sort(key=lambda x: x.get('started_at') or '', reverse=True)
        return scans[:20]  # Limit to 20 most recent

    def get_scan_results(self, scan_id: str) -> List[Dict]:
        """Get results for a scan (checks memory first, then database)"""
        with self._lock:
            if scan_id in self.scan_results:
                findings = self.scan_results[scan_id]
                return [f.to_dict() for f in findings]

        # Check database for historical results
        if self._db:
            try:
                findings_data = self._db.get_scan_findings(scan_id)
                return findings_data
            except Exception as e:
                logger.debug(f"Error getting findings from DB: {e}")

        return []

    def get_all_findings(self, severity: str = None, limit: int = 100) -> List[Dict]:
        """Get all findings across all scans (combines memory and database)"""
        all_findings = []
        finding_scan_map = {}  # finding_id -> scan_id

        with self._lock:
            for scan_id, findings in self.scan_results.items():
                for f in findings:
                    all_findings.append(f)
                    finding_scan_map[f.finding_id] = scan_id

        # Also get from database
        if self._db:
            try:
                db_findings = self._db.get_all_findings(severity=severity, limit=limit)
                # Merge with memory findings (avoid duplicates by finding_id)
                memory_ids = {f.finding_id for f in all_findings}
                for db_finding in db_findings:
                    fid = db_finding.get('finding_id')
                    if fid not in memory_ids:
                        f = self._dict_to_finding(db_finding)
                        all_findings.append(f)
                        if db_finding.get('scan_id'):
                            finding_scan_map[f.finding_id] = db_finding['scan_id']
            except Exception as e:
                logger.debug(f"Error getting findings from DB: {e}")

        # Filter by severity if specified
        if severity:
            try:
                sev = VulnSeverity(severity.lower())
                all_findings = [f for f in all_findings if f.severity == sev]
            except ValueError:
                pass

        # Sort by severity (critical first) then by timestamp
        severity_order = {
            VulnSeverity.CRITICAL: 0,
            VulnSeverity.HIGH: 1,
            VulnSeverity.MEDIUM: 2,
            VulnSeverity.LOW: 3,
            VulnSeverity.INFO: 4
        }
        all_findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.timestamp), reverse=True)

        results = []
        for f in all_findings[:limit]:
            d = f.to_dict()
            d['scan_id'] = finding_scan_map.get(f.finding_id, '')
            results.append(d)
        return results
    
    def get_summary(self) -> Dict[str, Any]:
        """Get overall vulnerability summary (combines memory and database)"""
        severity_counts = {s.value: 0 for s in VulnSeverity}
        scanner_counts = {}
        total_findings = 0

        with self._lock:
            for findings in self.scan_results.values():
                for f in findings:
                    total_findings += 1
                    severity_counts[f.severity.value] += 1
                    scanner_counts[f.scanner] = scanner_counts.get(f.scanner, 0) + 1

            active_scans = sum(1 for p in self.active_scans.values() if p.status == 'running')

        # Also get summary from database
        if self._db:
            try:
                db_summary = self._db.get_findings_summary()
                # Merge database counts (database may have findings not in memory)
                db_total = db_summary.get('total', 0)
                if db_total > total_findings:
                    total_findings = db_total
                    for sev, count in db_summary.get('by_severity', {}).items():
                        severity_counts[sev] = max(severity_counts.get(sev, 0), count)
                    for scanner, count in db_summary.get('by_scanner', {}).items():
                        scanner_counts[scanner] = max(scanner_counts.get(scanner, 0), count)
            except Exception as e:
                logger.debug(f"Error getting summary from DB: {e}")

        return {
            'total_findings': total_findings,
            'severity_counts': severity_counts,
            'scanner_counts': scanner_counts,
            'total_scans': len(self.active_scans),
            'active_scans': active_scans,
            'available_scanners': self.get_available_scanners()
        }

    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan"""
        with self._lock:
            if scan_id in self.active_scans:
                progress = self.active_scans[scan_id]
                if progress.status == 'running':
                    progress.status = 'cancelled'
                    progress.error_message = 'Cancelled by user'
                    progress.completed_at = datetime.now()
                    # Save to database
                    self._save_scan_to_db(scan_id, progress)
                    return True
        return False

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and its findings from memory and database"""
        deleted = False

        with self._lock:
            # Remove from active scans
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
                deleted = True

            # Remove findings from memory
            if scan_id in self.scan_results:
                del self.scan_results[scan_id]
                deleted = True

        # Remove from database
        if self._db:
            try:
                with self._db.get_connection() as conn:
                    cursor = conn.cursor()
                    # Delete findings for this scan
                    cursor.execute("DELETE FROM scan_findings WHERE scan_id = ?", (scan_id,))
                    # Delete scan job record
                    cursor.execute("DELETE FROM scan_jobs WHERE scan_id = ?", (scan_id,))
                    conn.commit()
                deleted = True
                logger.info(f"Deleted scan {scan_id} from database")
            except Exception as e:
                logger.error(f"Error deleting scan from database: {e}")

        return deleted

    def delete_all_scans(self) -> int:
        """Delete all scans and findings"""
        count = 0

        with self._lock:
            count = len(self.active_scans) + len(self.scan_results)
            self.active_scans.clear()
            self.scan_results.clear()

        # Clear database
        if self._db:
            try:
                with self._db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM scan_findings")
                    cursor.execute("DELETE FROM scan_jobs")
                    conn.commit()
                logger.info("Deleted all scans from database")
            except Exception as e:
                logger.error(f"Error clearing scans from database: {e}")

        return count

    def generate_zap_report(self, report_format: str = 'html') -> Optional[bytes]:
        """Generate a ZAP scan report"""
        if not self._is_zap_running():
            logger.error("ZAP is not running, cannot generate report")
            return None

        try:
            # ZAP report formats: html, xml, json, md
            format_endpoints = {
                'html': 'JSON/reports/action/generate',
                'xml': 'OTHER/core/other/xmlreport',
                'json': 'JSON/core/view/alerts',
                'md': 'JSON/reports/action/generate'
            }

            if report_format == 'json':
                # For JSON, get all alerts
                alerts_resp = self._zap_api_call('JSON/core/view/alerts', {
                    'start': '0',
                    'count': '10000'
                })
                report_data = json.dumps(alerts_resp, indent=2)
                return report_data.encode('utf-8')

            elif report_format == 'xml':
                # XML report
                url = f"{self._zap_base_url}/OTHER/core/other/xmlreport/?apikey={self._zap_api_key}"
                req = urllib.request.Request(url, method='GET')
                with urllib.request.urlopen(req, timeout=60) as response:
                    return response.read()

            elif report_format in ('html', 'md'):
                # Use ZAP's report generation API
                # First check if traditional report is available
                try:
                    template = 'traditional-html' if report_format == 'html' else 'traditional-md'
                    report_resp = self._zap_api_call('JSON/reports/action/generate', {
                        'title': 'Ragnar Security Scan Report',
                        'template': template,
                        'reportDir': '',
                        'reportFileName': f'ragnar_report.{report_format}'
                    })

                    # Get the report file path
                    report_file = report_resp.get('generate')
                    if report_file:
                        # Read the generated report
                        with open(report_file, 'rb') as f:
                            return f.read()
                except Exception as e:
                    logger.warning(f"Modern report generation failed, trying legacy: {e}")

                # Fallback to legacy HTML report
                if report_format == 'html':
                    url = f"{self._zap_base_url}/OTHER/core/other/htmlreport/?apikey={self._zap_api_key}"
                    req = urllib.request.Request(url, method='GET')
                    with urllib.request.urlopen(req, timeout=60) as response:
                        return response.read()

            logger.error(f"Unsupported report format: {report_format}")
            return None

        except Exception as e:
            logger.error(f"Error generating ZAP report: {e}")
            return None

    def cleanup(self):
        """Cleanup resources (ZAP process, etc.)"""
        try:
            if self._zap_process and self._zap_process.poll() is None:
                self._zap_process.terminate()
        except Exception:
            pass


# Global instance
_advanced_scanner: Optional[AdvancedVulnScanner] = None


def get_advanced_vuln_scanner(shared_data=None) -> AdvancedVulnScanner:
    """Get or create the global AdvancedVulnScanner instance"""
    global _advanced_scanner
    if _advanced_scanner is None:
        _advanced_scanner = AdvancedVulnScanner(shared_data)
    return _advanced_scanner
