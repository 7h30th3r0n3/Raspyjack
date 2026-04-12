# server_capabilities.py
"""
Server Mode Detection and Advanced Feature Management for Ragnar

This module detects when Ragnar is running on a capable server (AMD64/ARM64 with 8GB+ RAM)
and unlocks advanced features that would be impossible on a Pi Zero W2.

Features unlocked in server mode:
- Traffic Analysis (packet capture, network monitoring)
- Advanced Vulnerability Assessment (OpenVAS, Nuclei, Nikto)
- Parallel scanning
- Large dictionary attacks
- Local AI/LLM integration
"""

import os
import platform
import subprocess
import threading
import logging
import json
import shutil
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime

from logger import Logger

logger = Logger(name="server_capabilities", level=logging.INFO)


@dataclass
class SystemCapabilities:
    """Data class representing system hardware capabilities"""
    architecture: str = "unknown"
    cpu_cores: int = 1
    total_ram_gb: float = 0.0
    available_ram_gb: float = 0.0
    is_64bit: bool = False
    is_server_capable: bool = False
    is_pi_zero: bool = False
    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    kernel_version: str = ""
    
    # Feature flags
    traffic_analysis_enabled: bool = False
    advanced_vuln_enabled: bool = False
    parallel_scanning_enabled: bool = False
    local_ai_enabled: bool = False
    large_dictionaries_enabled: bool = False
    
    # Tool availability
    available_tools: Dict[str, bool] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ServerCapabilities:
    """
    Detect system capabilities and manage server-mode features.
    
    Server mode is enabled when:
    - Architecture is AMD64 or ARM64 (or armv8l in 32-bit mode on 64-bit Pi)
    - System has at least 7.5GB RAM (allows for system reserved)
    - Not running on Pi Zero
    """
    
    # Minimum requirements for server mode
    # Use 7.5GB to account for system reserved memory on 8GB devices
    MIN_RAM_GB = 7.5
    MIN_CORES = 2
    # Include armv8l which is 32-bit userspace on 64-bit ARM (Pi 4/5 with 32-bit OS)
    SUPPORTED_ARCHS = ['x86_64', 'amd64', 'aarch64', 'arm64', 'armv8l', 'armv7l']
    
    # Tool definitions for advanced features
    TRAFFIC_ANALYSIS_TOOLS = {
        'tcpdump': {'package': 'tcpdump', 'critical': True},
        'tshark': {'package': 'tshark', 'critical': False},
        'ngrep': {'package': 'ngrep', 'critical': False},
        'iftop': {'package': 'iftop', 'critical': False},
        'nethogs': {'package': 'nethogs', 'critical': False},
        'ss': {'package': 'iproute2', 'critical': True},
    }
    
    VULN_ASSESSMENT_TOOLS = {
        'nmap': {'package': 'nmap', 'critical': True},
        'nuclei': {'package': 'nuclei', 'critical': False, 'install_cmd': 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'},
        'nikto': {'package': 'nikto', 'critical': False},
        'sqlmap': {'package': 'sqlmap', 'critical': False},
        'hydra': {'package': 'hydra', 'critical': False},
        'whatweb': {'package': 'whatweb', 'critical': False},
    }
    
    def __init__(self, shared_data=None):
        self.shared_data = shared_data
        self.capabilities = SystemCapabilities()
        self._lock = threading.Lock()
        self._detection_complete = False
        
        # Detect capabilities on init
        self.detect_capabilities()
    
    def detect_capabilities(self) -> SystemCapabilities:
        """Detect system hardware and software capabilities"""
        with self._lock:
            try:
                self._detect_hardware()
                self._detect_os_info()
                self._check_tool_availability()
                self._determine_feature_flags()
                self._detection_complete = True
                
                logger.info(f"Server capabilities detected: arch={self.capabilities.architecture}, "
                           f"ram={self.capabilities.total_ram_gb:.1f}GB, cores={self.capabilities.cpu_cores}, "
                           f"server_capable={self.capabilities.is_server_capable}")
                
            except Exception as e:
                logger.error(f"Error detecting capabilities: {e}")
                
        return self.capabilities
    
    def _detect_hardware(self):
        """Detect CPU and memory specifications"""
        # Architecture
        arch = platform.machine().lower()
        self.capabilities.architecture = arch
        self.capabilities.is_64bit = platform.architecture()[0] == '64bit'
        
        # CPU cores
        try:
            self.capabilities.cpu_cores = os.cpu_count() or 1
        except Exception:
            self.capabilities.cpu_cores = 1
        
        # RAM detection
        try:
            import psutil
            mem = psutil.virtual_memory()
            self.capabilities.total_ram_gb = mem.total / (1024 ** 3)
            self.capabilities.available_ram_gb = mem.available / (1024 ** 3)
        except ImportError:
            # Fallback: read from /proc/meminfo
            self._detect_ram_from_proc()
        
        # Pi Zero detection
        self._detect_pi_zero()
        
        # Determine if server capable
        # Pi 5 with 8GB is definitely capable, Pi 4/5 with 4GB gets partial features
        self.capabilities.is_server_capable = (
            arch in self.SUPPORTED_ARCHS and
            self.capabilities.total_ram_gb >= self.MIN_RAM_GB and
            self.capabilities.cpu_cores >= self.MIN_CORES and
            not self.capabilities.is_pi_zero
        )
        
        # Log detailed capability info for debugging
        logger.debug(f"Capability check: arch={arch} (supported={arch in self.SUPPORTED_ARCHS}), "
                    f"ram={self.capabilities.total_ram_gb:.1f}GB (min={self.MIN_RAM_GB}GB), "
                    f"cores={self.capabilities.cpu_cores} (min={self.MIN_CORES}), "
                    f"is_pi_zero={self.capabilities.is_pi_zero}")
    
    def _detect_ram_from_proc(self):
        """Fallback RAM detection from /proc/meminfo"""
        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        # Value is in kB
                        kb = int(line.split()[1])
                        self.capabilities.total_ram_gb = kb / (1024 ** 2)
                    elif line.startswith('MemAvailable:'):
                        kb = int(line.split()[1])
                        self.capabilities.available_ram_gb = kb / (1024 ** 2)
        except Exception as e:
            logger.warning(f"Could not read /proc/meminfo: {e}")
    
    def _detect_pi_zero(self):
        """Detect if running on Raspberry Pi Zero (vs Pi 4/5 which are server-capable)"""
        self.capabilities.is_pi_zero = False
        
        try:
            # Check device-tree model first - most reliable
            model_path = '/sys/firmware/devicetree/base/model'
            if os.path.exists(model_path):
                with open(model_path, 'r') as f:
                    model = f.read().lower().strip('\x00')
                    logger.debug(f"Detected device model: {model}")
                    
                    # Pi 4 and Pi 5 with sufficient RAM are server-capable
                    if 'raspberry pi 5' in model or 'raspberry pi 4' in model:
                        if self.capabilities.total_ram_gb >= 4.0:
                            logger.info(f"Detected capable Raspberry Pi: {model.strip()}")
                            self.capabilities.is_pi_zero = False
                            return
                    
                    # Only mark as Pi Zero if explicitly a Zero model
                    if 'zero' in model:
                        self.capabilities.is_pi_zero = True
                        return
            
            # Fallback: Check /proc/cpuinfo for Pi Zero signature
            if os.path.exists('/proc/cpuinfo'):
                with open('/proc/cpuinfo', 'r') as f:
                    content = f.read().lower()
                    # BCM2835 is Pi Zero/1 - only flag if also low RAM
                    if 'bcm2835' in content and self.capabilities.total_ram_gb < 1.0:
                        self.capabilities.is_pi_zero = True
                        return
                        
        except Exception as e:
            logger.debug(f"Pi Zero detection error: {e}")
    
    def _detect_os_info(self):
        """Detect OS information"""
        self.capabilities.hostname = platform.node()
        self.capabilities.os_name = platform.system()
        self.capabilities.os_version = platform.release()
        self.capabilities.kernel_version = platform.version()
    
    def _check_tool_availability(self):
        """Check which security tools are available"""
        all_tools = {**self.TRAFFIC_ANALYSIS_TOOLS, **self.VULN_ASSESSMENT_TOOLS}
        
        for tool_name in all_tools:
            self.capabilities.available_tools[tool_name] = shutil.which(tool_name) is not None
    
    def _determine_feature_flags(self):
        """Determine which advanced features can be enabled"""
        caps = self.capabilities
        
        if caps.is_server_capable:
            # Traffic Analysis: needs tcpdump at minimum
            caps.traffic_analysis_enabled = caps.available_tools.get('tcpdump', False)
            
            # Advanced Vuln: needs nmap (which Ragnar already uses)
            caps.advanced_vuln_enabled = caps.available_tools.get('nmap', False)
            
            # Parallel scanning: enabled on multi-core systems
            caps.parallel_scanning_enabled = caps.cpu_cores >= 4
            
            # Local AI: check for Ollama
            caps.local_ai_enabled = shutil.which('ollama') is not None
            
            # Large dictionaries: enabled on 7.5GB+ RAM (8GB devices report ~7.87GB)
            caps.large_dictionaries_enabled = caps.total_ram_gb >= 7.5
        else:
            # All advanced features disabled on Pi Zero / low-spec systems
            caps.traffic_analysis_enabled = False
            caps.advanced_vuln_enabled = False
            caps.parallel_scanning_enabled = False
            caps.local_ai_enabled = False
            caps.large_dictionaries_enabled = False
    
    def is_server_mode(self) -> bool:
        """Check if running in server mode"""
        return self.capabilities.is_server_capable
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Get capabilities as dictionary for API"""
        return self.capabilities.to_dict()
    
    def get_feature_status(self) -> Dict[str, bool]:
        """Get status of all advanced features"""
        caps = self.capabilities
        return {
            'server_mode': caps.is_server_capable,
            'traffic_analysis': caps.traffic_analysis_enabled,
            'advanced_vuln_assessment': caps.advanced_vuln_enabled,
            'parallel_scanning': caps.parallel_scanning_enabled,
            'local_ai': caps.local_ai_enabled,
            'large_dictionaries': caps.large_dictionaries_enabled,
        }
    
    def get_missing_tools(self, feature: str) -> List[str]:
        """Get list of missing tools for a feature"""
        if feature == 'traffic_analysis':
            tools = self.TRAFFIC_ANALYSIS_TOOLS
        elif feature == 'advanced_vuln':
            tools = self.VULN_ASSESSMENT_TOOLS
        else:
            return []
        
        missing = []
        for tool_name, info in tools.items():
            if not self.capabilities.available_tools.get(tool_name, False):
                if info.get('critical', False):
                    missing.insert(0, tool_name)  # Critical tools first
                else:
                    missing.append(tool_name)
        
        return missing
    
    def install_missing_tools(self, feature: str) -> Tuple[bool, str]:
        """Attempt to install missing tools for a feature"""
        if not self.capabilities.is_server_capable:
            return False, "Server mode not available on this system"
        
        missing = self.get_missing_tools(feature)
        if not missing:
            return True, "All required tools are already installed"
        
        # Determine package manager
        pkg_cmd = None
        if shutil.which('apt-get'):
            pkg_cmd = ['sudo', 'apt-get', 'install', '-y']
        elif shutil.which('dnf'):
            pkg_cmd = ['sudo', 'dnf', 'install', '-y']
        elif shutil.which('yum'):
            pkg_cmd = ['sudo', 'yum', 'install', '-y']
        elif shutil.which('pacman'):
            pkg_cmd = ['sudo', 'pacman', '-S', '--noconfirm']
        
        if not pkg_cmd:
            return False, "No supported package manager found"
        
        installed = []
        failed = []
        
        for tool in missing:
            try:
                result = subprocess.run(
                    pkg_cmd + [tool],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if result.returncode == 0:
                    installed.append(tool)
                else:
                    failed.append(tool)
            except Exception as e:
                logger.error(f"Failed to install {tool}: {e}")
                failed.append(tool)
        
        # Re-check availability
        self._check_tool_availability()
        self._determine_feature_flags()
        
        if failed:
            return False, f"Installed: {installed}, Failed: {failed}"
        return True, f"Successfully installed: {installed}"


# Global instance
_server_capabilities: Optional[ServerCapabilities] = None


def get_server_capabilities(shared_data=None) -> ServerCapabilities:
    """Get or create the global ServerCapabilities instance"""
    global _server_capabilities
    if _server_capabilities is None:
        _server_capabilities = ServerCapabilities(shared_data)
    return _server_capabilities


def is_server_mode() -> bool:
    """Quick check if running in server mode"""
    return get_server_capabilities().is_server_mode()
