# resource_monitor.py
"""
Resource monitoring for Raspberry Pi Zero W2
Prevents system hangs by monitoring and limiting resource usage
"""

import os
import logging
import time
from logger import Logger

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

logger = Logger(name="resource_monitor", level=logging.INFO)


class ResourceMonitor:
    """Monitor system resources and prevent overload on Pi Zero W2"""
    
    def __init__(self):
        self.logger = logger
        
        # Pi Zero W2 thresholds (ULTRA-conservative for 416MB actual usable RAM)
        # System has 512MB total but only ~416MB available for apps
        self.memory_warning_threshold = 60  # % - Start warning (lowered from 70%)
        self.memory_critical_threshold = 75  # % - Block new operations (lowered from 85%)
        self.cpu_warning_threshold = 80  # %
        self.cpu_critical_threshold = 95  # %
        
        # Monitoring state
        self.last_warning_time = 0
        self.warning_interval = 60  # Don't spam warnings more than once per minute
        
    def get_memory_usage(self):
        """Get current memory usage percentage"""
        if not _HAS_PSUTIL:
            return 0
        try:
            mem = psutil.virtual_memory()
            return mem.percent
        except Exception as e:
            self.logger.error(f"Error getting memory usage: {e}")
            return 0

    def get_cpu_usage(self):
        """Get current CPU usage percentage (1 second average)"""
        if not _HAS_PSUTIL:
            return 0
        try:
            return psutil.cpu_percent(interval=1)
        except Exception as e:
            self.logger.error(f"Error getting CPU usage: {e}")
            return 0

    def get_available_memory_mb(self):
        """Get available memory in MB"""
        if not _HAS_PSUTIL:
            return 999
        try:
            mem = psutil.virtual_memory()
            return mem.available / (1024 * 1024)
        except Exception as e:
            self.logger.error(f"Error getting available memory: {e}")
            return 0
    
    def is_system_healthy(self):
        """Check if system has enough resources for new operations"""
        mem_percent = self.get_memory_usage()
        cpu_percent = self.get_cpu_usage()
        
        if mem_percent >= self.memory_critical_threshold:
            current_time = time.time()
            if current_time - self.last_warning_time > self.warning_interval:
                self.logger.critical(
                    f"CRITICAL: Memory usage at {mem_percent:.1f}% - "
                    f"BLOCKING new operations to prevent system hang!"
                )
                self.last_warning_time = current_time
            return False
        
        if cpu_percent >= self.cpu_critical_threshold:
            current_time = time.time()
            if current_time - self.last_warning_time > self.warning_interval:
                self.logger.critical(
                    f"CRITICAL: CPU usage at {cpu_percent:.1f}% - "
                    f"BLOCKING new operations to prevent system hang!"
                )
                self.last_warning_time = current_time
            return False
        
        if mem_percent >= self.memory_warning_threshold:
            current_time = time.time()
            if current_time - self.last_warning_time > self.warning_interval:
                self.logger.warning(
                    f"WARNING: Memory usage at {mem_percent:.1f}% - "
                    f"System may slow down"
                )
                self.last_warning_time = current_time
        
        return True
    
    def can_start_operation(self, operation_name="operation", min_memory_mb=50):
        """
        Check if there's enough memory to start a new operation
        
        Args:
            operation_name: Name of the operation for logging
            min_memory_mb: Minimum MB of free memory required
        
        Returns:
            bool: True if operation can start, False otherwise
        """
        available_mb = self.get_available_memory_mb()
        
        if available_mb < min_memory_mb:
            self.logger.warning(
                f"Cannot start {operation_name}: "
                f"Only {available_mb:.1f}MB available, need {min_memory_mb}MB"
            )
            return False
        
        return self.is_system_healthy()
    
    def is_memory_pressure_critical(self):
        """
        Check if we're in critical memory pressure (< 80MB free)
        Emergency threshold for 416MB systems
        
        Returns:
            bool: True if critical memory pressure detected
        """
        available_mb = self.get_available_memory_mb()
        
        if available_mb < 80:
            self.logger.critical(
                f"🚨 CRITICAL MEMORY PRESSURE: Only {available_mb:.1f}MB free! "
                f"Emergency pause recommended."
            )
            return True
        elif available_mb < 120:
            self.logger.warning(
                f"⚠️  Memory pressure detected: {available_mb:.1f}MB free"
            )
            return False
        
        return False
    
    def get_system_status(self):
        """Get comprehensive system status"""
        if not _HAS_PSUTIL:
            return {
                'memory': {'percent': 0, 'status': 'ok', 'total_mb': 0, 'available_mb': 999, 'used_mb': 0},
                'cpu': {'percent': 0, 'status': 'ok'},
                'processes': 0, 'threads': 0,
                'healthy': True
            }
        try:
            mem = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=0.5)

            # Get process count
            process_count = len(psutil.pids())

            # Get thread count (current process)
            try:
                thread_count = psutil.Process().num_threads()
            except Exception:
                thread_count = 0

            status = {
                'memory': {
                    'total_mb': mem.total / (1024 * 1024),
                    'available_mb': mem.available / (1024 * 1024),
                    'used_mb': mem.used / (1024 * 1024),
                    'percent': mem.percent,
                    'status': self._get_status_level(mem.percent,
                                                     self.memory_warning_threshold,
                                                     self.memory_critical_threshold)
                },
                'cpu': {
                    'percent': cpu_percent,
                    'status': self._get_status_level(cpu_percent,
                                                     self.cpu_warning_threshold,
                                                     self.cpu_critical_threshold)
                },
                'processes': process_count,
                'threads': thread_count,
                'healthy': self.is_system_healthy()
            }

            return status

        except Exception as e:
            self.logger.error(f"Error getting system status: {e}")
            return {
                'memory': {'percent': 0, 'status': 'unknown'},
                'cpu': {'percent': 0, 'status': 'unknown'},
                'healthy': True  # Fail open if we can't check
            }
    
    def _get_status_level(self, value, warning_threshold, critical_threshold):
        """Determine status level (ok, warning, critical) based on value and thresholds"""
        if value >= critical_threshold:
            return 'critical'
        elif value >= warning_threshold:
            return 'warning'
        else:
            return 'ok'
    
    def force_garbage_collection(self):
        """Force Python garbage collection to free memory"""
        try:
            import gc
            collected = gc.collect()
            self.logger.info(f"Garbage collection freed {collected} objects")
        except Exception as e:
            self.logger.error(f"Error during garbage collection: {e}")
    
    def log_system_status(self):
        """Log current system status"""
        status = self.get_system_status()
        self.logger.info(
            f"System Status - "
            f"Memory: {status['memory']['percent']:.1f}% ({status['memory']['status']}), "
            f"CPU: {status['cpu']['percent']:.1f}% ({status['cpu']['status']}), "
            f"Processes: {status['processes']}, "
            f"Threads: {status['threads']}"
        )


# Global instance
resource_monitor = ResourceMonitor()
