#!/usr/bin/env python3
"""
Pushover Notification Service for Ragnar
Sends push notifications via the Pushover API for security events.
"""

import logging
import threading
import time

logger = logging.getLogger(__name__)

PUSHOVER_API_URL = "https://api.pushover.net/1/messages.json"


class PushoverService:
    """Lightweight wrapper around the Pushover HTTP API."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self._lock = threading.Lock()
        # Tracks already-notified items to avoid spamming
        self._notified_devices = set()   # set of IPs ever notified (persisted across restarts via DB load)
        self._offline_devices = set()    # IPs that went offline this session (for back-online detection)
        self._last_notified_vuln_count = 0  # last count we sent a vuln alert for
        self._notified_creds = 0         # last known cred count
        self._last_send_ts = 0.0         # rate-limit: min 2 s between sends
        self._startup_ts = time.time()   # suppress device notifications shortly after restart
        self._startup_grace_s = 90       # seconds to wait before sending device alerts
        self._load_known_state_from_db()

    # ------------------------------------------------------------------
    # DB state loader — prevents restart-triggered false notifications
    # ------------------------------------------------------------------

    def _load_known_state_from_db(self):
        """Pre-populate _notified_devices and _last_notified_vuln_count from the DB
        so that a restart does not re-notify about already-known devices/vulns."""
        try:
            db = getattr(self.shared_data, 'db', None)
            if db is None:
                return
            with db.get_connection() as conn:
                cursor = conn.cursor()
                # Load all known IPs
                cursor.execute("SELECT ip FROM hosts WHERE ip IS NOT NULL AND ip != ''")
                rows = cursor.fetchall()
                with self._lock:
                    for row in rows:
                        ip = row[0] if isinstance(row, (list, tuple)) else row.get('ip', '')
                        if ip:
                            self._notified_devices.add(ip)
                # Load current vuln count as baseline (so we only alert on genuinely new ones)
                cursor.execute(
                    "SELECT COUNT(*) FROM hosts "
                    "WHERE vulnerabilities IS NOT NULL AND vulnerabilities != '' AND vulnerabilities != 'None'"
                )
                row = cursor.fetchone()
                baseline = row[0] if row else 0
                with self._lock:
                    self._last_notified_vuln_count = baseline
                # Load credential baseline count
                try:
                    cursor.execute("SELECT COUNT(*) FROM hosts WHERE credentials IS NOT NULL AND credentials != '' AND credentials != 'None'")
                    cred_row = cursor.fetchone()
                    cred_baseline = cred_row[0] if cred_row else 0
                    with self._lock:
                        self._notified_creds = cred_baseline
                except Exception:
                    pass  # credentials column may not exist
            logger.debug(
                f"Pushover: loaded {len(self._notified_devices)} known IPs, "
                f"vuln baseline={baseline} from DB"
            )
        except Exception as e:
            logger.debug(f"Pushover DB state load skipped: {e}")

    # ------------------------------------------------------------------
    # Key helpers (reads from .env via EnvManager)
    # ------------------------------------------------------------------

    def _get_keys(self):
        """Return (user_key, api_token) or (None, None) if not configured."""
        try:
            from env_manager import EnvManager
            em = EnvManager()
            user_key = em.get_env_key("RAGNAR_PUSHOVER_USER_KEY")
            api_token = em.get_env_key("RAGNAR_PUSHOVER_API_TOKEN")
            return user_key, api_token
        except Exception as e:
            logger.debug(f"Pushover key lookup failed: {e}")
            return None, None

    def is_configured(self):
        """Return True when both Pushover keys are present."""
        user_key, api_token = self._get_keys()
        return bool(user_key and api_token)

    def is_enabled(self):
        """Return True when Pushover is both configured and enabled in config."""
        return self.shared_data.config.get("pushover_enabled", False) and self.is_configured()

    # ------------------------------------------------------------------
    # Core send
    # ------------------------------------------------------------------

    def send(self, message, title="Ragnar", priority=0, sound="pushover"):
        """Send a Pushover notification. Returns dict with success/message."""
        user_key, api_token = self._get_keys()
        if not user_key or not api_token:
            return {"success": False, "message": "Pushover keys not configured"}

        # Simple rate-limit (2 s)
        with self._lock:
            now = time.time()
            elapsed = now - self._last_send_ts
            if elapsed < 2.0:
                time.sleep(2.0 - elapsed)
            self._last_send_ts = time.time()

        try:
            import urllib.request
            import urllib.parse
            import json

            payload = urllib.parse.urlencode({
                "token": api_token,
                "user": user_key,
                "message": message,
                "title": title,
                "priority": priority,
                "sound": sound,
            }).encode("utf-8")

            req = urllib.request.Request(PUSHOVER_API_URL, data=payload, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                if body.get("status") == 1:
                    logger.info(f"Pushover notification sent: {title}")
                    return {"success": True, "message": "Notification sent"}
                else:
                    err = body.get("errors", ["Unknown error"])
                    logger.warning(f"Pushover API error: {err}")
                    return {"success": False, "message": f"Pushover error: {err}"}

        except Exception as e:
            logger.error(f"Pushover send failed: {e}")
            return {"success": False, "message": str(e)}

    # ------------------------------------------------------------------
    # Event helpers (called from webapp update loop)
    # ------------------------------------------------------------------

    def _in_startup_grace(self):
        """Return True if still within the post-restart grace period."""
        return (time.time() - self._startup_ts) < self._startup_grace_s

    def notify_new_devices(self, new_ips):
        """Notify about devices that have NEVER been seen before (deduped against DB)."""
        if not self.is_enabled():
            return
        if not self.shared_data.config.get("pushover_notify_new_device", True):
            return
        truly_new = [ip for ip in new_ips if ip not in self._notified_devices]
        if not truly_new:
            return
        self._notified_devices.update(truly_new)
        # Suppress notification during startup grace period — just record the IPs
        if self._in_startup_grace():
            logger.debug(f"Pushover: suppressed new-device alert for {len(truly_new)} IP(s) during startup grace")
            return
        count = len(truly_new)
        ip_list = ", ".join(sorted(truly_new)[:5])
        suffix = f" (+{count - 5} more)" if count > 5 else ""
        msg = f"⚔️ {count} new device(s) discovered on the network for the first time:\n{ip_list}{suffix}"
        threading.Thread(target=self.send, args=(msg, "Ragnar — New Device"), daemon=True).start()

    def notify_device_lost(self, lost_ips):
        """Notify when devices go offline (and remember them for back-online detection)."""
        if not self.is_enabled():
            return
        # Always track offline state even if notifications are disabled, so back-online works
        self._offline_devices.update(lost_ips)
        if self._in_startup_grace():
            logger.debug(f"Pushover: suppressed device-lost alert for {len(lost_ips)} IP(s) during startup grace")
            return
        if not self.shared_data.config.get("pushover_notify_device_lost", False):
            return
        if not lost_ips:
            return
        count = len(lost_ips)
        ip_list = ", ".join(sorted(lost_ips)[:5])
        suffix = f" (+{count - 5} more)" if count > 5 else ""
        msg = f"🛡️ {count} device(s) went offline:\n{ip_list}{suffix}"
        threading.Thread(target=self.send, args=(msg, "Ragnar — Device Lost"), daemon=True).start()

    def notify_device_back_online(self, appeared_ips):
        """Notify when a previously known device that went offline comes back online."""
        if not self.is_enabled():
            return
        if not self.shared_data.config.get("pushover_notify_device_back_online", False):
            return
        # Only alert for IPs we actually saw go offline this session
        back_online = [ip for ip in appeared_ips
                       if ip in self._notified_devices and ip in self._offline_devices]
        if not back_online:
            return
        # Remove from offline tracking since they're back
        self._offline_devices.difference_update(back_online)
        count = len(back_online)
        ip_list = ", ".join(sorted(back_online)[:5])
        suffix = f" (+{count - 5} more)" if count > 5 else ""
        msg = f"📶 {count} device(s) back online:\n{ip_list}{suffix}"
        threading.Thread(target=self.send, args=(msg, "Ragnar — Device Back Online"), daemon=True).start()

    def notify_new_vulnerabilities(self, new_total):
        """Notify about newly discovered vulnerabilities (compares against last notified count)."""
        if not self.is_enabled():
            return
        if not self.shared_data.config.get("pushover_notify_new_vulnerability", True):
            return
        with self._lock:
            if new_total <= self._last_notified_vuln_count:
                return
            delta = new_total - self._last_notified_vuln_count
            self._last_notified_vuln_count = new_total
        # Suppress notification during startup grace — just absorb the baseline
        if self._in_startup_grace():
            logger.debug(f"Pushover: suppressed vuln alert (delta={delta}) during startup grace")
            return
        msg = f"🔥 {delta} new vulnerability/vulnerabilities found! (total: {new_total})"
        threading.Thread(target=self.send, args=(msg, "Ragnar — Vulnerability Alert", 1), daemon=True).start()

    def notify_new_credentials(self, new_count, total):
        """Notify when new credentials are captured."""
        if not self.is_enabled():
            return
        if not self.shared_data.config.get("pushover_notify_new_credential", True):
            return
        if new_count <= 0:
            return
        if total == self._notified_creds:
            return
        self._notified_creds = total
        # Suppress notification during startup grace — just absorb the baseline
        if self._in_startup_grace():
            logger.debug(f"Pushover: suppressed credential alert during startup grace")
            return
        msg = f"🗝️ {new_count} new credential(s) captured! (total: {total})"
        threading.Thread(target=self.send, args=(msg, "Ragnar — Credentials"), daemon=True).start()
