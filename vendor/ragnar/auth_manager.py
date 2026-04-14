# auth_manager.py
"""
Authentication and Database Encryption Manager for Ragnar.

Provides:
- Hardware-bound authentication (login locked to specific device)
- Full database file encryption at rest (Fernet/AES)
- Recovery codes for password reset
- Session management via Flask signed cookies

Architecture:
- ragnar_auth.db: Small unencrypted DB with password hashes, HW fingerprint, wrapped keys
- ragnar.db.enc: Main DB encrypted with Fernet, decrypted only while authenticated
- Fernet key wrapped per-password and per-recovery-code, never stored in plaintext
"""

import os
import sys
import json
import sqlite3
import hashlib
import secrets
import string
import threading
import logging
import time
from contextlib import contextmanager

try:
    from cryptography.fernet import Fernet, InvalidToken
    cryptography_available = True
except ImportError:
    cryptography_available = False

try:
    from logger import Logger
    logger = Logger(name="auth_manager.py", level=logging.DEBUG)
except Exception:
    import logging as _logging
    logger = _logging.getLogger("auth_manager")


class AuthManager:
    """Manages authentication, hardware binding, and database encryption."""

    PBKDF2_ITERATIONS = 200_000  # Secure for local device, fast on Pi
    RECOVERY_CODE_COUNT = 10
    RECOVERY_CODE_LENGTH = 8

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.datadir = getattr(shared_data, 'datadir', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data'))
        self._db_ready = not self._check_has_encrypted_db()  # True if no decryption needed
        self.auth_db_path = os.path.join(self.datadir, 'ragnar_auth.db')
        self.main_db_path = os.path.join(self.datadir, 'ragnar.db')
        self.encrypted_db_path = os.path.join(self.datadir, 'ragnar.db.enc')
        self._lock = threading.RLock()
        self._fernet_key = None  # Cached in memory after login
        self._secret_key = None

        os.makedirs(self.datadir, exist_ok=True)
        self._init_auth_db()
        self._handle_crash_recovery()

    def _check_has_encrypted_db(self):
        """Check if an encrypted DB file exists (needs decryption on login)."""
        datadir = getattr(self, 'datadir', '')
        return os.path.exists(os.path.join(datadir, 'ragnar.db.enc'))

    @property
    def db_ready(self):
        return self._db_ready

    # =========================================================================
    # AUTH DB MANAGEMENT
    # =========================================================================

    def _ensure_auth_schema(self, conn):
        """Ensure the auth DB schema exists on this connection."""
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                hardware_fingerprint TEXT NOT NULL,
                encrypted_fernet_key TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS recovery_codes (
                id INTEGER PRIMARY KEY,
                code_hash TEXT NOT NULL,
                code_salt TEXT NOT NULL,
                encrypted_fernet_key TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                used_at TEXT DEFAULT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_secrets (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

    def _init_auth_db(self):
        """Create the auth database schema if it doesn't exist."""
        with self._get_auth_conn() as conn:
            self._ensure_auth_schema(conn)
            conn.commit()

    @contextmanager
    def _get_auth_conn(self):
        """Context manager for auth database connections."""
        conn = None
        try:
            conn = sqlite3.connect(self.auth_db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._ensure_auth_schema(conn)
            yield conn
        except Exception:
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()

    # =========================================================================
    # HARDWARE FINGERPRINT
    # =========================================================================

    @staticmethod
    def get_hardware_fingerprint() -> str:
        """
        Generate a deterministic hardware fingerprint from stable device identifiers.
        Uses: machine-id + CPU serial (RPi). These never change regardless of
        network interface (WiFi/Ethernet/USB). MAC address is intentionally excluded
        because it changes when switching between wlan0 and eth0.
        """
        components = []

        # 1. Machine ID (Linux) - stable, generated once at OS install
        for path in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
            try:
                with open(path, 'r') as f:
                    mid = f.read().strip()
                    if mid:
                        components.append(f"machine-id:{mid}")
                        break
            except (OSError, IOError):
                continue

        # 2. Windows Machine GUID
        if not components and sys.platform == 'win32':
            try:
                import winreg
                reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                     r"SOFTWARE\Microsoft\Cryptography")
                guid, _ = winreg.QueryValueEx(reg, "MachineGuid")
                winreg.CloseKey(reg)
                if guid:
                    components.append(f"machine-guid:{guid}")
            except Exception:
                pass

        # 3. CPU serial (Raspberry Pi) - burned into SoC, cannot be changed
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('Serial'):
                        serial = line.split(':')[1].strip()
                        if serial and serial != '0000000000000000':
                            components.append(f"cpu-serial:{serial}")
                        break
        except (OSError, IOError):
            pass

        # Fallback: hostname + platform (only if neither machine-id nor CPU serial found)
        if not components:
            import platform
            components.append(f"hostname:{platform.node()}")
            components.append(f"platform:{platform.platform()}")

        fingerprint_input = '|'.join(sorted(components))
        return hashlib.sha256(fingerprint_input.encode('utf-8')).hexdigest()

    # =========================================================================
    # PASSWORD HASHING
    # =========================================================================

    @staticmethod
    def _hash_password(password: str, salt: bytes = None) -> tuple:
        """Hash a password with PBKDF2-SHA256. Returns (hash_hex, salt_hex)."""
        if salt is None:
            salt = secrets.token_bytes(32)
        pw_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            AuthManager.PBKDF2_ITERATIONS
        )
        return pw_hash.hex(), salt.hex()

    @staticmethod
    def _verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
        """Verify a password against stored hash and salt."""
        salt = bytes.fromhex(stored_salt)
        pw_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            AuthManager.PBKDF2_ITERATIONS
        )
        return secrets.compare_digest(pw_hash.hex(), stored_hash)

    # =========================================================================
    # FERNET KEY WRAPPING
    # =========================================================================

    @staticmethod
    def _derive_wrapping_key(secret: str, hw_fingerprint: str) -> bytes:
        """Derive a Fernet-compatible wrapping key from a secret + HW fingerprint."""
        import base64
        combined = f"{secret}:{hw_fingerprint}".encode('utf-8')
        # Use PBKDF2 with a fixed salt derived from the fingerprint
        salt = hashlib.sha256(hw_fingerprint.encode('utf-8')).digest()[:16]
        derived = hashlib.pbkdf2_hmac('sha256', combined, salt, 50_000)
        # Fernet requires url-safe base64 encoded 32-byte key
        return base64.urlsafe_b64encode(derived)

    @staticmethod
    def _wrap_fernet_key(fernet_key: bytes, wrapping_key: bytes) -> str:
        """Encrypt the Fernet key with a wrapping key. Returns hex string."""
        f = Fernet(wrapping_key)
        return f.encrypt(fernet_key).decode('utf-8')

    @staticmethod
    def _unwrap_fernet_key(wrapped: str, wrapping_key: bytes) -> bytes:
        """Decrypt the Fernet key with a wrapping key. Returns raw key bytes."""
        f = Fernet(wrapping_key)
        return f.decrypt(wrapped.encode('utf-8'))

    # =========================================================================
    # RECOVERY CODES
    # =========================================================================

    def _generate_recovery_codes(self) -> list:
        """Generate random recovery codes in format XXXX-XXXX."""
        codes = []
        charset = string.ascii_uppercase + string.digits
        # Remove ambiguous characters
        charset = charset.replace('O', '').replace('0', '').replace('I', '').replace('1', '').replace('L', '')
        for _ in range(self.RECOVERY_CODE_COUNT):
            part1 = ''.join(secrets.choice(charset) for _ in range(4))
            part2 = ''.join(secrets.choice(charset) for _ in range(4))
            codes.append(f"{part1}-{part2}")
        return codes

    # =========================================================================
    # PUBLIC API - SETUP & STATUS
    # =========================================================================

    def is_configured(self) -> bool:
        """Check if authentication has been set up."""
        try:
            with self._get_auth_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM auth")
                count = cursor.fetchone()[0]
                return count > 0
        except Exception as e:
            logger.error(f"Error checking auth status: {e}")
            return False

    def get_auth_status(self, session=None) -> dict:
        """Get current authentication status."""
        configured = self.is_configured()
        hw_fingerprint = self.get_hardware_fingerprint()
        hw_match = True

        if configured:
            try:
                with self._get_auth_conn() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT hardware_fingerprint, username FROM auth LIMIT 1")
                    row = cursor.fetchone()
                    if row:
                        hw_match = secrets.compare_digest(row['hardware_fingerprint'], hw_fingerprint)
            except Exception:
                hw_match = False

        authenticated = False
        if session and session.get('authenticated'):
            authenticated = True

        remaining_codes = 0
        if configured:
            try:
                with self._get_auth_conn() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM recovery_codes WHERE used = 0")
                    remaining_codes = cursor.fetchone()[0]
            except Exception:
                pass

        # First login: auth configured and encrypted DB exists (needs decryption)
        first_login = configured and os.path.exists(self.encrypted_db_path)

        return {
            'configured': configured,
            'authenticated': authenticated,
            'hw_match': hw_match,
            'recovery_codes_remaining': remaining_codes,
            'first_login': first_login,
            'db_ready': self._db_ready
        }

    # =========================================================================
    # PUBLIC API - SETUP
    # =========================================================================

    def setup(self, username: str, password: str) -> dict:
        """
        Initial authentication setup. Creates user, generates encryption key,
        encrypts database, generates recovery codes.
        Returns dict with recovery_codes list on success.
        """
        if not cryptography_available:
            return {'success': False, 'error': 'cryptography package not installed. Run: pip install cryptography'}

        if self.is_configured():
            return {'success': False, 'error': 'Authentication is already configured'}

        if not username or not password:
            return {'success': False, 'error': 'Username and password are required'}

        if len(password) < 8:
            return {'success': False, 'error': 'Password must be at least 8 characters'}

        try:
            hw_fingerprint = self.get_hardware_fingerprint()

            # Generate the master Fernet key (this is the actual encryption key)
            fernet_key = Fernet.generate_key()

            # Hash the password
            pw_hash, pw_salt = self._hash_password(password)

            # Wrap the Fernet key with password + HW fingerprint
            wrapping_key = self._derive_wrapping_key(password, hw_fingerprint)
            wrapped_fernet_key = self._wrap_fernet_key(fernet_key, wrapping_key)

            # Generate recovery codes and wrap Fernet key with each
            recovery_codes = self._generate_recovery_codes()
            recovery_entries = []
            for code in recovery_codes:
                code_hash, code_salt = self._hash_password(code)
                code_wrapping_key = self._derive_wrapping_key(code, hw_fingerprint)
                code_wrapped_key = self._wrap_fernet_key(fernet_key, code_wrapping_key)
                recovery_entries.append((code_hash, code_salt, code_wrapped_key))

            # Store everything in auth DB
            with self._get_auth_conn() as conn:
                cursor = conn.cursor()

                # Clear any existing data (shouldn't exist, but be safe)
                cursor.execute("DELETE FROM auth")
                cursor.execute("DELETE FROM recovery_codes")

                # Insert auth record
                cursor.execute("""
                    INSERT INTO auth (username, password_hash, password_salt,
                                     hardware_fingerprint, encrypted_fernet_key)
                    VALUES (?, ?, ?, ?, ?)
                """, (username, pw_hash, pw_salt, hw_fingerprint, wrapped_fernet_key))

                # Insert recovery codes
                for code_hash, code_salt, code_wrapped_key in recovery_entries:
                    cursor.execute("""
                        INSERT INTO recovery_codes (code_hash, code_salt, encrypted_fernet_key)
                        VALUES (?, ?, ?)
                    """, (code_hash, code_salt, code_wrapped_key))

                conn.commit()

            # Cache the Fernet key so shutdown/logout can re-encrypt the DB.
            self._fernet_key = fernet_key

            # Create the initial encrypted snapshot (keep plaintext for the running session).
            # This ensures ragnar.db.enc exists immediately so the next startup
            # knows decryption is needed. Shutdown/logout will re-encrypt with latest data.
            if os.path.exists(self.main_db_path):
                try:
                    f = Fernet(fernet_key)
                    with open(self.main_db_path, 'rb') as db_file:
                        plaintext = db_file.read()
                    encrypted = f.encrypt(plaintext)
                    with open(self.encrypted_db_path, 'wb') as enc_file:
                        enc_file.write(encrypted)
                    logger.info("Initial encrypted DB snapshot created")
                except Exception as enc_err:
                    logger.warning(f"Initial encryption snapshot failed: {enc_err}")

            logger.info(f"Authentication configured for user '{username}'")
            return {
                'success': True,
                'recovery_codes': recovery_codes,
                'message': 'Authentication configured successfully. Save your recovery codes!'
            }

        except Exception as e:
            logger.error(f"Failed to set up authentication: {e}")
            return {'success': False, 'error': f'Setup failed: {str(e)}'}

    # =========================================================================
    # PUBLIC API - LOGIN / LOGOUT
    # =========================================================================

    def login(self, username: str, password: str) -> dict:
        """Verify credentials and start DB decryption in background. Returns immediately."""
        if not self.is_configured():
            return {'success': False, 'error': 'Authentication not configured'}

        try:
            with self._get_auth_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM auth WHERE username = ?", (username,))
                row = cursor.fetchone()

                if not row:
                    return {'success': False, 'error': 'Invalid username or password'}

                # Verify password
                if not self._verify_password(password, row['password_hash'], row['password_salt']):
                    return {'success': False, 'error': 'Invalid username or password'}

                # Verify hardware fingerprint
                hw_fingerprint = self.get_hardware_fingerprint()
                if not secrets.compare_digest(row['hardware_fingerprint'], hw_fingerprint):
                    logger.warning("Hardware fingerprint mismatch during login!")
                    return {
                        'success': False,
                        'error': 'Hardware mismatch - this Ragnar instance is bound to different hardware',
                        'hw_mismatch': True
                    }

                # Unwrap the Fernet key
                wrapping_key = self._derive_wrapping_key(password, hw_fingerprint)
                try:
                    fernet_key = self._unwrap_fernet_key(row['encrypted_fernet_key'], wrapping_key)
                except InvalidToken:
                    return {'success': False, 'error': 'Failed to decrypt encryption key'}

                self._fernet_key = fernet_key

                # If encrypted DB exists, decrypt in background so this response returns fast
                if os.path.exists(self.encrypted_db_path):
                    self._db_ready = False
                    threading.Thread(target=self._background_decrypt, daemon=True).start()
                else:
                    self._db_ready = True

                logger.info(f"User '{username}' logged in successfully")
                return {'success': True}

        except Exception as e:
            logger.error(f"Login failed: {e}")
            return {'success': False, 'error': f'Login failed: {str(e)}'}

    def _background_decrypt(self):
        """Decrypt DB and reinitialize in a background thread."""
        try:
            logger.info("Background DB decryption starting...")
            self._close_db()
            time.sleep(0.2)
            self.decrypt_database()
            self._reinit_db()
            self._db_ready = True
            logger.info("Background DB decryption complete - DB ready")
        except Exception as e:
            logger.error(f"Background decrypt failed: {e}")
            self._db_ready = True  # Mark ready anyway so the system isn't stuck

    def logout(self) -> dict:
        """Encrypt database and clear session data."""
        try:
            if self.is_configured() and self._fernet_key:
                # Acquire the DB lock to prevent other threads from creating
                # new DB connections during the encrypt window
                from db_manager import _db_lock
                with _db_lock:
                    # Close existing DB connections
                    self._close_db()
                    # Give a moment for connections to close
                    time.sleep(0.2)
                    # Encrypt the database
                    if os.path.exists(self.main_db_path):
                        self.encrypt_database()
                self._fernet_key = None

            return {'success': True}
        except Exception as e:
            logger.error(f"Logout encryption failed: {e}")
            return {'success': False, 'error': str(e)}

    # =========================================================================
    # PUBLIC API - PASSWORD CHANGE
    # =========================================================================

    def change_password(self, current_password: str, new_password: str) -> dict:
        """Change the user's password. Re-wraps the Fernet key with the new password."""
        if not self.is_configured():
            return {'success': False, 'error': 'Authentication not configured'}

        if len(new_password) < 8:
            return {'success': False, 'error': 'New password must be at least 8 characters'}

        try:
            with self._get_auth_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM auth LIMIT 1")
                row = cursor.fetchone()

                if not row:
                    return {'success': False, 'error': 'No auth record found'}

                # Verify current password
                if not self._verify_password(current_password, row['password_hash'], row['password_salt']):
                    return {'success': False, 'error': 'Current password is incorrect'}

                hw_fingerprint = row['hardware_fingerprint']

                # Unwrap Fernet key with current password
                old_wrapping = self._derive_wrapping_key(current_password, hw_fingerprint)
                try:
                    fernet_key = self._unwrap_fernet_key(row['encrypted_fernet_key'], old_wrapping)
                except InvalidToken:
                    return {'success': False, 'error': 'Failed to decrypt encryption key'}

                # Re-wrap with new password
                new_pw_hash, new_pw_salt = self._hash_password(new_password)
                new_wrapping = self._derive_wrapping_key(new_password, hw_fingerprint)
                new_wrapped_key = self._wrap_fernet_key(fernet_key, new_wrapping)

                # Update auth record
                cursor.execute("""
                    UPDATE auth SET password_hash = ?, password_salt = ?,
                                    encrypted_fernet_key = ?,
                                    updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (new_pw_hash, new_pw_salt, new_wrapped_key, row['id']))
                conn.commit()

                self._fernet_key = fernet_key
                logger.info("Password changed successfully")
                return {'success': True, 'message': 'Password changed successfully'}

        except Exception as e:
            logger.error(f"Password change failed: {e}")
            return {'success': False, 'error': f'Password change failed: {str(e)}'}

    # =========================================================================
    # PUBLIC API - RECOVERY
    # =========================================================================

    def recover(self, username: str, recovery_code: str, new_password: str) -> dict:
        """Use a recovery code to reset the password and decrypt the database."""
        if not self.is_configured():
            return {'success': False, 'error': 'Authentication not configured'}

        if len(new_password) < 8:
            return {'success': False, 'error': 'New password must be at least 8 characters'}

        try:
            with self._get_auth_conn() as conn:
                cursor = conn.cursor()

                # Verify username
                cursor.execute("SELECT * FROM auth WHERE username = ?", (username,))
                auth_row = cursor.fetchone()
                if not auth_row:
                    return {'success': False, 'error': 'Invalid username or recovery code'}

                hw_fingerprint = auth_row['hardware_fingerprint']

                # Check hardware
                current_hw = self.get_hardware_fingerprint()
                if not secrets.compare_digest(hw_fingerprint, current_hw):
                    return {'success': False, 'error': 'Hardware mismatch', 'hw_mismatch': True}

                # Normalize recovery code (strip spaces, uppercase, ensure dash format)
                recovery_code = recovery_code.replace(' ', '').strip().upper()
                if '-' not in recovery_code and len(recovery_code) == 8:
                    recovery_code = recovery_code[:4] + '-' + recovery_code[4:]

                # Find matching recovery code
                cursor.execute("SELECT * FROM recovery_codes WHERE used = 0")
                rows = cursor.fetchall()

                matched_row = None
                for row in rows:
                    if self._verify_password(recovery_code, row['code_hash'], row['code_salt']):
                        matched_row = row
                        break

                if not matched_row:
                    return {'success': False, 'error': 'Invalid username or recovery code'}

                # Unwrap Fernet key using recovery code
                code_wrapping = self._derive_wrapping_key(recovery_code, hw_fingerprint)
                try:
                    fernet_key = self._unwrap_fernet_key(matched_row['encrypted_fernet_key'], code_wrapping)
                except InvalidToken:
                    return {'success': False, 'error': 'Recovery code decryption failed'}

                # Mark recovery code as used
                cursor.execute("""
                    UPDATE recovery_codes SET used = 1, used_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (matched_row['id'],))

                # Re-wrap Fernet key with new password
                new_pw_hash, new_pw_salt = self._hash_password(new_password)
                new_wrapping = self._derive_wrapping_key(new_password, hw_fingerprint)
                new_wrapped_key = self._wrap_fernet_key(fernet_key, new_wrapping)

                # Update auth record
                cursor.execute("""
                    UPDATE auth SET password_hash = ?, password_salt = ?,
                                    encrypted_fernet_key = ?,
                                    updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (new_pw_hash, new_pw_salt, new_wrapped_key, auth_row['id']))

                conn.commit()

                # Decrypt database in background
                self._fernet_key = fernet_key
                if os.path.exists(self.encrypted_db_path):
                    self._db_ready = False
                    threading.Thread(target=self._background_decrypt, daemon=True).start()
                else:
                    self._db_ready = True

                # Count remaining codes
                cursor.execute("SELECT COUNT(*) FROM recovery_codes WHERE used = 0")
                remaining = cursor.fetchone()[0]

                logger.info(f"Password recovered for user '{username}'. {remaining} recovery codes remaining.")
                return {
                    'success': True,
                    'message': f'Password reset successful. {remaining} recovery codes remaining.',
                    'recovery_codes_remaining': remaining
                }

        except Exception as e:
            logger.error(f"Recovery failed: {e}")
            return {'success': False, 'error': f'Recovery failed: {str(e)}'}

    def regenerate_recovery_codes(self, password: str) -> dict:
        """Generate new recovery codes (requires current password)."""
        if not self.is_configured():
            return {'success': False, 'error': 'Authentication not configured'}

        try:
            with self._get_auth_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM auth LIMIT 1")
                auth_row = cursor.fetchone()

                if not auth_row:
                    return {'success': False, 'error': 'No auth record found'}

                # Verify password
                if not self._verify_password(password, auth_row['password_hash'], auth_row['password_salt']):
                    return {'success': False, 'error': 'Incorrect password'}

                hw_fingerprint = auth_row['hardware_fingerprint']

                # Get the Fernet key
                wrapping_key = self._derive_wrapping_key(password, hw_fingerprint)
                try:
                    fernet_key = self._unwrap_fernet_key(auth_row['encrypted_fernet_key'], wrapping_key)
                except InvalidToken:
                    return {'success': False, 'error': 'Failed to decrypt encryption key'}

                # Generate new codes
                recovery_codes = self._generate_recovery_codes()

                # Delete old codes and insert new ones
                cursor.execute("DELETE FROM recovery_codes")
                for code in recovery_codes:
                    code_hash, code_salt = self._hash_password(code)
                    code_wrapping = self._derive_wrapping_key(code, hw_fingerprint)
                    code_wrapped_key = self._wrap_fernet_key(fernet_key, code_wrapping)
                    cursor.execute("""
                        INSERT INTO recovery_codes (code_hash, code_salt, encrypted_fernet_key)
                        VALUES (?, ?, ?)
                    """, (code_hash, code_salt, code_wrapped_key))

                conn.commit()

                logger.info("Recovery codes regenerated")
                return {
                    'success': True,
                    'recovery_codes': recovery_codes,
                    'message': 'New recovery codes generated. Save them securely!'
                }

        except Exception as e:
            logger.error(f"Recovery code regeneration failed: {e}")
            return {'success': False, 'error': str(e)}

    # =========================================================================
    # DATABASE ENCRYPTION / DECRYPTION
    # =========================================================================

    def encrypt_database(self):
        """Encrypt ragnar.db to ragnar.db.enc and remove the plaintext copy."""
        if not self._fernet_key:
            raise RuntimeError("No Fernet key available for encryption")

        if not os.path.exists(self.main_db_path):
            logger.warning("No database to encrypt")
            return

        with self._lock:
            try:
                f = Fernet(self._fernet_key)
                with open(self.main_db_path, 'rb') as db_file:
                    plaintext = db_file.read()

                encrypted = f.encrypt(plaintext)

                # Write encrypted file atomically (write to temp, then rename)
                temp_path = self.encrypted_db_path + '.tmp'
                with open(temp_path, 'wb') as enc_file:
                    enc_file.write(encrypted)

                # Replace the encrypted file
                if os.path.exists(self.encrypted_db_path):
                    os.remove(self.encrypted_db_path)
                os.rename(temp_path, self.encrypted_db_path)

                # Remove plaintext database
                os.remove(self.main_db_path)
                # Also remove WAL and SHM files if they exist
                for suffix in ['-wal', '-shm']:
                    wal_path = self.main_db_path + suffix
                    if os.path.exists(wal_path):
                        os.remove(wal_path)

                logger.info("Database encrypted successfully")
            except Exception as e:
                # Clean up temp file on failure
                temp_path = self.encrypted_db_path + '.tmp'
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                logger.error(f"Database encryption failed: {e}")
                raise

    def decrypt_database(self):
        """Decrypt ragnar.db.enc to ragnar.db. Keeps encrypted copy as backup."""
        if not self._fernet_key:
            raise RuntimeError("No Fernet key available for decryption")

        if not os.path.exists(self.encrypted_db_path):
            logger.warning("No encrypted database to decrypt")
            return

        with self._lock:
            try:
                f = Fernet(self._fernet_key)
                with open(self.encrypted_db_path, 'rb') as enc_file:
                    encrypted = enc_file.read()

                plaintext = f.decrypt(encrypted)

                # Remove empty placeholder DB and its WAL/SHM files before writing
                if os.path.exists(self.main_db_path):
                    os.remove(self.main_db_path)
                for suffix in ['-wal', '-shm']:
                    p = self.main_db_path + suffix
                    if os.path.exists(p):
                        os.remove(p)

                with open(self.main_db_path, 'wb') as db_file:
                    db_file.write(plaintext)

                logger.info("Database decrypted successfully")
            except InvalidToken:
                logger.error("Database decryption failed - invalid key")
                raise
            except Exception as e:
                logger.error(f"Database decryption failed: {e}")
                raise

    def shutdown_encrypt(self):
        """Called on application shutdown to encrypt the database."""
        if not self.is_configured():
            return
        if not self._fernet_key:
            logger.warning("No Fernet key at shutdown - DB may not be encrypted")
            return

        try:
            self._close_db()
            time.sleep(0.2)
            if os.path.exists(self.main_db_path):
                self.encrypt_database()
                logger.info("Database encrypted on shutdown")
        except Exception as e:
            logger.error(f"Shutdown encryption failed: {e}")

    # =========================================================================
    # CRASH RECOVERY
    # =========================================================================

    def _handle_crash_recovery(self):
        """Handle leftover plaintext DB from a crash.

        On normal restart after auth is configured, get_db() will have already
        created an empty placeholder ragnar.db before this method runs.  That is
        harmless -- decrypt_database() removes it before writing the real data.
        We only log a notice here; no deletion is needed.
        """
        if not self.is_configured():
            return

        if os.path.exists(self.main_db_path) and os.path.exists(self.encrypted_db_path):
            # Both exist.  Likely either a crash leftover or the empty placeholder
            # created by get_db() at startup.  Either way the encrypted copy is the
            # authoritative version; decrypt_database() will replace ragnar.db on login.
            logger.info("Encrypted DB found alongside plaintext. "
                        "Encrypted copy is authoritative; will replace on login.")

        elif os.path.exists(self.main_db_path) and not os.path.exists(self.encrypted_db_path):
            # Plaintext exists but no encrypted version -- unusual.
            # Can't encrypt without the key. Leave it; will encrypt after next login.
            logger.warning("Crash recovery: plaintext DB exists without encrypted backup. "
                          "Will encrypt after next login.")

    # =========================================================================
    # SECRET KEY MANAGEMENT
    # =========================================================================

    def get_or_create_secret_key(self) -> str:
        """Get or create a persistent Flask SECRET_KEY."""
        try:
            with self._get_auth_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT value FROM app_secrets WHERE key = 'flask_secret_key'")
                row = cursor.fetchone()
                if row:
                    return row['value']

                # Generate and store a new secret key
                secret_key = secrets.token_hex(32)
                cursor.execute(
                    "INSERT INTO app_secrets (key, value) VALUES (?, ?)",
                    ('flask_secret_key', secret_key)
                )
                conn.commit()
                return secret_key
        except Exception as e:
            logger.error(f"Failed to get/create secret key: {e}")
            # Fallback to a random key (won't persist across restarts)
            return secrets.token_hex(32)

    # =========================================================================
    # DB HELPER METHODS
    # =========================================================================

    def _close_db(self):
        """Close the main database connections via shared_data."""
        try:
            from db_manager import close_db
            close_db()
        except Exception as e:
            logger.error(f"Failed to close DB: {e}")

    def _reinit_db(self):
        """Reinitialize the database connection after decryption."""
        try:
            from db_manager import reinit_db
            self.shared_data.db = reinit_db(currentdir=getattr(self.shared_data, 'currentdir', None))
            # Re-apply network storage context if it was set during startup
            if hasattr(self.shared_data, '_configure_database'):
                self.shared_data._configure_database()
        except Exception as e:
            logger.error(f"Failed to reinitialize DB: {e}")

    def is_db_available(self) -> bool:
        """Check if the main database is available (decrypted)."""
        return os.path.exists(self.main_db_path)
