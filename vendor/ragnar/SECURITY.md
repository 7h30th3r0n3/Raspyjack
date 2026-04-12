# Security & Authentication

Ragnar includes a hardware-bound authentication and database encryption system. On first start, Ragnar runs open (no login). Once you enable authentication from the **Config** tab, every subsequent start requires a login before anything is accessible.

## What happens when you enable authentication

1. **All endpoints are locked** &mdash; every API route and the dashboard return `401 Unauthorized` until you log in. Only `/api/kill` (the kill switch), the login page, and the auth API remain open.
2. **The database is encrypted at rest** &mdash; `ragnar.db` is encrypted with AES-128 (Fernet) into `ragnar.db.enc` whenever you log out or Ragnar shuts down. The plaintext file is deleted.
3. **Hardware binding** &mdash; the encryption key is tied to a fingerprint derived from the device's machine-id, MAC address, and CPU serial. Moving the database to different hardware will not decrypt it.
4. **Recovery codes** &mdash; 10 one-time codes are generated at setup. Each can independently reset your password and decrypt the database if you forget your password.

## Enabling authentication

1. Open the Ragnar dashboard at `http://<ragnar-ip>:8000`.
2. Go to the **Config** tab.
3. Under **Security**, enter a username and password (minimum 8 characters) and click **Enable Authentication**.
4. **Save the recovery codes** that are displayed. Each code can only be used once. Store them somewhere safe outside of Ragnar.
5. From this point forward, Ragnar will show a login screen on every start.

## Login

Navigate to `http://<ragnar-ip>:8000`. If authentication is configured you will be redirected to the login page. Enter your username and password.

Sessions last 24 hours. After that you will need to log in again.

## Password recovery

If you forget your password:

1. On the login page, click **Forgot password? Use recovery code**.
2. Enter your username, one of your recovery codes (`XXXX-XXXX` format), and a new password.
3. The recovery code is consumed and cannot be reused.
4. You will be logged in automatically with the new password.

Check how many codes you have left from the **Config > Security** panel and regenerate them if needed.

## Changing your password

1. Go to **Config > Security > Change Password**.
2. Enter your current password and the new password.
3. The database encryption key is automatically re-wrapped with the new password. No data is lost.

## Regenerating recovery codes

1. Go to **Config > Security > Recovery Codes**.
2. Click **Regenerate Recovery Codes** and enter your current password.
3. All previous codes are invalidated and 10 new codes are generated.
4. Save them immediately &mdash; they are shown only once.

## Logout

Click the **Logout** button in the navigation bar or go to **Config > Security > Session > Logout**. On logout:

- Your session is cleared.
- The database is encrypted back to `ragnar.db.enc`.
- The plaintext `ragnar.db` is deleted.

## Technical details

| Component | Detail |
|-----------|--------|
| **Password hashing** | PBKDF2-HMAC-SHA256, 200 000 iterations, random 32-byte salt |
| **Database encryption** | Fernet (AES-128-CBC + HMAC-SHA256) via the `cryptography` Python package |
| **Hardware fingerprint** | SHA-256 of `/etc/machine-id` + CPU serial (`/proc/cpuinfo`). MAC address is intentionally excluded because it changes between WiFi and Ethernet. Falls back to hostname + platform on non-Linux systems |
| **Key management** | A random Fernet key is generated once at setup. It is wrapped (encrypted) with a key derived from `password + hardware_fingerprint` via PBKDF2. Each recovery code also independently wraps the same Fernet key. The Fernet key itself never changes, so password changes and recovery only re-wrap the key &mdash; the database is never re-encrypted |
| **Session** | Flask signed cookie with a random `SECRET_KEY` persisted in `ragnar_auth.db`. 24-hour expiration |
| **Auth database** | `data/ragnar_auth.db` &mdash; small unencrypted SQLite DB containing only password hashes, the hardware fingerprint, the wrapped Fernet key, and hashed recovery codes. No sensitive data is stored here in plaintext |
| **WebSocket** | SocketIO connections are rejected during the HTTP upgrade handshake if the session is not authenticated |
| **Kill switch** | `/api/kill` remains accessible without authentication (requires separate `ERASE_ALL_DATA` confirmation) so the device can always be wiped |

## Crash recovery

If Ragnar is terminated unexpectedly (power loss, crash):

- On next startup, if both `ragnar.db` and `ragnar.db.enc` exist, the plaintext copy is deleted and the encrypted backup is used.
- If only the plaintext copy exists (encryption was interrupted), it is left in place and will be encrypted after the next login.
- An `atexit` handler and the `SIGTERM`/`SIGINT` shutdown handler both attempt to encrypt the database before exit as a safety net.

## Dependency

Authentication requires the `cryptography` Python package (`pip install cryptography`). It is included in `requirements.txt` and installed automatically by `install_ragnar.sh`. Pre-built wheels are available for ARM (Raspberry Pi) and most Linux architectures. If the package is not installed, the setup endpoint will return an error explaining what to install.
