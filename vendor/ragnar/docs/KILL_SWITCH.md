# Ragnar Kill Switch - Educational Data Erasure

## ⚠️ WARNING: DESTRUCTIVE OPERATION ⚠️

This endpoint is designed for **educational purposes only** to ensure complete data erasure after demonstrations or training sessions.

## What It Does

The `/api/kill` endpoint performs complete data destruction:

1. **Wipes all databases** - Deletes `ragnar.db`, CSV files, and JSON data
2. **Clears all logs** - Removes system and application logs
3. **Deletes temporary files** - Cleans up cache and temp data
4. **Erases the repository** - Completely removes the Ragnar installation
5. **Optional shutdown** - Can power off the system after erasure

## Security Features

- **Confirmation Required**: Must send exact confirmation token
- **POST-only**: Cannot be triggered accidentally via GET
- **Logged**: All actions are logged before deletion
- **Self-deleting**: Repository deletion happens after API response

## Usage

### Using cURL

```bash
# Basic kill switch (wipe data and delete repo)
curl -X POST http://localhost:8000/api/kill \
  -H "Content-Type: application/json" \
  -d '{"confirmation": "ERASE_ALL_DATA"}'

# Kill switch with system shutdown
curl -X POST http://localhost:8000/api/kill \
  -H "Content-Type: application/json" \
  -d '{"confirmation": "ERASE_ALL_DATA", "shutdown": true}'
```

### Using Python

```python
import requests

# Basic kill switch
response = requests.post('http://localhost:8000/api/kill', 
    json={'confirmation': 'ERASE_ALL_DATA'})
print(response.json())

# With shutdown
response = requests.post('http://localhost:8000/api/kill',
    json={'confirmation': 'ERASE_ALL_DATA', 'shutdown': True})
print(response.json())
```

### Using JavaScript/Fetch

```javascript
// Basic kill switch
fetch('http://localhost:8000/api/kill', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({confirmation: 'ERASE_ALL_DATA'})
})
.then(response => response.json())
.then(data => console.log(data));

// With shutdown
fetch('http://localhost:8000/api/kill', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        confirmation: 'ERASE_ALL_DATA',
        shutdown: true
    })
})
.then(response => response.json())
.then(data => console.log(data));
```

## Response Format

### Success Response
```json
{
    "success": true,
    "message": "Kill switch executed. All data wiped. Repository deleting in 5 seconds.",
    "details": {
        "database_wiped": true,
        "repository_deleted": true,
        "logs_cleared": true,
        "temp_files_cleared": true,
        "shutdown_scheduled": false,
        "errors": []
    },
    "timestamp": "2025-11-14T12:30:45.123456"
}
```

### Error Response (Invalid Confirmation)
```json
{
    "success": false,
    "error": "Invalid confirmation token. Use \"ERASE_ALL_DATA\" to confirm."
}
```

## What Gets Deleted

### Database Files
- `data/ragnar.db` - Main SQLite database
- `data/netkb.csv` - Legacy CSV database
- `data/` - Entire data directory

### Log Files
- `/var/log/ragnar.log`
- `/var/log/ragnar_wifi.log`
- `/var/log/ap.log`
- `/var/log/ragnar_failsafe.log`
- `var/log/` - Application log directory

### Temporary Files
- `/tmp/ragnar/` - Temporary configuration files
- `/tmp/ragnar_wifi_state.json`
- `/tmp/ragnar_wifi_manager.pid`

### Repository
- **Entire Ragnar installation directory** (deleted 5 seconds after response)

## Timeline

1. **T+0s**: API called, confirmation validated
2. **T+1s**: Database files wiped
3. **T+2s**: Logs cleared
4. **T+3s**: Temp files cleared
5. **T+4s**: Self-delete script created and launched
6. **T+5s**: API response sent
7. **T+10s**: Repository completely deleted
8. **T+60s**: System shutdown (if requested)

## Use Cases

### After Training/Demonstration
```bash
# Quick cleanup after showing Ragnar to students
curl -X POST http://localhost:8000/api/kill \
  -H "Content-Type: application/json" \
  -d '{"confirmation": "ERASE_ALL_DATA"}'
```

### Complete Decommission
```bash
# Wipe everything and power off
curl -X POST http://localhost:8000/api/kill \
  -H "Content-Type: application/json" \
  -d '{"confirmation": "ERASE_ALL_DATA", "shutdown": true}'
```

### Remote Wipe
```bash
# Trigger from remote location (if Ragnar is accessible)
curl -X POST http://192.168.1.100:8000/api/kill \
  -H "Content-Type: application/json" \
  -d '{"confirmation": "ERASE_ALL_DATA", "shutdown": true}'
```

## Safety Notes

1. **No Undo**: Once triggered, there is NO way to recover the data
2. **Backup First**: If you need to preserve any data, back it up before using the kill switch
3. **Test Confirmation**: Wrong confirmation token will be rejected (403 Forbidden)
4. **Network Required**: Must have network access to Ragnar's web interface
5. **Root Not Required**: Can be triggered without root privileges (repo deletion uses current user)

## Verification

After triggering, you can verify deletion:

<img width="680" height="223" alt="image" src="https://github.com/user-attachments/assets/d724aee1-050d-4c2d-982b-40a67b64b2e2" />

```bash
# Check if Ragnar directory exists
ls -la /path/to/Ragnar  # Should not exist after ~10 seconds

# Check logs
ls -la /var/log/ragnar*  # Should be empty or not exist

# Check database
ls -la /path/to/Ragnar/data/  # Should not exist
```

## Educational Use

This feature is specifically designed for:
- ✅ Cybersecurity training environments
- ✅ Penetration testing demonstrations
- ✅ CTF (Capture The Flag) competitions
- ✅ Research lab cleanup
- ✅ Temporary installations

**NOT recommended for:**
- ❌ Production environments
- ❌ Persistent monitoring systems
- ❌ Long-term deployments

## Legal & Ethical Notice

This tool is provided for **educational purposes only**. Users must:
- Have proper authorization to use penetration testing tools
- Only use on networks they own or have explicit permission to test
- Follow all applicable laws and regulations
- Use the kill switch responsibly to protect privacy and data

---

**Remember**: The kill switch exists to ensure no sensitive data remains after educational use. Always verify complete deletion when handling sensitive networks.
